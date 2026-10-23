"""Unit tests for helpers and actions in `src/charm.py`."""

import io
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.message import Message
from types import SimpleNamespace
from typing import Any, List, Optional
from unittest import mock
from urllib.error import HTTPError, URLError

import pytest
from charm import LxdCharm
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SERVER_CRT = "/var/snap/lxd/common/lxd/server.crt"
CLUSTER_CRT = "/var/snap/lxd/common/lxd/cluster.crt"


class _Bag:
    """Stand-in for the unit or application that owns a relation data bag."""

    def __init__(self, name: str):
        """Store the name used in log messages."""
        self.name = name


class _FakeCharm(LxdCharm):
    """Charm with the ops framework bypassed so methods run on plain attributes."""

    config: Any = None
    model: Any = None
    unit: Any = None
    app: Any = None
    peers: Any = None
    _stored: Any = None

    def __init__(self, **attrs):
        """Set the attributes the tested methods read."""
        for name, value in attrs.items():
            setattr(self, name, value)


def _event(**params):
    """Return an action event with the given params."""
    return SimpleNamespace(params=params, fail=mock.Mock(), set_results=mock.Mock())


def _self_signed_pem(dns_names: Optional[List[str]] = None) -> str:
    """Return a self-signed certificate, with a DNS SAN extension if `dns_names` is set."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lxd")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
    )
    if dns_names is not None:
        san = x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names])
        builder = builder.add_extension(san, critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _charm_with_spaces(spaces, *, listen_metrics=False):
    """Return a charm whose network spaces map to the given addresses."""
    return _FakeCharm(
        config={"lxd-listen-metrics": listen_metrics},
        juju_space_get_address=lambda name, require_ipv4=False: spaces.get(name, ""),
    )


def _charm_with_addresses(addresses):
    """Return a charm whose network binding reports the given ingress addresses."""
    binding = SimpleNamespace(network=SimpleNamespace(ingress_addresses=addresses))
    return _FakeCharm(model=SimpleNamespace(get_binding=lambda name: binding))


@pytest.fixture
def peer_charm():
    """Return a charm whose cluster relation has an empty data bag per unit and app."""
    return _FakeCharm(
        peers=SimpleNamespace(data=defaultdict(dict)),
        unit=_Bag("lxd/0"),
        app=_Bag("lxd"),
    )


@pytest.mark.parametrize(
    ("method", "empty"),
    [("get_peer_data_dict", {}), ("get_peer_data_list", []), ("get_peer_data_str", "")],
)
def test_peer_getters_return_empty_without_relation(method, empty):
    """Peer getters return an empty value when there is no cluster relation."""
    charm = _FakeCharm(peers=None)

    assert getattr(charm, method)(_Bag("lxd/0"), "key") == empty


def test_get_peer_data_dict_returns_stored_dict(peer_charm):
    """A JSON object stored in the bag is returned as a dict."""
    peer_charm.peers.data[peer_charm.app]["members"] = '{"lxd/0":"host-0"}'

    assert peer_charm.get_peer_data_dict(peer_charm.app, "members") == {"lxd/0": "host-0"}


@pytest.mark.parametrize("raw", ['["lxd/0"]', '"lxd/0"', "1"])
def test_get_peer_data_dict_rejects_non_dict(peer_charm, raw):
    """A JSON value that is not an object yields an empty dict."""
    peer_charm.peers.data[peer_charm.app]["members"] = raw

    assert peer_charm.get_peer_data_dict(peer_charm.app, "members") == {}


def test_get_peer_data_list_returns_stored_list(peer_charm):
    """A JSON array stored in the bag is returned as a list."""
    peer_charm.peers.data[peer_charm.app]["member_config"] = '[{"key":"source"}]'

    assert peer_charm.get_peer_data_list(peer_charm.app, "member_config") == [{"key": "source"}]


def test_get_peer_data_list_rejects_non_list(peer_charm):
    """A JSON value that is not an array yields an empty list."""
    peer_charm.peers.data[peer_charm.app]["member_config"] = '{"key":"source"}'

    assert peer_charm.get_peer_data_list(peer_charm.app, "member_config") == []


def test_pop_peer_data_str_removes_value(peer_charm):
    """Popping a key returns its value and removes it from the bag."""
    peer_charm.peers.data[peer_charm.app]["lxd/1"] = "token"

    assert peer_charm.pop_peer_data_str(peer_charm.app, "lxd/1") == "token"
    assert "lxd/1" not in peer_charm.peers.data[peer_charm.app]


def test_set_peer_data_dict_writes_compact_sorted_json(peer_charm):
    """A changed dict is written as compact JSON with sorted keys."""
    peer_charm.set_peer_data_dict(peer_charm.app, "members", {"lxd/1": "b", "lxd/0": "a"})

    assert peer_charm.peers.data[peer_charm.app]["members"] == '{"lxd/0":"a","lxd/1":"b"}'


def test_set_peer_data_dict_skips_unchanged_value(peer_charm):
    """An unchanged dict is not rewritten, so a non-canonical stored form is kept."""
    peer_charm.peers.data[peer_charm.app]["members"] = '{ "lxd/0": "a" }'

    peer_charm.set_peer_data_dict(peer_charm.app, "members", {"lxd/0": "a"})

    assert peer_charm.peers.data[peer_charm.app]["members"] == '{ "lxd/0": "a" }'


def test_set_peer_data_str_updates_value(peer_charm):
    """A string is stored in the bag."""
    peer_charm.set_peer_data_str(peer_charm.unit, "hostname", "node-1")

    assert peer_charm.peers.data[peer_charm.unit]["hostname"] == "node-1"


@pytest.mark.parametrize(("version", "supported"), [("1.0", True), ("2.0", False), ("", False)])
def test_is_peer_data_version_supported(peer_charm, version, supported):
    """Only version 1.0 of the peer data format is supported."""
    peer_charm.peers.data[peer_charm.unit]["version"] = version

    assert peer_charm.is_peer_data_version_supported(peer_charm.unit) is supported


def test_config_changed_reports_new_and_modified_keys_only():
    """Keys that are new or differ from the stored config are reported."""
    charm = _FakeCharm(
        config={"mode": "cluster", "snap-channel": "5.21/stable", "sysctl-tuning": True},
        _stored=SimpleNamespace(config={"mode": "cluster", "sysctl-tuning": False}),
    )

    assert charm.config_changed() == {"snap-channel": "5.21/stable", "sysctl-tuning": True}


def test_metrics_port_is_https_unless_metrics_listener_enabled():
    """The metrics port is the HTTPS port unless the dedicated metrics listener is on."""
    assert _charm_with_spaces({}).metrics_port == 8443
    assert _charm_with_spaces({}, listen_metrics=True).metrics_port == 9100


def test_metrics_address_prefers_metrics_space():
    """The metrics space is used when it has an address."""
    charm = _charm_with_spaces({"metrics": "10.0.0.1", "https": "10.0.0.2"})

    assert charm.metrics_address == "10.0.0.1"


def test_metrics_address_falls_back_to_https_space():
    """The HTTPS space is used when there is no metrics address."""
    charm = _charm_with_spaces({"https": "10.0.0.2"})

    assert charm.metrics_address == "10.0.0.2"


def test_metrics_address_brackets_ipv6():
    """IPv6 addresses are wrapped in brackets so a port can be appended."""
    charm = _charm_with_spaces({"https": "2001:db8::1"})

    assert charm.metrics_address == "[2001:db8::1]"


def test_metrics_address_empty_without_addresses():
    """No address in either space yields an empty metrics address."""
    assert _charm_with_spaces({}).metrics_address == ""


def test_metrics_target_combines_address_and_metrics_port():
    """The metrics target is the address and the metrics port."""
    charm = _charm_with_spaces({"metrics": "10.0.0.1"}, listen_metrics=True)

    assert charm.metrics_target == "10.0.0.1:9100"


def test_metrics_target_empty_without_address():
    """No metrics address yields an empty metrics target."""
    assert _charm_with_spaces({}).metrics_target == ""


def test_juju_space_get_address_without_binding_is_empty():
    """No binding for the space yields an empty address."""
    charm = _FakeCharm(model=SimpleNamespace(get_binding=lambda name: None))

    assert charm.juju_space_get_address("cluster") == ""


@pytest.mark.parametrize("addresses", [[], ["host.example"]])
def test_juju_space_get_address_without_ip_is_empty(addresses):
    """Hostnames and empty ingress lists yield an empty address."""
    assert _charm_with_addresses(addresses).juju_space_get_address("cluster") == ""


def test_juju_space_get_address_skips_hostnames():
    """The first ingress address that parses as an IP is returned."""
    charm = _charm_with_addresses(["host.example", "10.0.0.5", "2001:db8::1"])

    assert charm.juju_space_get_address("cluster") == "10.0.0.5"


def test_juju_space_get_address_require_ipv4():
    """With require_ipv4, an IPv6-only space yields an empty address."""
    charm = _charm_with_addresses(["2001:db8::1", "10.0.0.5"])
    assert charm.juju_space_get_address("cluster", require_ipv4=True) == "10.0.0.5"

    charm = _charm_with_addresses(["2001:db8::1"])
    assert charm.juju_space_get_address("cluster", require_ipv4=True) == ""


def test_get_tls_san_dnsnames_returns_dns_names():
    """DNS names from the SAN extension are returned in order."""
    pem = _self_signed_pem(["lxd.example", "lxd-2.example"])

    assert LxdCharm._get_tls_san_dnsnames(pem) == ["lxd.example", "lxd-2.example"]


def test_get_tls_san_dnsnames_without_san_is_empty():
    """A certificate without a SAN extension yields no DNS names."""
    assert LxdCharm._get_tls_san_dnsnames(_self_signed_pem()) == []


def test_get_tls_san_dnsnames_invalid_pem_is_empty():
    """Data that is not a PEM certificate yields no DNS names."""
    assert LxdCharm._get_tls_san_dnsnames("not a certificate") == []


@pytest.mark.parametrize(("mode", "path"), [("standalone", SERVER_CRT), ("cluster", CLUSTER_CRT)])
def test_get_tls_ca_cert_reads_mode_specific_file(mode, path):
    """The CA certificate is cluster.crt in cluster mode and server.crt otherwise."""
    charm = _FakeCharm(config={"mode": mode})

    with mock.patch("charm.os.path.exists", return_value=True) as exists:
        with mock.patch("builtins.open", mock.mock_open(read_data="PEM")) as opened:
            assert charm._get_tls_ca_cert() == "PEM"

    exists.assert_called_once_with(path)
    opened.assert_called_once_with(path)


def test_get_tls_ca_cert_missing_file_is_empty():
    """A missing certificate file yields an empty string."""
    charm = _FakeCharm(config={"mode": "cluster"})

    with mock.patch("charm.os.path.exists", return_value=False):
        assert charm._get_tls_ca_cert() == ""


def test_get_tls_ca_cert_read_error_is_empty():
    """A certificate file that cannot be read yields an empty string."""
    charm = _FakeCharm(config={"mode": "standalone"})

    with mock.patch("charm.os.path.exists", return_value=True):
        with mock.patch("builtins.open", side_effect=PermissionError(13, "Permission denied")):
            assert charm._get_tls_ca_cert() == ""


def test_add_trusted_client_requires_cert_or_url():
    """The action fails when neither cert nor cert-url is given."""
    trust_add = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_add=trust_add)
    event = _event()

    charm._on_action_add_trusted_client(event)

    event.fail.assert_called_once()
    trust_add.assert_not_called()


def test_add_trusted_client_normalizes_single_line_cert():
    """A certificate on one line is split back into PEM lines before it is trusted."""
    trust_add = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_add=trust_add)
    pem = "-----BEGIN CERTIFICATE----- MIIB abc -----END CERTIFICATE-----"
    event = _event(name="client", cert=pem)

    charm._on_action_add_trusted_client(event)

    trust_add.assert_called_once_with(
        cert="-----BEGIN CERTIFICATE-----\nMIIB\nabc\n-----END CERTIFICATE-----",
        name="client",
        projects="",
    )
    event.set_results.assert_called_once_with({"result": "The client certificate is now trusted"})


def test_add_trusted_client_success_message_lists_projects():
    """The success message names the projects the certificate was trusted for."""
    charm = _FakeCharm(lxd_trust_add=mock.Mock(return_value=True))
    event = _event(name="client", cert="PEM", projects="default,dev")

    charm._on_action_add_trusted_client(event)

    msg = "The client certificate is now trusted for the following project(s): default,dev"
    event.set_results.assert_called_once_with({"result": msg})


def test_add_trusted_client_reports_trust_failure():
    """The action fails when the certificate cannot be added to the trust store."""
    charm = _FakeCharm(lxd_trust_add=mock.Mock(return_value=False))
    event = _event(name="client", cert="PEM")

    charm._on_action_add_trusted_client(event)

    event.fail.assert_called_once_with("Failed to add the certificate to the trusted list")


def test_add_trusted_client_fetches_cert_from_url():
    """The certificate is downloaded from cert-url when no cert is given."""
    trust_add = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_add=trust_add)
    response = mock.Mock()
    response.read.return_value = b"PEMDATA"
    event = _event(**{"cert-url": "https://example.com/cert.pem"})

    with mock.patch("charm.urlopen", return_value=response) as urlopen:
        charm._on_action_add_trusted_client(event)

    urlopen.assert_called_once_with("https://example.com/cert.pem")
    trust_add.assert_called_once_with(cert="PEMDATA", name="unknown", projects="")


def test_add_trusted_client_prefers_cert_over_cert_url():
    """When both are given, cert is used and cert-url is not fetched."""
    trust_add = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_add=trust_add)
    event = _event(**{"cert": "PEM", "cert-url": "https://example.com/cert.pem"})

    with mock.patch("charm.urlopen") as urlopen:
        charm._on_action_add_trusted_client(event)

    urlopen.assert_not_called()
    trust_add.assert_called_once_with(cert="PEM", name="unknown", projects="")


def test_add_trusted_client_rejects_non_http_url():
    """A cert-url that is not http or https is rejected without fetching it."""
    trust_add = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_add=trust_add)
    event = _event(**{"cert-url": "ftp://example.com/cert.pem"})

    with mock.patch("charm.urlopen") as urlopen:
        charm._on_action_add_trusted_client(event)

    event.fail.assert_called_once_with(
        'The cert-url parameter needs to start with "http://" or "https://".'
    )
    urlopen.assert_not_called()
    trust_add.assert_not_called()


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (
            HTTPError("https://example.com/cert.pem", 404, "Not Found", Message(), io.BytesIO()),
            "The server couldn't fulfill the request. Error code: 404",
        ),
        (
            URLError("name resolution failed"),
            "We failed to reach a server. Reason: name resolution failed",
        ),
    ],
)
def test_add_trusted_client_reports_fetch_errors(error, message):
    """Download errors are reported to the operator and nothing is trusted."""
    trust_add = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_add=trust_add)
    event = _event(**{"cert-url": "https://example.com/cert.pem"})

    with mock.patch("charm.urlopen", side_effect=error):
        charm._on_action_add_trusted_client(event)

    event.fail.assert_called_once_with(message)
    trust_add.assert_not_called()


def test_get_client_token_requires_https_listener():
    """The action fails when the HTTPS listener is disabled."""
    charm = _FakeCharm(_stored=SimpleNamespace(config={"lxd-listen-https": False}))
    event = _event(name="client")

    charm._on_action_get_client_token(event)

    event.fail.assert_called_once()
    assert "lxd-listen-https=false" in event.fail.call_args.args[0]


def test_get_client_token_requires_name():
    """The action fails when the name parameter is missing."""
    charm = _FakeCharm(_stored=SimpleNamespace(config={"lxd-listen-https": True}))
    event = _event()

    charm._on_action_get_client_token(event)

    event.fail.assert_called_once_with("Missing required parameter: name")


def test_get_client_token_returns_token():
    """The token is returned with the client name in the result."""
    token_fn = mock.Mock(return_value="TOKEN")
    charm = _FakeCharm(
        _stored=SimpleNamespace(config={"lxd-listen-https": True}),
        lxd_trust_token=token_fn,
    )
    event = _event(name="client", projects="default")

    charm._on_action_get_client_token(event)

    token_fn.assert_called_once_with(name="client", projects="default")
    event.set_results.assert_called_once_with(
        {"result": "Client client certificate add token:\nTOKEN"}
    )


def test_remove_trusted_client_requires_fingerprint():
    """The action fails when the fingerprint parameter is missing."""
    remove = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_remove=remove)
    event = _event()

    charm._on_action_remove_trusted_client(event)

    event.fail.assert_called_once_with("Missing required parameter: fingerprint")
    remove.assert_not_called()


def test_remove_trusted_client_normalizes_openssl_fingerprint():
    """An openssl-formatted fingerprint is reduced to 64 hex characters before removal."""
    remove = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_remove=remove)
    fingerprint = "AB" * 32
    event = _event(fingerprint="sha256 Fingerprint=" + ":".join(["AB"] * 32))

    charm._on_action_remove_trusted_client(event)

    remove.assert_called_once_with(fingerprint)
    event.set_results.assert_called_once_with(
        {"result": "The client certificate is no longer trusted"}
    )


def test_remove_trusted_client_rejects_invalid_fingerprint():
    """A fingerprint that is not 64 hex characters is rejected."""
    remove = mock.Mock(return_value=True)
    charm = _FakeCharm(lxd_trust_remove=remove)
    event = _event(fingerprint="ABCD")

    charm._on_action_remove_trusted_client(event)

    event.fail.assert_called_once_with("Invalid fingerprint")
    remove.assert_not_called()


def test_remove_trusted_client_reports_removal_failure():
    """The action fails when the certificate cannot be removed."""
    charm = _FakeCharm(lxd_trust_remove=mock.Mock(return_value=False))
    event = _event(fingerprint="AB" * 32)

    charm._on_action_remove_trusted_client(event)

    event.fail.assert_called_once_with(
        "The client certificate was not removed, see the logs for details"
    )


def test_show_pending_config_reports_config_changed():
    """The pending action returns the changed config keys."""
    charm = _FakeCharm(config_changed=mock.Mock(return_value={"sysctl-tuning": True}))
    event = _event()

    charm._on_action_show_pending_config(event)

    event.set_results.assert_called_once_with({"pending": {"sysctl-tuning": True}})


def test_https_relation_broken_removes_departed_app_certificate():
    """The client certificate named after the departed app is removed from the trust store."""
    fingerprint_fn = mock.Mock(return_value="ABC")
    remove = mock.Mock(return_value=True)
    charm = _FakeCharm(
        config={"mode": "standalone"},
        lxd_trust_fingerprint=fingerprint_fn,
        lxd_trust_remove=remove,
    )

    charm._on_https_relation_broken(mock.Mock(app=_Bag("grafana")))

    fingerprint_fn.assert_called_once_with("juju-relation-grafana")
    remove.assert_called_once_with("ABC")


def test_https_relation_broken_ignores_non_leader_in_cluster_mode():
    """In cluster mode only the leader removes the certificate."""
    remove = mock.Mock(return_value=True)
    charm = _FakeCharm(
        config={"mode": "cluster"},
        unit=SimpleNamespace(is_leader=lambda: False),
        _stored=SimpleNamespace(lxd_clustered=True),
        lxd_trust_remove=remove,
    )

    charm._on_https_relation_broken(mock.Mock(app=_Bag("grafana")))

    remove.assert_not_called()


@pytest.mark.parametrize("name", ["", "lxd/0-metrics"])
def test_generate_cert_key_pair_rejects_invalid_name(name):
    """Empty names and names containing a slash are rejected before running openssl."""
    charm = _FakeCharm()

    with mock.patch("charm.subprocess.run") as run:
        assert charm.lxd_generate_cert_key_pair(name) == ("", "")

    run.assert_not_called()
