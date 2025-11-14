#!/usr/bin/env python3

"""LXD charm."""

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from typing import Dict, List, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import pylxd
import yaml
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v0.loki_push_api import LokiPushApiConsumer
from cosl.juju_topology import JujuTopology
from cryptography import x509
from ops.charm import (
    ActionEvent,
    CharmBase,
    ConfigChangedEvent,
    InstallEvent,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationCreatedEvent,
    RelationDepartedEvent,
    RelationJoinedEvent,
    StartEvent,
)
from ops.framework import StoredState
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
    ModelError,
    RelationData,
)

logger = logging.getLogger(__name__)

# Reduce verbosity of API calls made by pylxd
logging.getLogger("urllib3").setLevel(logging.WARNING)

SYSCTL_CONFIGS: Dict[str, int] = {
    "fs.aio-max-nr": 524288,
    "fs.inotify.max_queued_events": 1048576,
    "fs.inotify.max_user_instances": 1048576,
    "fs.inotify.max_user_watches": 1048576,
    "kernel.dmesg_restrict": 1,
    "kernel.keys.maxbytes": 2000000,
    "kernel.keys.maxkeys": 2000,
    "net.ipv4.neigh.default.gc_thresh3": 8192,
    "net.ipv6.neigh.default.gc_thresh3": 8192,
    "vm.max_map_count": 262144,
}

SYSTEMD_TMPFILES_CONFIGS: List[str] = [
    "z /proc/sched_debug 0400 - - -",
    "z /sys/kernel/slab  0700 - - -",
]

REBOOT_REQUIRED_FILE: str = "/run/lxd-reboot-required"


class LxdCharm(CharmBase):
    """LXD charm class."""

    _stored = StoredState()

    # default ports
    ports: Dict[str, int] = {
        "bgp": 179,
        "dns": 53,
        "https": 8443,
        "metrics": 9100,
    }

    def __init__(self, *args):
        """Initialize charm's variables."""
        super().__init__(*args)

        # Initialize the persistent storage if needed
        self._stored.set_default(
            addresses={},
            config={},
            inside_container=False,
            lxd_binary_path="",
            lxd_clustered=False,
            lxd_initialized=False,
            lxd_snap_path="",
            ovn_certificates_present=False,
            reboot_required="false",
        )

        # XXX: not using the default relation_name="grafana-dashboard" to keep supporting the old
        #      grafana machine charm that also used that interface name.
        self.grafana_dashboard_provider = GrafanaDashboardProvider(
            charm=self, relation_name="grafana-dashboard-k8s"
        )
        self._loki_consumer = LokiPushApiConsumer(self)

        # Action event handlers
        self.framework.observe(
            self.on.add_trusted_client_action, self._on_action_add_trusted_client
        )
        self.framework.observe(self.on.debug_action, self._on_action_debug)
        self.framework.observe(self.on.get_client_token_action, self._on_action_get_client_token)
        self.framework.observe(
            self.on.remove_trusted_client_action, self._on_action_remove_trusted_client
        )
        self.framework.observe(
            self.on.show_pending_config_action, self._on_action_show_pending_config
        )

        # Main event handlers
        self.framework.observe(self.on.config_changed, self._on_charm_config_changed)
        self.framework.observe(self.on.install, self._on_charm_install)
        self.framework.observe(self.on.start, self._on_charm_start)
        self.framework.observe(self.on.upgrade_charm, self._on_charm_upgrade)

        # Relation event handlers
        self.framework.observe(self.on.ceph_relation_changed, self._on_ceph_relation_changed)
        self.framework.observe(
            self.on.certificates_relation_changed,
            self._on_certificates_relation_changed,
        )
        self.framework.observe(self.on.cluster_relation_changed, self._on_cluster_relation_changed)
        self.framework.observe(self.on.cluster_relation_created, self._on_cluster_relation_created)
        self.framework.observe(
            self.on.cluster_relation_departed, self._on_cluster_relation_departed
        )
        self.framework.observe(
            self.on.grafana_dashboard_relation_changed,
            self._on_grafana_dashboard_relation_changed,
        )
        self.framework.observe(self.on.https_relation_broken, self._on_https_relation_broken)
        self.framework.observe(self.on.https_relation_changed, self._on_https_relation_changed)
        self.framework.observe(self.on.https_relation_departed, self._on_https_relation_departed)
        self.framework.observe(
            self._loki_consumer.on.loki_push_api_endpoint_joined,
            self._on_loki_push_api_endpoint_joined,
        )
        self.framework.observe(
            self._loki_consumer.on.loki_push_api_endpoint_departed,
            self._on_loki_push_api_endpoint_departed,
        )
        self.framework.observe(
            self.on.ovsdb_cms_relation_changed, self._on_ovsdb_cms_relation_changed
        )
        self.framework.observe(
            self.on.prometheus_manual_relation_changed,
            self._on_prometheus_manual_relation_changed,
        )
        self.framework.observe(
            self.on.prometheus_manual_relation_departed,
            self._on_prometheus_manual_relation_departed,
        )
        self.framework.observe(
            self.on.metrics_endpoint_relation_changed,
            self._on_metrics_endpoint_relation_changed,
        )
        self.framework.observe(
            self.on.metrics_endpoint_relation_created,
            self._on_metrics_endpoint_relation_created,
        )
        self.framework.observe(
            self.on.metrics_endpoint_relation_departed,
            self._on_metrics_endpoint_relation_departed,
        )

    @property
    def metrics_port(self) -> int:
        """Return the port to use for metrics collection."""
        port: int = self.ports["https"]
        if self.config["lxd-listen-metrics"]:
            port = self.ports["metrics"]
        return port

    @property
    def metrics_address(self) -> str:
        """Return the address to use for metrics collection.

        First check if there is a dedicated metrics endpoint and fallback to the generic https
        listener where metrics are also available.
        """
        addr: str = self.juju_space_get_address("metrics") or self.juju_space_get_address("https")
        if not addr:
            return ""

        if ":" in addr:
            addr = f"[{addr}]"
        return addr

    @property
    def metrics_target(self) -> str:
        """Get the metrics target (IP:port)."""
        addr: str = self.metrics_address
        if not addr:
            return ""
        return f"{addr}:{self.metrics_port}"

    @property
    def peers(self):
        """Fetch the cluster relation."""
        return self.model.get_relation("cluster")

    def get_peer_data_dict(self, bag, key: str) -> Dict:
        """Retrieve a dict from the peer data bag."""
        if not self.peers or not bag or not key:
            return {}
        value = json.loads(self.peers.data[bag].get(key, "{}"))
        if isinstance(value, Dict):
            return value
        logger.error(f"Invalid data pulled out from {bag.name}.get('{key}')")
        return {}

    def get_peer_data_list(self, bag, key: str) -> List:
        """Retrieve a list from the peer data bag."""
        if not self.peers or not bag or not key:
            return []
        value = json.loads(self.peers.data[bag].get(key, "[]"))
        if isinstance(value, List):
            return value
        logger.error(f"Invalid data pulled out from {bag.name}.get('{key}')")
        return []

    def get_peer_data_str(self, bag, key: str) -> str:
        """Retrieve a str from the peer data bag."""
        if not self.peers or not bag or not key:
            return ""
        value = self.peers.data[bag].get(key, "")
        if isinstance(value, str):
            return value
        logger.error(f"Invalid data pulled out from {bag.name}.get('{key}')")
        return ""

    def pop_peer_data_str(self, bag, key: str) -> Union[Dict, str]:
        """Pop a str out of the peer data bag."""
        if not self.peers or not bag or not key:
            return ""
        value = self.peers.data[bag].pop(key, "")
        if isinstance(value, str):
            return value
        logger.error(f"Invalid data pulled out from {bag.name}.get('{key}')")
        return ""

    def set_peer_data_dict(self, bag, key: str, value: Dict) -> None:
        """Put a dict into the peer data bag if not there or different."""
        if not self.peers or not bag or not key:
            return

        old_value: Dict = self.get_peer_data_dict(bag, key)
        if old_value != value:
            self.peers.data[bag][key] = json.dumps(value, separators=(",", ":"), sort_keys=True)

    def set_peer_data_list(self, bag, key: str, value: List) -> None:
        """Put a list into the peer data bag if not there or different."""
        if not self.peers or not bag or not key:
            return

        old_value: List = self.get_peer_data_list(bag, key)
        if old_value != value:
            self.peers.data[bag][key] = json.dumps(value, separators=(",", ":"), sort_keys=True)

    def set_peer_data_str(self, bag, key: str, value: str) -> None:
        """Put a str into the peer data bag if not there or different."""
        if not self.peers or not bag or not key:
            return

        old_value: str = self.get_peer_data_str(bag, key)
        if old_value != value:
            self.peers.data[bag][key] = value

    def is_peer_data_version_supported(self, bag) -> bool:
        """Ensure the version in the peer data bag matches what we support."""
        version: str = self.get_peer_data_str(bag, "version")
        return version == "1.0"

    def _get_tls_ca_cert(self) -> str:
        """Return the TLS CA certificate used by the HTTPS listener.

        The CA certificate is cluster.crt when mode=cluster and server.crt
        otherwise.

        On error, return an empty str.
        """
        ca_file: str = "/var/snap/lxd/common/lxd/server.crt"
        if self.config.get("mode", "") == "cluster":
            ca_file = "/var/snap/lxd/common/lxd/cluster.crt"

        if not os.path.exists(ca_file):
            logger.error(f"Certificate file missing ({ca_file})")
            return ""

        try:
            with open(ca_file) as f:
                return f.read()
        except OSError as e:
            logger.error(f"Could not read {ca_file}: {e.strerror}")
            return ""

    @staticmethod
    def _get_tls_san_dnsnames(certificate: str) -> List[str]:
        """Extract the DNSNames from the Subject Alternative Name list of a certificate."""
        try:
            cert = x509.load_pem_x509_certificate(certificate.encode())
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return sans.value.get_values_for_type(x509.DNSName)
        except (ValueError, x509.InvalidVersion, x509.ExtensionNotFound):
            return []

    def _on_action_add_trusted_client(self, event: ActionEvent) -> None:
        """Retrieve and add a client certificate to the trusted list."""
        name: str = event.params.get("name", "unknown")
        cert: str = event.params.get("cert", "")
        cert_url: str = event.params.get("cert-url", "")
        projects: str = event.params.get("projects", "")

        if not cert and not cert_url:
            msg = "One of cert or cert-url parameter needs to be provided."
            event.fail(msg)
            logger.error(msg)
            return

        if cert:
            # The received PEM needs to be mangled to be able to split()
            # on spaces without breaking the "-----BEGIN CERTIFICATE-----"
            # and "-----END CERTIFICATE-----" lines
            cert = "\n".join(cert.replace(" CERTIFICATE", "CERTIFICATE", 2).split()).replace(
                "CERTIFICATE", " CERTIFICATE", 2
            )
            # Ignore the cert-url param if a cert was provided
            cert_url = ""

        if cert_url and not (cert_url.startswith("http://") or cert_url.startswith("https://")):
            msg = 'The cert-url parameter needs to start with "http://" or "https://".'
            event.fail(msg)
            logger.error(msg)
            return

        if cert_url:
            try:
                response = urlopen(cert_url)
            except HTTPError as e:
                msg = f"The server couldn't fulfill the request. Error code: {e.code}"
                event.fail(msg)
                logger.error(msg)
                return
            except URLError as e:
                msg = f"We failed to reach a server. Reason: {e.reason}"
                event.fail(msg)
                logger.error(msg)
                return
            else:
                cert = response.read().decode()

        if not cert:
            msg = "Invalid/empty certificate provided/retrieved."
            event.fail(msg)
            logger.error(msg)
            return

        if self.lxd_trust_add(cert=cert, name=name, projects=projects):
            msg = "The client certificate is now trusted"
            if projects:
                msg += f" for the following project(s): {projects}"
            event.set_results({"result": msg})
        else:
            msg = "Failed to add the certificate to the trusted list"
            if projects:
                msg += f" for the following project(s): {projects}"
            event.fail(msg)
            logger.error(msg)

    def _on_action_debug(self, event: ActionEvent) -> None:
        """Collect information for a bug report."""
        try:
            b = subprocess.run(["lxd.buginfo"], capture_output=True, check=True, timeout=600)
        except subprocess.CalledProcessError as e:
            msg = f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})"
            event.fail(msg)
            logger.error(msg)
            raise RuntimeError
        except subprocess.TimeoutExpired as e:
            msg = f"Timeout exceeded while running {e.cmd!r}"
            event.fail(msg)
            logger.error(msg)
            raise RuntimeError

        event.set_results({"buginfo": b.stdout})
        logger.debug("lxd.buginfo called successfully")

    def _on_action_get_client_token(self, event: ActionEvent) -> None:
        """Return a client certificate add token (to use with: `lxc remote add $rmt $token`).

        An HTTPS listener (lxd-listener-https=true) is required.
        """
        if not self._stored.config["lxd-listen-https"]:
            msg = (
                "The get-client-token action is not usable (lxd-listen-https=false), "
                "please update the config and try again."
            )
            event.fail(msg)
            logger.error(msg)
            return

        name: str = event.params.get("name", "")
        if not name:
            msg = "Missing required parameter: name"
            event.fail(msg)
            logger.error(msg)
            return

        projects: str = event.params.get("projects", "")

        token: str = self.lxd_trust_token(name=name, projects=projects)
        if token:
            msg = f"Client {name} certificate add token:\n{token}"
            event.set_results({"result": msg})
        else:
            msg = "Failed to get a client certificate add token"
            event.fail(msg)
            logger.error(msg)

    def _on_action_remove_trusted_client(self, event: ActionEvent) -> None:
        """Remove a client certificate from the trusted list."""
        fingerprint: str = event.params.get("fingerprint", "")
        if not fingerprint:
            msg = "Missing required parameter: fingerprint"
            event.fail(msg)
            logger.error(msg)
            return

        # Remove any unneeded prefix `openssl` might have left and remove the
        # colons to turn the fingerprint into a string of hex characters:
        # "sha256 Fingerprint=EF:3B:F2:...:28:08:A6" => "EF3BF2...2808A6"
        fingerprint = fingerprint.split("=")[-1].replace(":", "")
        if len(fingerprint) != 64:
            msg = "Invalid fingerprint"
            event.fail(msg)
            logger.error(msg)
            return

        if self.lxd_trust_remove(fingerprint):
            msg = "The client certificate is no longer trusted"
            event.set_results({"result": msg})
        else:
            msg = "The client certificate was not removed, see the logs for details"
            event.fail(msg)
            logger.error(msg)

    def _on_action_show_pending_config(self, event: ActionEvent) -> None:
        """Show the currently pending configuration changes (queued for after the reboot)."""
        event.set_results({"pending": self.config_changed()})

    def _on_charm_config_changed(self, event: Union[ConfigChangedEvent, StartEvent]) -> None:
        """React to configuration changes.

        Some configuration items can be set only once
        while others are changable, sometimes requiring
        a service reload or even a machine reboot.
        """
        logger.info("Updating charm config")

        error = False

        # Model config changes like proxy settings will trigger this event
        # so refresh configuration of core.proxy_* keys
        self.juju_set_proxy()

        # Space binding changes will trigger this event but won't show up in self.config
        # so those need to be processed even when config_changed() returns nothing
        for listener in ("bgp", "dns", "https", "metrics"):
            # Check if we should listen
            toggle_key: str = f"lxd-listen-{listener}"
            toggle_value: str = self.config.get(toggle_key, "")
            if toggle_value:
                space_addr: str = self.juju_space_get_address(listener)

                # Configure a listener or update it if needed
                if space_addr and space_addr != self._stored.addresses.get(listener):
                    if not self.lxd_set_address(listener, space_addr):
                        error = True
                        continue
            elif self._stored.addresses.get(listener):
                # Turn off the existing listener
                if not self.lxd_set_address(listener, ""):
                    error = True
                    continue

            # Save the `lxd-listen-<listener>` toggle value
            self._stored.config[toggle_key] = toggle_value

        # Keep the metrics data up to date
        self._update_metrics_target()
        self.lxd_update_prometheus_manual_scrape_job()

        # Confirm that the config is valid
        if not self.config_is_valid():
            return

        # Get all the configs that changed
        changed = self.config_changed()
        if not changed:
            logger.debug("No configuration changes to apply")
            return

        # Check if the required reboot occurred and clear the flag if yes
        if os.path.exists(REBOOT_REQUIRED_FILE):
            self.unit_blocked("Reboot required, deferring config change")
            event.defer()
            return

        # Check if any required reboot was done
        self.system_clear_reboot_required()

        # Apply all the configs that changed
        try:
            if "snap-channel" in changed:
                self.snap_install_lxd()
            elif "sysctl-tuning" in changed:
                self.kernel_sysctl()
            elif "kernel-hardening" in changed:
                self.kernel_hardening()
            elif [k for k in changed if k.startswith("snap-config-")]:
                self.snap_config_set()
        except RuntimeError:
            msg = "Failed to apply some configuration change(s): {}".format(", ".join(changed))
            self.unit_blocked(msg)
            event.defer()
            return

        # If some changes needed a reboot to take effect, enter blocked status
        if self._stored.reboot_required == "true":
            self.unit_blocked("Machine reboot required")
            return

        # All done
        if error:
            msg = "Some configuration change(s) didn't apply successfully"
        else:
            msg = "Configuration change(s) applied successfully"
        self.unit_active(msg)

    def _on_charm_install(self, event: InstallEvent) -> None:
        logger.info("Installing the LXD charm")
        # Confirm that the config is valid
        if not self.config_is_valid():
            return

        # Install LXD itself
        try:
            self.snap_install_lxd()
            logger.info("LXD installed successfully")
        except RuntimeError:
            logger.error("Failed to install LXD")
            event.defer()
            return

        # Detect if running inside a container
        c = subprocess.run(
            ["systemd-detect-virt", "--quiet", "--container"],
            check=False,
            timeout=600,
        )
        if c.returncode == 0:
            logger.debug(
                "systemd-detect-virt detected the run-time environment as being of container type"
            )
            self._stored.inside_container = True

        # Apply various configs
        self.snap_config_set()
        self.kernel_sysctl()
        self.kernel_hardening()

        # Initial configuration
        try:
            self.lxd_init()
            self._stored.lxd_initialized = True
            logger.info("LXD initialized successfully")
        except RuntimeError:
            logger.error("Failed to initialize LXD")
            event.defer()
            return

        # Apply sideloaded resources attached at deploy time
        self.resource_sideload()

        # All done
        self.unit_active()

    def _on_charm_start(self, event: StartEvent) -> None:
        logger.info("Starting the LXD charm")

        if not self._stored.lxd_initialized:
            logger.debug("LXD is not initialized yet, not starting the charm")
            return

        # Check if any required reboot was done
        self.system_clear_reboot_required()

        if self._stored.reboot_required == "false" and isinstance(self.unit.status, BlockedStatus):
            self.unit_active("Pending configuration changes were applied during the last reboot")

        # Apply pending config changes (those were likely queued up while the unit was
        # down/rebooting)
        if self.config_changed():
            logger.debug("Pending config changes detected")
            self._on_charm_config_changed(event)

    def _on_charm_upgrade(self, _):
        logger.info("Upgrading the LXD charm")

        # Nothing to do if LXD is not initialized yet
        if not self._stored.lxd_initialized:
            logger.info("Nothing to upgrade as LXD is not initialized yet")
            return

        # If LXD was initialized and new `lxd-*` keys are introduced on
        # upgrades, those will need to be taken as-is (with a warning) because
        # they would otherwise cause failures during the config-changed event
        # following the upgrade-charm event.
        changed = self.config_changed()
        for k, v in changed.items():
            # lxd-listen-* keys can be toggled at any time
            if k.startswith("lxd-listen-"):
                continue

            if k.startswith("lxd-"):
                logger.warning(
                    f"The new {k!r} key won't be applied to existing units "
                    "as their LXD is already initialized"
                )
                self._stored.config[k] = v

        # Apply sideloaded resources attached after deployment
        self.resource_sideload()

    def _on_ceph_relation_changed(self, event: RelationChangedEvent) -> None:
        """Create or update ceph.conf and keyring."""
        if not self._stored.config["snap-config-ceph-builtin"]:
            logger.error(
                "The ceph relation is not usable (snap-config-ceph-builtin=false), "
                "please update the config and relate again"
            )
            return

        if not event.unit:
            logger.debug("No available data yet")
            return

        # Get the authentication key (which is the same for every remote unit)
        key: str = event.relation.data[event.unit].get("key", "")
        if not key:
            logger.error(f"Missing key in {event.unit.name}")
            return

        # Get the list of monitor hosts' IPs
        hosts: List[str] = []
        for unit in event.relation.units:
            # Do as charm-ceph-osd which looks for "ceph-public-address"
            # and falls back to the "private-address"
            unit_data = event.relation.data[unit]
            host: str = unit_data.get("ceph-public-address") or unit_data.get("private-address")
            if host:
                logger.debug(f"Related {event.unit.name} has the IP: {host}")
                hosts.append(host)
            else:
                logger.debug(f"Related {event.unit.name} did not provide any IP")

        if not hosts:
            logger.error(f"No monitor IP found in {event.app.name} relation data")
            return

        # Create the config dir if needed
        ceph_dir: str = "/var/snap/lxd/common/ceph"
        if not os.path.exists(ceph_dir):
            os.mkdir(ceph_dir)

        # Creds issued by ceph-mon are for the name of the related app (i.e: lxd)
        ceph_user = self.app.name

        # Save the credentials in the appropriate keyring file
        keyring: str = f"{ceph_dir}/ceph.client.{ceph_user}.keyring"
        if os.path.exists(keyring):
            os.remove(keyring)
        old_umask: int = os.umask(0o077)
        with open(keyring, "w") as f:
            f.write(f"[client.{ceph_user}]\n\tkey = {key}\n")
        os.umask(old_umask)

        # Save a minimal ceph.conf
        ceph_conf: str = f"{ceph_dir}/ceph.conf"
        with open(ceph_conf, "w") as f:
            f.write(f"[global]\n\tmon host = {' '.join(hosts)}\n")

        logger.debug(f"The unit {self.unit.name} can now interact with Ceph")

    def _on_certificates_relation_changed(self, event: RelationChangedEvent) -> None:
        """Retrieve and save the PKI files required to connect to OVN using SSL."""
        if not event.unit:
            logger.debug("event.unit is not set")
            return

        d: RelationData = event.relation.data[event.unit]
        ca: str = d.get("ca", "")
        cert: str = d.get("client.cert", "")
        key: str = d.get("client.key", "")

        if not ca or not cert or not key:
            logger.error(f"Missing ca, cert and/or key in {event.unit.name}")
            return

        # The received PEMs needs to be mangled to be able to split()
        # on spaces without breaking the "-----BEGIN CERTIFICATE-----"
        # and "-----END CERTIFICATE-----" lines
        ca = (
            "\n".join(ca.replace(" CERTIFICATE", "CERTIFICATE", 2).split()).replace(
                "CERTIFICATE", " CERTIFICATE", 2
            )
            + "\n"
        )
        cert = (
            "\n".join(cert.replace(" CERTIFICATE", "CERTIFICATE", 2).split()).replace(
                "CERTIFICATE", " CERTIFICATE", 2
            )
            + "\n"
        )
        key = (
            "\n".join(key.replace(" RSA PRIVATE KEY", "RSA_PRIVATE_KEY", 2).split()).replace(
                "RSA_PRIVATE_KEY", " RSA PRIVATE KEY", 2
            )
            + "\n"
        )

        # Create the config dir if needed
        ovn_dir: str = "/var/snap/lxd/common/ovn"
        if not os.path.exists(ovn_dir):
            os.mkdir(ovn_dir)

        # Reuse Openstack file names
        ca_crt: str = f"{ovn_dir}/ovn-central.crt"
        with open(ca_crt, "w") as f:
            f.write(ca)

        cert_host: str = f"{ovn_dir}/cert_host"
        with open(cert_host, "w") as f:
            f.write(cert)

        # Save the credentials in the appropriate keyring file
        key_host: str = f"{ovn_dir}/key_host"
        if os.path.exists(key_host):
            os.remove(key_host)
        old_umask: int = os.umask(0o077)
        with open(key_host, "w") as f:
            f.write(key)
        os.umask(old_umask)

        self._stored.ovn_certificates_present = True
        logger.debug(f"PKI files required to connect to OVN using SSL saved to {ovn_dir}")

        # If we were previously waiting on a certificates relation we should now unblock
        if (
            isinstance(self.unit.status, BlockedStatus)
            and "'certificates' missing" in self.unit.status.message
        ):
            self.unit_active()

    def _leader_issue_join_token(self, event: RelationChangedEvent) -> None:
        """Check if non-leader units are in need of join tokens."""
        if not event.unit:
            logger.debug("No available data yet")
            return

        if not self.is_peer_data_version_supported(event.unit):
            logger.error(f"Incompatible/missing version found in {event.unit.name}")
            return

        hostname: str = self.get_peer_data_str(event.unit, "hostname")
        if not hostname:
            # Clear the app data bag of any consumed token associated with the remote unit
            if self.pop_peer_data_str(self.app, event.unit.name):
                logger.debug(f"Cleared consumed token for {event.unit.name}")
            else:
                logger.error(f"Missing hostname in {event.unit.name}")
            return

        if self.get_peer_data_str(self.app, event.unit.name):
            logger.debug(f"{event.unit.name} ({hostname}) has not used its join token yet")
            return

        logger.debug(f"Cluster join token request received from {event.unit.name} for {hostname}")
        token: str = self.lxd_cluster_add_token(hostname)
        if not token:
            logger.error(f"Unable to add a join token for hostname={hostname}")
            return

        # Remove the "description" from member_config to reduce the size of the data bag
        member_config: List[Dict] = pylxd.Client().cluster.get().member_config
        for c in member_config:
            _ = c.pop("description", None)

        # XXX: the members dict maintains an assiciation between the Juju unit name
        #      and the LXD cluster member name (hostname/uname). This is needed when
        #      removing cluster members when they depart from the relation.

        # Update the members list in the app data bag with the hostname of the unit that is
        # about to join the cluster
        members: Dict = self.get_peer_data_dict(self.app, "members")
        if not members:
            # If there is no members list, we need to add ourself first
            my_hostname = os.uname().nodename
            logger.debug(f"Initializing the members list with {self.unit.name} ({my_hostname})")
            members = {self.unit.name: my_hostname}

        # Check for hostname colisions
        for unit_name, unit_hostname in members.items():
            if hostname == unit_hostname:
                logger.error(f"Hostname colision with {unit_name} ({hostname})")
                return

        logger.debug(f"Adding {event.unit.name} ({hostname}) to members list")
        members[event.unit.name] = hostname

        # If we made it here, potential problems should have been handled already so it
        # is time to share the information needed by the remote unit to join the cluster
        self.set_peer_data_str(self.app, event.unit.name, token)
        self.set_peer_data_list(self.app, "member_config", member_config)
        self.set_peer_data_dict(self.app, "members", members)

        logger.debug(f"Cluster joining information added for {event.unit.name}")

    def _non_leader_join_cluster(self, event: RelationChangedEvent) -> None:
        """Check if the leader issued a cluster join token for us."""
        # Exit early if already clustered
        if self._stored.lxd_clustered:
            return

        # Check versions of data bags before using them
        for bag in (self.unit, self.app):
            if not self.is_peer_data_version_supported(bag):
                logger.error(f"Incompatible/missing version found in {bag.name}")
                return

        # As a non-leader not yet joined to a cluster, check the app data bag for
        # our join token and the member_config
        my_token: str = self.get_peer_data_str(self.app, self.unit.name)
        if not my_token:
            logger.error(f"Missing token for {self.unit.name} in {self.app.name}")
            return

        cluster_member_config: List[Dict] = self.get_peer_data_list(self.app, "member_config")

        # Use the token and member_config to join the cluster
        logger.debug(f"Cluster joining information found in {self.app.name}")
        self.lxd_cluster_join(my_token, cluster_member_config)

        # Remove our hostname from our unit data bag to signify
        # we no longer need a join token to be emitted
        _ = self.pop_peer_data_str(self.unit, "hostname")

        logger.debug(f"The unit {self.unit.name} is now part of the cluster")

    def _on_cluster_relation_changed(self, event: RelationChangedEvent) -> None:
        """Keep unit information up to date and cluster management.

        All units need to keep their unit data bag up to date.

        The leader unit needs to:
        * Aggregate monitoring information to share with related apps
        * Issue join tokens if mode=cluster

        Non-leaders units need to:
        * Join the cluster using their join token if mode=cluster
        """
        # Keep the metrics data up to date
        self._update_metrics_target()
        if self.unit.is_leader():
            self._update_metrics_endpoint_app_data()

        # Nothing left to do if mode != cluster
        if self.config.get("mode", "") != "cluster":
            return

        if self.unit.is_leader():
            self._leader_issue_join_token(event)
        else:
            self._non_leader_join_cluster(event)

    def _on_cluster_relation_created(self, event: RelationCreatedEvent) -> None:
        """Populate the cluster unit data bag with information to communicate to our peers.

        If mode=cluster, non-leader add their hostname to the unit data bag to signal the
        leader that they need a join token issued for them.
        """
        # Advertise our supported version
        self.set_peer_data_str(self.unit, "version", "1.0")

        # Advertise the supported version in the app data bag
        if self.unit.is_leader():
            self.set_peer_data_str(self.app, "version", "1.0")

        self._update_metrics_target()

        # Nothing left to do if mode != cluster
        if self.config.get("mode", "") != "cluster":
            return

        # The leader does not need to request a join token
        if self.unit.is_leader():
            return

        # Request a join token by adding our hostname to the unit data bag
        hostname: str = os.uname().nodename
        self.set_peer_data_str(self.unit, "hostname", hostname)
        self.unit_maintenance(f"Cluster join token requested ({hostname})")

    def _on_cluster_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Handle cluster members going away. Nothing to do if not clustered."""
        # If we never joined, no point in departing
        if not self._stored.lxd_clustered:
            return

        # Only the leader will deal with node removal
        if not self.unit.is_leader():
            return

        if not self.is_peer_data_version_supported(self.app):
            logger.error(f"Incompatible/missing version found in {self.app.name}")
            return

        # Load the list of cluster members
        members: Dict = self.get_peer_data_dict(self.app, "members")
        if not members:
            logger.error(f"Unable to get the cluster members list from {self.app.name}")
            return

        # Lookup the hostname of the unit that left
        hostname: str = members.pop(event.unit.name, "")
        if not hostname:
            logger.error(
                f"Unable to find the hostname of {event.unit.name}, not removing from the cluster"
            )
            return

        # Remove it from the cluster
        logger.debug(f"Removing {event.unit.name} ({hostname}) from members list")
        self.lxd_cluster_remove(hostname)

        # Save the updated cluster members list
        self.set_peer_data_dict(self.app, "members", members)
        logger.info(f"The unit {event.unit.name} is no longer part of the cluster")

    def _on_grafana_dashboard_relation_changed(self, event: RelationChangedEvent) -> None:
        """Provide the LXD dashboard to Grafana."""
        # Only one dashboard is needed so let the app leader deal with it
        if not self.unit.is_leader():
            return

        # Check if there is an existing relation named "prometheus-manual"
        prometheus_manual_relation = self.model.get_relation("prometheus-manual")
        if not prometheus_manual_relation:
            logger.error(
                "Missing prometheus-manual relation required by grafana-dashboard relation"
            )
            return

        if not prometheus_manual_relation.app.name:
            logger.error("Missing app.name for prometheus-manual relation")
            return

        # Load the dashboard
        dashboard_file = "grafana_dashboards/LXD.json"
        if not os.path.exists(dashboard_file):
            logger.error("No LXD dashboard for Grafana was bundled in the charm")
            return

        with open(dashboard_file) as f:
            data = f.read()
            # XXX: Undo workaround for grafana-k8s-operator's bug
            #      https://github.com/canonical/grafana-k8s-operator/issues/178
            data = data.replace("{prometheusds}", "{DS_LXD}")
            dashboard = json.loads(data)

        # The bundled dashboard should contain:
        #   "__inputs": [
        #     {
        #       "name": "DS_INFRA",
        #       "label": "infra",
        #       "description": "",
        #       "type": "datasource",
        #       "pluginId": "prometheus",
        #       "pluginName": "Prometheus"
        #     }
        #   ],
        # and the name value needs to be replaced by the proper datasource name which
        # is derived from the application name used when Prometheus2 was deployed.
        ds_prometheus = f'"{prometheus_manual_relation.app.name} - Juju generated source"'

        # Safety checks
        if "__inputs" not in dashboard or len(dashboard["__inputs"]) != 1:
            logger.error(f'{dashboard_file} has invalid or missing "__inputs" section')
            return

        # Get the name of the datasource that will need to be replaced
        ds_to_replace = dashboard["__inputs"][0].get("name")
        if not ds_to_replace:
            logger.error(f"{dashboard_file} is malformed")
            return

        # Replace the datasource name
        #   "name": "DS_INFRA"   -> "name": "ds_prometheus"
        #   "uid": "${DS_INFRA}" -> "uid": "ds_prometheus"
        data = data.replace('"' + ds_to_replace + '"', ds_prometheus).replace(
            '"${' + ds_to_replace + '}"', ds_prometheus
        )

        # Reload the mangled data as JSON
        dashboard = json.loads(data)

        # XXX: Introduce an artificial delay before sending the dashboard to
        # Grafana to give time for the prometheus2:grafana-source relation
        # to be established. Without that, the injected dashboard shows
        # as empty requiring manual intervention:
        # # > remove the relation
        # juju remove-relation lxd:grafana-dashboard grafana:dashboards
        # # > log to grafana using the admin password obtained with:
        # juju run --wait=2m grafana/leader get-admin-password
        # # > delete the bogus LXD dashboard
        # # > recreate the relation
        # juju add-relation lxd:grafana-dashboard grafana:dashboards
        time.sleep(60)

        # Send a compact JSON version of the dashboard to Grafana
        event.relation.data[self.app].update(
            {
                "name": self.app.name.upper(),
                "dashboard": json.dumps(
                    dashboard,
                    separators=(",", ":"),
                ),
            }
        )
        logger.debug("LXD dashboard sent to Grafana")

    def _on_https_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Remove the client certificate of the departed app.

        Look through all the certificate to see if one matches the name of
        the departed app.

        Certificates tied to apps are shared among units so they should be removed
        only when the relation is broken indicating all remote units are gone.

        If clustered, only the leader unit needs to take action.
        """
        # In cluster mode, only the leader needs to handle the trust removal
        if self.config.get("mode", "") == "cluster":
            if not self.unit.is_leader() or not self._stored.lxd_clustered:
                return

        if not event.app:
            logger.warning("Unable to remove the client certificate of the departed app")
            return

        fingerprint: str = self.lxd_trust_fingerprint(f"juju-relation-{event.app.name}")
        if fingerprint:
            self.lxd_trust_remove(fingerprint)

    def _on_https_relation_changed(self, event: RelationChangedEvent) -> None:
        """Add the received client certificate to the trusted list.

        If clustered, only the leader unit needs to take action.
        """
        # Relation cannot be rejected so notify the operator if it won't
        # be usable and don't touch the remote unit data bag at all
        if not self._stored.config["lxd-listen-https"]:
            logger.error(
                "The https relation is not usable (lxd-listen-https=false), "
                "please update the config and relate again"
            )
            return

        # In cluster mode, only the leader needs to handle the received cert
        if self.config.get("mode", "") == "cluster":
            if not self.unit.is_leader():
                return

            # Unable to accept certificate because our cluster isn't bootstrapped yet
            if not self._stored.lxd_clustered:
                logger.debug("Cluster not bootstrapped, deferring")
                event.defer()
                return

        # If the remote side is clustered, it will use the app bag
        # if not clustered, the unit bag will be used
        d: Dict = {}
        bag = None
        for bag in (event.app, event.unit):
            if not bag:
                continue

            d = event.relation.data[bag]
            if d.get("version", "") == "1.0":
                logger.debug(f"Valid version found in {bag.name}")
                break
            else:
                logger.error(f"Incompatible/missing version found in {bag.name}")

        if not d or not bag:
            logger.error("No compatible version found in any data bags")
            return

        cert = d.get("certificate", "")
        if not cert:
            logger.error(f"Missing certificate in {bag.name}")
            return

        projects = d.get("projects", "")

        client = pylxd.Client()
        host_env = client.host_info["environment"]

        # With LXD 4.0, `lxc config trust list --format csv` does not show the
        # certificate name provided when adding the certificate. This prevents
        # the charm from adding the `juju-relation-` prefix that is required to
        # later remove the certificate when the relation is broken. Because of
        # this, the charm will refuse to add the certificate if the LXD is too
        # old to allow proper trust management.
        server_major_version: int = int(host_env["server_version"].split(".", 1)[0])
        if server_major_version < 5:
            logger.error(
                "LXD version is too old to allow proper trust management,"
                " suggestion: switch to LXD 5.0 or newer"
            )
            return

        # Only add the cert if not already trusted
        cert_name = f"juju-relation-{bag.name}"
        if not self.lxd_trust_fingerprint(cert_name):
            if self.lxd_trust_add(cert=cert, name=cert_name, projects=projects):
                msg = "The client certificate is now trusted"
                if projects:
                    msg += f" for the following project(s): {projects}"
                logger.info(msg)
            else:
                msg = "Failed to add the certificate to the trusted list"
                if projects:
                    msg += f" for the following project(s): {projects}"
                logger.error(msg)
                return
        else:
            logger.debug(f"The client certificate ({cert_name=}) was already trusted")

        addresses_list: List[str] = []
        if host_env["server_clustered"]:
            for member in client.cluster.members.all():
                addresses_list.append(member.url.replace("https://", ""))
        else:
            addresses_list = host_env["addresses"]

        d = {
            "version": "1.0",
            "certificate": host_env["certificate"],
            "certificate_fingerprint": host_env["certificate_fingerprint"],
            # Only strings are allowed so convert list to comma separated string
            "addresses": ",".join(addresses_list),
        }

        # In cluster mode, put the info in the app data bag
        # otherwise put it in the unit data bag
        if self._stored.lxd_clustered:
            event.relation.data[self.app].update(d)
            logger.debug(f"Connection information put in {self.app.name} app data")
        else:
            event.relation.data[self.unit].update(d)
            logger.debug(f"Connection information put in {self.unit.name} unit data")

    def _on_https_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Remove the client certificate of the departed unit.

        Look through all the certificate to see if one matches the name of
        the departed unit.

        If clustered, only the leader unit needs to take action.
        """
        # In cluster mode, only the leader needs to handle the trust removal
        if self.config.get("mode", "") == "cluster":
            if not self.unit.is_leader() or not self._stored.lxd_clustered:
                return

        if not event.unit:
            logger.warning("Unable to remove the client certificate of the departed unit")
            return

        fingerprint: str = self.lxd_trust_fingerprint(f"juju-relation-{event.unit.name}")
        if fingerprint:
            self.lxd_trust_remove(fingerprint)

    def _on_loki_push_api_endpoint_joined(self, event: RelationJoinedEvent):
        """Configure LXD to send logs to Loki."""
        logger.debug("Loki push API endpoint joined")

        loki_endpoints = self._loki_consumer.loki_endpoints
        if not loki_endpoints:
            logger.debug("loki_endpoints not initialized")
            return

        # There can be multiple Loki endpoints but LXD only supports logging to
        # a single API URL, so pick the first.
        loki_api_url = loki_endpoints[0]["url"]

        # LXD assumes the Loki API URL only contains: protocol + name + port (optional)
        if loki_api_url.endswith("/loki/api/v1/push"):
            loki_api_url = loki_api_url[: -len("/loki/api/v1/push")]

        # Check if LXD supports streaming to Loki
        client = pylxd.Client()
        if not client.has_api_extension("loki"):
            logger.error(
                "LXD is missing the loki API extension so the logging relation is not usable"
            )
            return

        # Configuring LXD to stream to Loki
        try:
            conf = client.api.get().json()["metadata"]["config"]
            if conf.get("loki.api.url") != loki_api_url:
                conf["loki.api.url"] = loki_api_url
                client.api.put(json={"config": conf})
        except pylxd.exceptions.LXDAPIException as e:
            logger.error(f"Failed to set loki.api.url: {e}")
            return

        logger.info(f"LXD is now streaming logs to Loki at {loki_api_url})")

    def _on_loki_push_api_endpoint_departed(self, event: RelationDepartedEvent):
        """Configure LXD to stop sending logs to Loki."""
        logger.debug("Loki push API endpoint departed")

        # Configuring LXD to stop streaming to Loki
        client = pylxd.Client()
        try:
            conf = client.api.get().json()["metadata"]["config"]
            if conf.pop("loki.api.url", None):
                client.api.put(json={"config": conf})
                logger.info("LXD is no longer streaming logs to Loki)")
        except pylxd.exceptions.LXDAPIException as e:
            logger.error(f"Failed to set loki.api.url: {e}")
            return

    def _on_metrics_endpoint_relation_changed(self, event: RelationChangedEvent) -> None:
        """Add the client certificate issued to metrics collection to our trust store.

        The leader unit also needs to keep the app data up to date.
        """
        cert_name: str = f"{event.app.name}-metrics"
        metrics_authentication: Dict = self.get_peer_data_dict(self.app, "metrics_authentication")
        client_cert: str = metrics_authentication.get("client_cert", "")
        if client_cert and not self.lxd_trust_fingerprint(cert_name):
            self.lxd_trust_add(cert=client_cert, name=cert_name, projects="", metrics=True)

        if self.unit.is_leader():
            self._update_metrics_endpoint_app_data()

    def _on_metrics_endpoint_relation_created(self, event: RelationCreatedEvent) -> None:
        """The app leader issues a client certificate/key for metrics collection.

        # XXX: the data is saved in the peer app bag as all units need to access it.
        """
        if not self.metrics_address:
            logger.error(
                f"The {event.relation.name} relation is not usable (lxd-listen-https=false and "
                "lxd-listen-metrics=false), please update the config and relate again"
            )
            return

        if not self.unit.is_leader():
            return

        cert_name: str = f"{event.app.name}-metrics"
        (client_cert, client_key) = self.lxd_generate_cert_key_pair(cert_name)
        if not client_cert or not client_key:
            logger.error(f"Unable to generate a certificate/key pair for {cert_name}")
            return

        metrics_authentication: Dict = {
            "client_cert": client_cert,
            "client_key": client_key,
        }
        self.set_peer_data_dict(self.app, "metrics_authentication", metrics_authentication)

    def _on_metrics_endpoint_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Remove any client certificate the departed used used for metrics scraping.

        Look through all the certificates to see if one matches the name of
        the departed app.

        XXX: not using using relation_broken to ensure event.app still exists.
        """
        # If clustered, only the leader needs to deal with the cert removal
        if self._stored.lxd_clustered and not self.unit.is_leader():
            return

        cert_name: str = f"{event.app.name}-metrics"
        fingerprint: str = self.lxd_trust_fingerprint(cert_name)
        if fingerprint:
            self.lxd_trust_remove(fingerprint)

    def _on_ovsdb_cms_relation_changed(self, event: RelationChangedEvent) -> None:
        """Assemble a DB connection string to connect to OVN."""
        # Check if LXD can interact with OVN networks
        client = pylxd.Client()
        if not client.has_api_extension("network_type_ovn"):
            logger.error(
                "LXD is missing the network_type_ovn API extension so the ovsdb-cms relation"
                " is not usable"
            )
            return

        # Ensure builtin OVN tooling is used
        if not self._stored.config["snap-config-ovn-builtin"]:
            logger.error(
                "The ovsdb-cms relation is not usable (snap-config-ovn-builtin=false), "
                "please update the config and relate again"
            )
            return

        # For OVN to be usable, we need the PKI files to connect to it
        if not self._stored.ovn_certificates_present:
            self.unit_blocked("'certificates' missing")
            return

        # Get the list of ovn-central hosts' IPs
        hosts: List[str] = []
        for unit in event.relation.units:
            unit_data = event.relation.data[unit]
            host: str = unit_data.get("bound-address", "")
            if host:
                host = host.replace('"', "", 2)
                if ":" in host:
                    host = f"[{host}]"
                # OVN Northbound DB hosts listen with SSL on port 6641
                host = f"ssl:{host}:6641"
                hosts.append(host)
                logger.debug(f"Related {event.unit.name} is reachable at: {host}")
            else:
                logger.debug(f"Related {event.unit.name} did not provide any IP")

        if not hosts:
            logger.error(f"No ovn-central IP found in {event.app.name} relation data")
            return

        db: str = ",".join(sorted(hosts))

        # Configuring LXD to connect to ovn-central DB
        try:
            conf = client.api.get().json()["metadata"]["config"]
            if conf.get("network.ovn.northbound_connection") != db:
                conf["network.ovn.northbound_connection"] = db
                client.api.put(json={"config": conf})
        except pylxd.exceptions.LXDAPIException as e:
            logger.error(f"Failed to set network.ovn.northbound_connection: {e}")
            return

        logger.info(f"LXD is now connected to ovn-central DB (NB connection={db})")

        # Let OVN know which IP will be used to connect to it
        bound_address: str = self.juju_space_get_address("ovsdb-cms")
        if not bound_address:
            logger.error("Unable to find the address bounded to ovsdb-cms space")
            return

        if ":" in bound_address:
            bound_address = f"[{bound_address}]"

        event.relation.data[self.unit].update(
            {
                "cms-client-bound-address": bound_address,
            }
        )
        logger.debug(
            f"Connection information put in {self.unit.name} "
            "(cms-client-bound-address={bound_address})"
        )

    def _on_prometheus_manual_relation_changed(self, event: RelationChangedEvent) -> None:
        """Send scrape config job info to Prometheus."""
        if not self.metrics_address:
            logger.error(
                f"The {event.relation.name} relation is not usable (lxd-listen-https=false and "
                "lxd-listen-metrics=false), please update the config and relate again"
            )
            return

        remote_unit_name: str = ""
        if event.unit:
            remote_unit_name = f"{event.unit.name}-metrics".replace("/", "_")
        self.lxd_update_prometheus_manual_scrape_job(remote_unit_name)

    def _on_prometheus_manual_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Remove any client certificate the departed unit used for metrics scraping.

        Look through all the certificate to see if one matches the name of
        the departed unit.
        """
        if not event.unit:
            logger.error(
                "Could not remove the client certificate used for metrics scraping as"
                " the remote unit is unknown"
            )
            return

        fingerprint: str = self.lxd_trust_fingerprint(
            f"{event.unit.name}-metrics".replace("/", "_")
        )
        if fingerprint:
            self.lxd_trust_remove(fingerprint)

    def config_changed(self) -> Dict:
        """Figure out what changed."""
        new_config = self.config
        old_config = self._stored.config
        apply_config = {}
        for k, v in new_config.items():
            if k not in old_config:
                apply_config[k] = v
            elif v != old_config[k]:
                apply_config[k] = v

        return apply_config

    def config_is_valid(self) -> bool:
        """Validate the config."""
        if "local" in self.model.storages and len(self.model.storages["local"]) > 1:
            self.unit_blocked("LXD charm only supports a single storage volume")
            return False

        config_changed = self.config_changed()

        # If nothing changed and we were blocked due to a lxd- key
        # change (post-init), we can assume the change was reverted thus unblocking us
        if (
            not config_changed
            and isinstance(self.unit.status, BlockedStatus)
            and "Can't modify lxd- keys after initialization:" in self.unit.status.message
        ):
            self.unit_active("Unblocking as the lxd- keys were reset to their initial values")

        for k in config_changed:
            if k == "mode" and self._stored.lxd_initialized:
                self.unit_blocked("Can't modify mode after initialization")
                return False

            # lxd-listen-* keys can be toggled at any time
            if k.startswith("lxd-listen-"):
                continue

            if k.startswith("lxd-") and self._stored.lxd_initialized:
                self.unit_blocked(f"Can't modify lxd- keys after initialization: {k}")
                return False

        # If lxd-preseed is set, ensure it's valid YAML. Allowed in any mode.
        preseed: str = self.config.get("lxd-preseed", "")
        if preseed:
            try:
                _ = yaml.safe_load(preseed)
            except yaml.YAMLError as e:
                self.unit_blocked(f"Invalid YAML in lxd-preseed: {e}")
                return False

        return True

    def juju_space_get_address(self, space_name: str, require_ipv4: bool = False) -> str:
        """Return the primary IP address of network space.

        If require_ipv4 is True, return the first IPv4 available
        in the network space, if any, an emtpy string otherwise.
        """
        binding = self.model.get_binding(space_name)
        if not binding:
            return ""

        net = binding.network

        # ingress_addresses can contains strings (hostnames) while we only want IPs
        addrs = [a for a in net.ingress_addresses if not isinstance(a, str)]
        if not addrs:
            return ""

        if not require_ipv4:
            return str(addrs[0])

        ipv4_addrs = [a for a in addrs if a.version == 4]
        if ipv4_addrs:
            return str(ipv4_addrs[0])

        return ""

    def juju_set_proxy(self) -> None:
        """Apply proxy config."""
        http_proxy = os.getenv("JUJU_CHARM_HTTP_PROXY", "")
        https_proxy = os.getenv("JUJU_CHARM_HTTPS_PROXY", "")
        no_proxy = os.getenv("JUJU_CHARM_NO_PROXY", "")
        logger.debug(
            f"Retrieved proxy config from model: http-proxy='{http_proxy}', "
            f"https-proxy='{https_proxy}', no-proxy='{no_proxy}'"
        )

        try:
            client = pylxd.Client()
            conf = client.api.get().json()["metadata"]["config"]
            refresh: bool = False
            if conf.get("core.proxy_http", "") != http_proxy:
                refresh = True
                logger.debug(f"Configuring core.proxy_http={http_proxy}")
                conf["core.proxy_http"] = http_proxy
            if conf.get("core.proxy_https", "") != https_proxy:
                refresh = True
                logger.debug(f"Configuring core.proxy_https={https_proxy}")
                conf["core.proxy_https"] = https_proxy
            if conf.get("core.proxy_ignore_hosts", "") != no_proxy:
                refresh = True
                logger.debug(f"Configuring core.proxy_ignore_hosts={no_proxy}")
                conf["core.proxy_ignore_hosts"] = no_proxy

            if refresh:
                logger.info("Applying proxy configuration to LXD")
                client.api.put(json={"config": conf})

        except pylxd.exceptions.LXDAPIException as e:
            self.unit_blocked(f"Failed to set core.proxy_*: {e}")
            raise RuntimeError

    def kernel_sysctl(self) -> None:
        """Apply sysctl tuning keys."""
        logger.debug("Applying sysctl tuning")
        sysctl_file = "/etc/sysctl.d/60-lxd.conf"
        config = self.config["sysctl-tuning"]

        if config:
            self.unit_maintenance(f"Applying sysctl config file: {sysctl_file}")
            with open(sysctl_file, "w", encoding="UTF-8") as f:
                f.write("# Generated by LXD charm\n")
                for k, v in SYSCTL_CONFIGS.items():
                    f.write(f"{k} = {v}\n")

            try:
                subprocess.run(
                    ["sysctl", "--quiet", "--load", sysctl_file],
                    capture_output=True,
                    check=True,
                    timeout=600,
                )
            except subprocess.CalledProcessError as e:
                if not self._stored.inside_container:
                    self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
                    raise RuntimeError
                else:
                    self.unit_maintenance(
                        f"Ignoring failed execution of {e.cmd!r} due to being inside a container"
                    )
            except subprocess.TimeoutExpired as e:
                self.unit_blocked(f"Timeout exceeded while running {e.cmd!r}")
                raise RuntimeError

        elif os.path.exists(sysctl_file):
            self.unit_maintenance(f"Removing sysctl config file: {sysctl_file}")
            os.remove(sysctl_file)

        # Persist the configuration
        self._stored.config["sysctl-tuning"] = config

    def kernel_hardening(self) -> None:
        """Apply kernel hardening systemd tmpfiles."""
        logger.debug("Applying kernel hardening")
        systemd_tmpfiles = "/etc/tmpfiles.d/lxd.conf"
        config = self.config["kernel-hardening"]

        if config:
            self.unit_maintenance(f"Applying kernel hardening config file: {systemd_tmpfiles}")
            with open(systemd_tmpfiles, "w", encoding="UTF-8") as f:
                f.write("# Generated by LXD charm\n")
                f.write("\n".join(SYSTEMD_TMPFILES_CONFIGS) + "\n")
            try:
                subprocess.run(
                    ["systemd-tmpfiles", "--create"],
                    capture_output=True,
                    check=True,
                    timeout=600,
                )
            except subprocess.CalledProcessError as e:
                if not self._stored.inside_container:
                    self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
                    raise RuntimeError
                else:
                    self.unit_maintenance(
                        f"Ignoring failed execution of {e.cmd!r} due to being inside a container"
                    )
            except subprocess.TimeoutExpired as e:
                self.unit_blocked(f"Timeout exceeded while running {e.cmd!r}")
                raise RuntimeError

        elif os.path.exists(systemd_tmpfiles):
            self.unit_maintenance(f"Removing kernel hardening config file: {systemd_tmpfiles}")
            os.remove(systemd_tmpfiles)

        # Persist the configuration
        self._stored.config["kernel-hardening"] = config

    def lxd_cluster_add_token(self, hostname: str) -> str:
        """Add/issue a join token for `hostname`."""
        c = subprocess.run(
            ["lxc", "cluster", "add", hostname],
            capture_output=True,
            check=False,
            encoding="UTF-8",
            timeout=600,
        )
        if c.returncode != 0 or not c.stdout:
            logger.error(
                f'The command "lxc cluster add {hostname}" did not produce '
                f"any output (rc={c.returncode}, error={c.stderr})"
            )
            return ""

        try:
            token = c.stdout.splitlines()[1]
        except IndexError:
            return ""

        return token

    def lxd_apply_preseed(self, preseed_yaml: bytes) -> None:
        """Apply a YAML preseed to LXD."""
        logger.debug("Applying LXD preseed")

        try:
            subprocess.run(
                ["lxd", "init", "--preseed"],
                capture_output=True,
                check=True,
                input=preseed_yaml,
                timeout=600,
            )
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")

            # Leave a copy of the YAML preseed that didn't work
            handle, tmp_file = tempfile.mkstemp()
            with os.fdopen(handle, "wb") as f:
                f.write(preseed_yaml)
            logger.error(f"The YAML preseed that caused a failure was saved to {tmp_file}")
            raise RuntimeError
        except subprocess.TimeoutExpired as e:
            logger.error(f"Timeout exceeded while running {e.cmd!r}")
            raise RuntimeError

        logger.debug("LXD preseed applied successfully")

    def lxd_cluster_join(self, token: str, member_config: List[Dict]) -> None:
        """Join an existing cluster."""
        logger.debug("Joining cluster")

        # If a local storage device was provided, it needs to be added in the storage-pool
        if "local" in self.model.storages and len(self.model.storages["local"]) == 1:
            for m in member_config:
                if m.get("entity") == "storage-pool" and m.get("key") == "source":
                    dev = str(self.model.storages["local"][0].location)
                    m["value"] = dev

        cluster_address = self.juju_space_get_address("cluster")
        if not cluster_address:
            self.unit_blocked("Unable to get the cluster space address")
            raise RuntimeError

        preseed = {
            "config": {},
            "networks": [],
            "storage_pools": [],
            "profiles": [],
            "projects": [],
            "cluster": {
                "enabled": True,
                "member_config": member_config,
                "server_address": cluster_address,
                "cluster_token": token,
            },
        }
        preseed_yaml = yaml.safe_dump(
            preseed,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="UTF-8",
        )

        self.unit_maintenance("Joining cluster")
        try:
            subprocess.run(
                ["lxd", "init", "--preseed"],
                check=True,
                input=preseed_yaml,
                timeout=600,
            )
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")

            # Leave a copy of the YAML preseed that didn't work
            handle, tmp_file = tempfile.mkstemp()
            with os.fdopen(handle, "wb") as f:
                f.write(preseed_yaml)
            logger.error(f"The YAML preseed that caused a failure was saved to {tmp_file}")
            raise RuntimeError
        except subprocess.TimeoutExpired as e:
            logger.error(f"Timeout exceeded while running {e.cmd!r}")
            raise RuntimeError

        self.unit_active()
        self._stored.lxd_clustered = True
        logger.debug(f"Cluster joined successfully consuming the token: {token}")

    def lxd_cluster_remove(self, member: str) -> None:
        """Remove a member from the cluster.

        Check if the departing unit is actually a cluster member and then
        proceed with the removal.
        """
        client = pylxd.Client()
        try:
            if not client.cluster.enabled:
                logger.debug(f"Clustering not enabled for {member}")
                return
        except AttributeError:
            logger.debug("pylxd is too old, the cluster.enabled attribute is missing")

        try:
            m = client.cluster.members.get(member)
            m.delete()
        except pylxd.exceptions.NotFound:
            logger.debug(f"Not removing {member} from the cluster as it is not part of it")
            return
        except pylxd.exceptions.LXDAPIException as e:
            self.unit_blocked(f"Failed to remove {member} from the cluster: {e}")

    def lxd_generate_cert_key_pair(self, name: str) -> Tuple[str, str]:
        """Generate a certificate and key pair."""
        if not name:
            logger.error("The name cannot be empty.")
            return ("", "")

        if "/" in name:
            logger.error('The name cannot contain a "/".')
            return ("", "")

        cmd: List[str] = [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:secp384r1",
            "-sha384",
            "-keyout",
            "-",
            "-out",
            "certificate.crt",
            "-nodes",
            "-subj",
            f"/CN={name}",
            "-days",
            "+3650",
        ]
        try:
            c = subprocess.run(
                cmd,
                capture_output=True,
                check=True,
                encoding="UTF-8",
                timeout=600,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
            return ("", "")
        except subprocess.TimeoutExpired as e:
            logger.error(f"Timeout exceeded while running {e.cmd!r}")
            return ("", "")

        # The key data was output to stdout and never touched the disk
        # but the certificate data needs to be read from the file that
        # can then be discarded
        key: str = c.stdout
        with open("certificate.crt") as f:
            cert: str = f.read()
        os.remove("certificate.crt")

        return (cert, key)

    def lxd_get_prometheus_targets(self) -> Dict[str, str]:
        """Return a dict of targets (unit name and their endpoint) to be scraped by Prometheus.

        Non-leader return an empty list.

        The leader will look in the units' peer data to collect all the metrics_target.
        """
        if not self.unit.is_leader():
            return {}

        # Start with the leader's own metrics_target
        targets: Dict[str, str] = {
            self.unit.name: self.metrics_target,
        }

        # If we have no peer, assume we are alone
        if not self.peers:
            return targets

        # Otherwise add the other units
        for unit in self.peers.units:
            target: str = self.get_peer_data_str(unit, "metrics_target")
            if not target:
                logger.error(f"Couldn't obtain {unit.name}'s metrics_target")
                continue
            targets[unit.name] = target

        return dict(sorted(targets.items()))

    def _get_metrics_tls_config(self) -> Dict:
        """Return a tls_config usable by Prometheus."""
        tls_config: Dict = {}
        if self._stored.lxd_clustered:
            # TLS server verification
            ca_file = self._get_tls_ca_cert()

            # The metrics-endpoint will make a connection to the `targets` `IP:port`
            # which won't be covered by LXD TLS certs. As such, tell the metrics-endpoint
            # to expect a certain server name and use it for TLS verification.
            if dnsnames := self._get_tls_san_dnsnames(ca_file):
                tls_config = {
                    "ca_file": ca_file,
                    "server_name": dnsnames[0],
                }
            else:
                logger.error(
                    "Unable to obtain the server_name from the CA certificate, "
                    "disabling TLS server verification"
                )
                tls_config["insecure_skip_verify"] = True
        else:
            # XXX: in mode=standalone, each unit uses a different server.crt
            #      and only the leader can send a client cert/key to the
            #      metrics-endpoint consumer side. As such, skip TLS verification.
            logger.info("TLS server verification disabled (not clustered)")
            tls_config["insecure_skip_verify"] = True

        # TLS client authentication needs a cert_file and key_file for the remote app
        metrics_authentication: Dict = self.get_peer_data_dict(self.app, "metrics_authentication")
        if "client_cert" in metrics_authentication and "client_key" in metrics_authentication:
            tls_config["cert_file"] = metrics_authentication["client_cert"]
            tls_config["key_file"] = metrics_authentication["client_key"]
        else:
            logger.info("TLS client authentication disabled")

        return tls_config

    def _update_metrics_target(self) -> None:
        """Keep our metrics_target info up to date."""
        self.set_peer_data_str(self.unit, "metrics_target", self.metrics_target)

    def _update_metrics_endpoint_app_data(self) -> None:
        """Update the app data with the information needed for metrics collection."""
        rel = self.model.get_relation("metrics-endpoint")
        if not rel:
            logger.debug("No metrics-endpoint relation")
            return

        # scrape_jobs
        scrape_job_template: Dict = {
            "metrics_path": "/1.0/metrics",
            "scheme": "https",
            "tls_config": self._get_metrics_tls_config(),
        }
        scrape_jobs: List[Dict] = []
        if self._stored.lxd_clustered:
            # In mode=cluster, only one scrape job coverring all the targets (cluster units)
            # is needed
            scrape_job = scrape_job_template.copy()
            scrape_job["static_configs"] = [
                {"targets": [target for target in self.lxd_get_prometheus_targets().values()]}
            ]
            scrape_jobs = [scrape_job]
        else:
            # In mode=standalone, the leader will create multiple scrape jobs, each covering
            # a single target (a LXD unit)
            for unit_name, target in self.lxd_get_prometheus_targets().items():
                scrape_job = scrape_job_template.copy()
                scrape_job["job_name"] = unit_name.replace("/", "-")
                scrape_job["static_configs"] = [{"targets": [target]}]
                scrape_jobs.append(scrape_job)

        scrape_metadata: Dict = JujuTopology.from_charm(self).as_dict()

        rel.data[self.app].update(
            {
                "scrape_jobs": json.dumps(scrape_jobs, separators=(",", ":")),
                "scrape_metadata": json.dumps(scrape_metadata, separators=(",", ":")),
            }
        )

    def lxd_update_prometheus_manual_scrape_job(self, remote_unit_name: str = "") -> None:
        """Update the prometheus-manual scrape_job if applicable.

        Nothing to do unless there is a "prometheus-manual" relation.

        If mode=standalone, each unit needs to update its prometheus unit data bag.
        If mode=cluster, each unit needs to update cluster's unit data bag
        and only the lxd/leader needs to update the prometheus-manual's unit data bag.

        The remote_unit_name parameter is used to issue a TLS certificate for the prometheus
        scraper. If not provided, an existing TLS certificate is reused.
        """
        prometheus_relation = self.model.get_relation("prometheus-manual")
        if not prometheus_relation:
            logger.debug(
                "No need to update the metrics endpoint as no relation with"
                " prometheus-manual found"
            )
            return

        # Ensure request_id uniqueness
        my_id: str = self.app.name
        if not self._stored.lxd_clustered:
            # Replace foo/0 by foo_0 as `openssl req -subj` doesn't like '/'
            my_id = self.unit.name.replace("/", "_")

        # Include our own model name in the request_id to avoid potential
        # collisions when doing Cross-Model Relations (CMRs) because the unit
        # name is not subject to the normal unit name translation done during CMR
        my_id = f"{self.model.name}_{my_id}"
        scrape_job_key: str = f"request_{my_id}"

        # The scrape_job can be generated on the fly with the exception of the
        # client_cert/client_key that should be preserved.
        old_scrape_job: str = prometheus_relation.data[self.unit].get(scrape_job_key, "")
        client_cert: str = ""
        client_key: str = ""
        if old_scrape_job:
            old_data: Dict = json.loads(old_scrape_job)
            client_cert = old_data["client_cert"]
            client_key = old_data["client_key"]
        elif remote_unit_name:
            (client_cert, client_key) = self.lxd_generate_cert_key_pair(remote_unit_name)

            if client_cert:
                self.lxd_trust_add(
                    cert=client_cert,
                    name=remote_unit_name,
                    projects="",
                    metrics=True,
                )
        else:
            logger.error(
                "Unable to generate a TLS client certificate for the remote unit as no"
                " name was provided"
            )
            return

        if not client_cert or not client_key:
            logger.error("Invalid/missing TLS certificate for the remote unit")
            return

        scrape_job = {
            scrape_job_key: json.dumps(
                {
                    "job_name": self.unit.name,
                    "request_id": my_id,
                    "job_data": {
                        "metrics_path": "/1.0/metrics",
                        "scheme": "https",
                        "static_configs": [{"targets": self.metrics_target}],
                        "tls_config": {
                            "insecure_skip_verify": True,
                        },
                    },
                    "client_cert": client_cert,
                    "client_key": client_key,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
        }

        # Compare the old scrape_job with the current one before updating
        if old_scrape_job != scrape_job[scrape_job_key]:
            logger.debug(f"Updating Prometheus scrape_job ({scrape_job_key})")
            prometheus_relation.data[self.unit].update(scrape_job)
        else:
            logger.debug(f"Prometheus scrape_job ({scrape_job_key}) already up to date")

    def lxd_init(self) -> None:
        """Apply initial configuration of LXD."""
        mode: str = self.config.get("mode", "")
        self.unit_maintenance(f"Initializing LXD in {mode} mode")

        preseed: str = self.config.get("lxd-preseed", "")

        # network and storage pool creation can be disabled by the config
        init_storage: bool = self.config["lxd-init-storage"]
        init_network: bool = self.config["lxd-init-network"]

        if preseed:
            assert mode == "standalone", "lxd-preseed is only supported when mode=standalone"

            self.unit_maintenance("Applying LXD preseed")

            try:
                # NOTE: When preseeding, no further configuration is applied.
                subprocess.run(
                    ["lxd", "init", "--preseed"],
                    capture_output=True,
                    check=True,
                    input=preseed.encode(),
                    timeout=600,
                )
            except subprocess.CalledProcessError as e:
                self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
                raise RuntimeError
            except subprocess.TimeoutExpired as e:
                self.unit_blocked(f"Timeout exceeded while running {e.cmd!r}")
                raise RuntimeError
        else:
            self.unit_maintenance("Performing initial configuration")

            configure_storage: bool = True
            network_dev: str = ""

            if mode == "standalone":
                configure_storage = True
                network_dev = "lxdbr0"
            elif self.unit.is_leader():  # leader and mode=cluster
                configure_storage = True
                network_dev = "lxdfan0"
            else:  # non-leader and mode=cluster
                configure_storage = False
                network_dev = ""

            if not init_storage:
                configure_storage = False
            if not init_network:
                network_dev = ""

            client = pylxd.Client()
            profile = client.profiles.get("default")

            if configure_storage:
                if client.storage_pools.exists("local"):
                    logger.debug("Existing storage pool detected")
                    configure_storage = False

            if network_dev:
                if client.networks.exists(network_dev):
                    logger.debug("Existing network detected")
                    network_dev = ""

            try:
                # Configure the storage
                if configure_storage:
                    if "local" in self.model.storages and len(self.model.storages["local"]) == 1:
                        src = f"source={self.model.storages['local'][0].location}"
                        self.unit_maintenance("Configuring external storage pool (zfs, {src})")
                        client.storage_pools.create(
                            {
                                "name": "local",
                                "driver": "zfs",
                                "source": src,
                            }
                        )
                    else:
                        self.unit_maintenance("Configuring local storage pool (dir)")
                        client.storage_pools.create(
                            {
                                "name": "local",
                                "driver": "dir",
                            }
                        )

                    if not profile.devices.get("root"):
                        profile.devices["root"] = {
                            "type": "disk",
                            "pool": "local",
                            "path": "/",
                        }

                # Configure the network
                if network_dev:
                    network_config: Dict = {}
                    if network_dev == "lxdfan0":  # try to find a valid subnet to use for FAN
                        try:
                            fan_address = self.juju_space_get_address("fan", require_ipv4=True)
                            fan_subnet = ipaddress.IPv4Network(fan_address).supernet(new_prefix=16)
                            logger.debug(f"Using {fan_subnet} as FAN underlay network")
                            network_config = {
                                "bridge.mode": "fan",
                                "fan.underlay_subnet": str(fan_subnet),
                            }
                        except Exception:
                            msg = "Can't find a valid subnet for FAN, falling back to lxdbr0"
                            self.unit_maintenance(msg)
                            network_dev = "lxdbr0"
                            network_config = {}

                    self.unit_maintenance(f"Configuring network bridge ({network_dev})")
                    client.networks.create(network_dev, config=network_config)

                    if not profile.devices.get("eth0"):
                        profile.devices["eth0"] = {
                            "type": "nic",
                            "network": network_dev,
                            "name": "eth0",
                        }

                if mode == "cluster":
                    cluster_address = self.juju_space_get_address("cluster")
                    if not cluster_address:
                        self.unit_blocked("Unable to get the cluster space address")
                        raise RuntimeError

                    self.unit_maintenance(f"Configuring cluster.https_address ({cluster_address})")
                    conf = client.api.get().json()["metadata"]["config"]
                    if conf.get("cluster.https_address") != cluster_address:
                        conf["cluster.https_address"] = cluster_address
                        client.api.put(json={"config": conf})

                    # XXX: prevent the creation of another parallel cluster by checking if there is
                    # already an app data bag (self.model.get_relation("cluster").data[self.app])

                    # Enable clustering if needed
                    if self.unit.is_leader():
                        self.unit_maintenance("Enabling cluster mode")
                        try:
                            client.cluster.enable(server_name=os.uname().nodename)
                            self._stored.lxd_clustered = True
                        except pylxd.exceptions.LXDAPIException as e:
                            self.unit_blocked(f"Failed to enable cluster mode: {e}")
                            raise RuntimeError

                # Persist profile changes
                profile.save()

            except pylxd.exceptions.LXDAPIException as e:
                self.unit_blocked(f"Failed to configure LXD: {e}")
                raise RuntimeError

        # Initial configuration of core.proxy_* keys
        self.juju_set_proxy()

        # Done with the initialization
        self._stored.config["mode"] = mode
        self._stored.config["lxd-preseed"] = preseed
        self._stored.config["lxd-init-storage"] = init_storage
        self._stored.config["lxd-init-network"] = init_network

        # Flag any `lxd-*` keys not handled, except the `lxd-listen-*`, there should be none
        for k in self.config_changed():
            if k.startswith("lxd-listen-"):
                continue
            if k.startswith("lxd-"):
                logger.error(f"lxd_init did not handle the key config named: {k}")

    def lxd_is_active(self) -> bool:
        """Indicate if the lxd daemon is active."""
        c = subprocess.run(
            ["systemctl", "is-active", "--quiet", "snap.lxd.daemon.service"],
            check=False,
            timeout=600,
        )
        return c.returncode == 0

    def lxd_monitor_lifecycle(self) -> None:
        """Monitor lifecycle events (blocking)."""
        event_types = {pylxd.EventType.Lifecycle}
        events = pylxd.Client().events(event_types=event_types)
        events.connect()
        events.run()

    def lxd_reload(self) -> None:
        """Reload the lxd daemon."""
        self.unit_maintenance("Reloading LXD")
        try:
            # Avoid occasional race during startup where a reload could cause a failure
            subprocess.run(["lxd", "waitready", "--timeout=30"], capture_output=True, check=False)
            # Start a monitor thread and wait for it to exit due to the service
            # reloading and the old lxd process closing the monitor's socket.
            # Use lifecycle event type as filter because it's low bandwidth.
            mon = threading.Thread(
                target=self.lxd_monitor_lifecycle, name="lxd-monitor", daemon=True
            )
            mon.start()
            subprocess.run(
                ["systemctl", "reload", "snap.lxd.daemon.service"],
                capture_output=True,
                check=True,
            )
            mon.join(timeout=600.0)

            # If the monitor thread is still alive, it means LXD didn't reload
            if mon.is_alive():
                # There is no easy way to terminate the hanging thread but the charm
                # process is short-lived anyway.
                self.unit_maintenance("Timeout while reloading the LXD service")
                raise RuntimeError

        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
            raise RuntimeError

    def lxd_set_address(self, listener: str, addr: str) -> bool:
        """Configure the core.<listener>_address and save the configured address.

        Also save the boolean toggle to enable/disable the listener.
        """
        if listener not in self.ports:
            logger.error(f"Invalid listener ({listener}) provided")
            return False

        # Some listeners require a special API extension
        api_extensions: Dict[str, str] = {
            "bgp": "network_bgp",
            "dns": "network_dns",
            "metrics": "metrics",
        }

        required_api: str = api_extensions.get(listener, "")

        client = pylxd.Client()
        if required_api and not client.has_api_extension(required_api):
            msg = (
                f"LXD is missing the {required_api} API extension: "
                f"unable to set core.{listener}_address"
            )
            logger.error(msg)
            return False

        if addr:
            msg = f"Configuring core.{listener}_address ({addr})"
        else:
            msg = f"Disabling core.{listener}_address"
        logger.debug(msg)

        try:
            client.api.patch(f'{{"config": {{"core.{listener}_address": "{addr}"}}}}')
        except Exception as e:
            logger.error(f"Failed to set listener: {e}")
            return False

        # open/close-port
        cmd: List[str] = ["close-port"]
        if addr:
            cmd = ["open-port"]
        cmd += [str(self.ports[listener]), "--endpoints", listener]
        logger.debug(f"Calling {cmd}")

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                check=True,
                timeout=600,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
            return False
        except subprocess.TimeoutExpired as e:
            logger.error(f"Timeout exceeded while running {e.cmd!r}")
            return False

        # Save the addr instead of the socket because it makes it easier
        # to compare with the IP returned by get_binding()
        self._stored.addresses[listener] = addr

        return True

    def lxd_trust_add(
        self, cert: str, name: str, projects: str = "", metrics: bool = False
    ) -> bool:
        """Add a client certificate to the trusted list."""
        msg: str = f"Adding {name}'s certificate to the trusted list"
        config: Dict[str, Union[str, bytes, List[str], bool]] = {
            "name": name,
            "password": "",
            "cert_data": cert.encode(),
        }

        if projects:
            msg += f" for projects: {projects}"
            # Turn "foo, bar" str into ["foo", "bar"] list
            config["projects"] = projects.replace(" ", "").split(",")
            config["restricted"] = True

        if metrics:
            msg += " (metrics)"
            config["cert_type"] = "metrics"

        logger.info(msg)
        client = pylxd.Client()
        try:
            client.certificates.create(**config)
        except pylxd.exceptions.Conflict:
            logger.debug(f"Certificate for {name} already trusted")
        except pylxd.exceptions.LXDAPIException as e:
            logger.error(f"Failed to add certificated: {e}")
            return False

        return True

    def lxd_trust_fingerprint(
        self,
        name: str,
    ) -> str:
        """Return the fingerprint of the client certificate with the provided name, if trusted.

        Return an empty str otherwise.
        """
        client = pylxd.Client()
        for c in client.certificates.all():
            if c.name == name:
                fingerprint: str = c.fingerprint
                logger.debug(f"The certificate named {name} has the fingerprint: {fingerprint}")
                return fingerprint
        return ""

    def lxd_trust_remove(self, fingerprint: str) -> bool:
        """Remove a client certificate from the trusted list using its fingerprint."""
        client = pylxd.Client()
        try:
            c = client.certificates.get(fingerprint)
            logger.info(f"Removing {c.name}'s certificate ({fingerprint}) from the trusted list")
            c.delete()
        except pylxd.exceptions.NotFound:
            logger.error(f"No certificate with fingerprint {fingerprint} found")
            return False
        return True

    def lxd_trust_token(self, name: str, projects: str = "") -> str:
        """Get a client certificate add token."""
        msg: str = f"Requesting a client certificate add token for {name}"
        config: Dict[str, Union[str, List[str], bool]] = {
            "name": name,
        }

        if projects:
            msg += f" for projects: {projects}"
            # Turn "foo, bar" str into ["foo", "bar"] list
            config["projects"] = projects.replace(" ", "").split(",")
            config["restricted"] = True

        logger.info(msg)
        client = pylxd.Client()
        try:
            token: str = client.certificates.create_token(**config)
        except pylxd.exceptions.LXDAPIException as e:
            logger.error(f"Failed to get a client certificated add token: {e}")
            return ""

        return token

    def resource_sideload(self) -> None:
        """Sideload resources."""
        # Multi-arch support
        arch: str = os.uname().machine
        possible_archs: List[str] = [arch]
        if arch == "x86_64":
            possible_archs = ["x86_64", "amd64"]

        # LXD snap
        lxd_snap_resource: str = ""
        fname_suffix: str = ".snap"
        try:
            # Note: self._stored can only store simple data types (int/float/dict/list/etc)
            lxd_snap_resource = str(self.model.resources.fetch("lxd-snap"))
        except ModelError:
            pass

        tmp_dir: str = ""
        if lxd_snap_resource and tarfile.is_tarfile(lxd_snap_resource):
            logger.debug(f"{lxd_snap_resource} is a tarball; unpacking")
            tmp_dir = tempfile.mkdtemp()
            tarball = tarfile.open(lxd_snap_resource)
            valid_names = {f"lxd_{x}{fname_suffix}" for x in possible_archs}
            for f in valid_names.intersection(tarball.getnames()):
                tarball.extract(f, path=tmp_dir)
                logger.debug(f"{f} was extracted from the tarball")
                self._stored.lxd_snap_path = f"{tmp_dir}/{f}"
                break
            else:
                logger.debug("Missing arch specific snap from tarball.")
            tarball.close()
        else:
            self._stored.lxd_snap_path = lxd_snap_resource

        if self._stored.lxd_snap_path:
            self.snap_sideload_lxd()
            if tmp_dir:
                os.remove(self._stored.lxd_snap_path)
                os.rmdir(tmp_dir)

        # LXD binary
        lxd_binary_resource: str = ""
        fname_suffix = ""
        try:
            # Note: self._stored can only store simple data types (int/float/dict/list/etc)
            lxd_binary_resource = str(self.model.resources.fetch("lxd-binary"))
        except ModelError:
            pass

        tmp_dir = ""
        if lxd_binary_resource and tarfile.is_tarfile(lxd_binary_resource):
            logger.debug(f"{lxd_binary_resource} is a tarball; unpacking")
            tmp_dir = tempfile.mkdtemp()
            tarball = tarfile.open(lxd_binary_resource)
            valid_names = {f"lxd_{x}{fname_suffix}" for x in possible_archs}
            for f in valid_names.intersection(tarball.getnames()):
                tarball.extract(f, path=tmp_dir)
                logger.debug(f"{f} was extracted from the tarball")
                self._stored.lxd_binary_path = f"{tmp_dir}/{f}"
                break
            else:
                logger.debug("Missing arch specific binary from tarball.")
            tarball.close()
        else:
            self._stored.lxd_binary_path = lxd_binary_resource

        if self._stored.lxd_binary_path:
            self.snap_sideload_lxd_binary()
            if tmp_dir:
                os.remove(self._stored.lxd_binary_path)
                os.rmdir(tmp_dir)

    def snap_config_set(self) -> None:
        """Apply snap set to LXD."""
        logger.debug("Applying snap set lxd")

        # Get all the `snap-config-*` configs to set
        snap_set = {k: v for k, v in self.config_changed().items() if k.startswith("snap-config-")}

        if not snap_set:
            return

        # Apply the changes
        snap_set_list: List[str] = []
        reboot_needed: bool = False
        for k, v in snap_set.items():
            # Convert Juju config to "snap set" syntax
            if v is None:
                snap_value = ""
            elif isinstance(v, bool):
                snap_value = str(v).lower()
            else:
                snap_value = v
            snap_key = k.replace("snap-config-", "", 1).replace("-", ".")

            # Set the snap config
            snap_set_list.append(f"{snap_key}={snap_value}")

            # Keys that require a reboot
            if k.startswith("snap-config-lxcfs-"):
                # `snap-config-lxcfs-*` cannot be applied live
                reboot_needed = True
                continue

        self.unit_maintenance("Setting snap configuration(s): " + ", ".join(snap_set_list))

        try:
            subprocess.run(
                ["snap", "set", "lxd"] + snap_set_list,
                capture_output=True,
                check=True,
                timeout=600,
            )
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
            raise RuntimeError
        except subprocess.TimeoutExpired as e:
            self.unit_blocked(f"Timeout exceeded while running {e.cmd!r}")
            raise RuntimeError

        # If "snap set lxd" was successful: save all the k/v applied
        for k, v in snap_set.items():
            self._stored.config[k] = v

        if not self.lxd_is_active():
            logger.debug("Skipping LXD reload (service inactive)")
            return

        self.lxd_reload()
        if reboot_needed:
            self.system_set_reboot_required()

    def snap_install_lxd(self) -> None:
        """Install LXD from snap.

        If snap-channel is set to auto, try to use the lxd-installer if available and
        fallback to the default channel.

        If a specific snap-channel is requested, use it.
        """
        snap_channel: str = self.config["snap-channel"]

        # When snap-channel is set to auto, try to use the lxd-installer
        # if available and fallback to the default track.

        # The `lxd-installer` provides 2 shell wrappers: `/usr/sbin/lxd` and
        # `/usr/sbin/lxc` which are nutshells to trigger a `snap install lxd
        # --channel <proper-channel>`.
        #
        # If `which lxd` doesn't find the real snap provided `lxd``, but still
        # finds something, assume it found the `lxd-installer` wrapper that can
        # then be used.
        #
        # If `lxd-installer` is not available, a simple `snap install lxd` is
        # used. This will then pull LXD from the default track which is soon to
        # be `5.21/stable` (as of 2024-03-23).

        channel: List[str] = []
        if snap_channel == "auto":
            lxd_path: str = shutil.which("lxd") or ""
            if not lxd_path or lxd_path == "/snap/bin/lxd":
                logger.debug(
                    "snap-channel auto requested but lxd-installer not found, falling"
                    " back to default channel"
                )
        else:
            channel = [f"--channel={snap_channel}"]

        # During the install phase, there won't be anything in self._stored.config
        # so fallback to the live configuration
        mode: str = self._stored.config.get("mode", "")
        if not mode:
            mode = self.config["mode"]

        # Cluster members all need to get the same snap version so set a cohort
        cohort: List[str] = []
        if mode == "cluster":
            logger.debug("Using snap cohort due to mode=cluster")
            cohort = ["--cohort=+"]

        try:
            if channel:
                self.unit_maintenance(f"Installing LXD snap (channel={snap_channel})")
                subprocess.run(
                    ["snap", "install", "lxd"] + channel + cohort,
                    capture_output=True,
                    check=True,
                    timeout=600,
                )
                subprocess.run(
                    ["snap", "refresh", "lxd"] + channel + cohort,
                    capture_output=True,
                    check=True,
                    timeout=600,
                )
            else:
                self.unit_maintenance("Installing LXD snap (using lxd-installer)")
                subprocess.run(
                    ["lxd", "version"],
                    capture_output=True,
                    check=True,
                    timeout=600,
                )
                if cohort:
                    subprocess.run(
                        ["snap", "switch", "lxd"] + cohort,
                        capture_output=True,
                        check=True,
                        timeout=600,
                    )
            if os.path.exists("/var/lib/lxd"):
                subprocess.run(
                    ["lxd.migrate", "-yes"],
                    capture_output=True,
                    check=True,
                    timeout=600,
                )
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
            raise RuntimeError
        except subprocess.TimeoutExpired as e:
            self.unit_blocked(f"Timeout exceeded while running {e.cmd!r}")
            raise RuntimeError

        # Done with the snap installation
        self._stored.config["snap-channel"] = snap_channel

    def snap_sideload_lxd(self) -> None:
        """Sideload LXD snap resource."""
        logger.debug("Applying LXD snap sideload changes")

        cmd: List[str] = []
        alias: List[str] = []
        enable: List[str] = []

        # A 0 byte file will unload the resource
        if os.path.getsize(self._stored.lxd_snap_path) == 0:
            logger.debug("Reverting to LXD snap from snapstore")
            snap_channel: str = self._stored.config["snap-channel"]
            channel: List[str] = []
            if snap_channel != "auto":
                channel = [f"--channel={snap_channel}"]
            cmd = ["snap", "refresh", "lxd", "--amend"] + channel
        else:
            logger.debug("Sideloading LXD snap")
            cmd = ["snap", "install", "--dangerous", self._stored.lxd_snap_path]
            # Since the sideloaded snap doesn't have an assertion, some things need
            # to be done manually
            alias = ["snap", "alias", "lxd.lxc", "lxc"]
            enable = ["systemctl", "enable", "--now", "snap.lxd.daemon.unix.socket"]

        try:
            subprocess.run(cmd, capture_output=True, check=True, timeout=600)
            if alias:
                subprocess.run(alias, capture_output=True, check=True, timeout=600)
            if enable:
                subprocess.run(enable, capture_output=True, check=True, timeout=600)
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run {e.cmd!r}: {e.stderr} ({e.returncode})")
            raise RuntimeError
        except subprocess.TimeoutExpired as e:
            self.unit_blocked(f"Timeout exceeded while running {e.cmd!r}")
            raise RuntimeError

    def snap_sideload_lxd_binary(self) -> None:
        """Sideload LXD binary resource."""
        logger.debug("Applying LXD binary sideload changes")
        lxd_debug: str = "/var/snap/lxd/common/lxd.debug"

        # A 0 byte file will unload the resource
        if os.path.getsize(self._stored.lxd_binary_path) == 0:
            logger.debug("Unloading sideloaded LXD binary")
            if os.path.exists(lxd_debug):
                os.remove(lxd_debug)
        else:
            logger.debug("Sideloading LXD binary")
            # Avoid "Text file busy" error
            if os.path.exists(lxd_debug):
                logger.debug("Removing old sideloaded LXD binary")
                os.remove(lxd_debug)
            shutil.copyfile(self._stored.lxd_binary_path, lxd_debug)
            os.chmod(lxd_debug, 0o755)

        self.lxd_reload()

    def system_clear_reboot_required(self) -> None:
        """Clear the reboot_required flag if a reboot occurred."""
        # If the required reboot occurred so let's clear the flag
        if self._stored.reboot_required == "true" and not os.path.exists(REBOOT_REQUIRED_FILE):
            self._stored.reboot_required = "false"
            logger.debug("Required reboot done")

    def system_set_reboot_required(self) -> None:
        """Indicate that a reboot is required to reach a clean state."""
        # Touch a flag file indicating that a reboot is required.
        try:
            open(REBOOT_REQUIRED_FILE, "a").close()
            self._stored.reboot_required = "true"
        except OSError:
            logger.warning(f"Failed to create: {REBOOT_REQUIRED_FILE}")

    def unit_active(self, msg: str = "") -> None:
        """Set the unit's status to active and log the provided message, if any."""
        self.unit.status = ActiveStatus()
        if msg:
            logger.debug(msg)

    def unit_blocked(self, msg: str) -> None:
        """Set the unit's status to blocked and log the provided message."""
        self.unit.status = BlockedStatus(msg)
        logger.error(msg)

    def unit_maintenance(self, msg: str) -> None:
        """Set the unit's status to maintenance and log the provided message."""
        self.unit.status = MaintenanceStatus(msg)
        logger.info(msg)


if __name__ == "__main__":
    main(LxdCharm)
