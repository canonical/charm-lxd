"""Unit tests for adoption safety gates and post-adoption management."""

from unittest.mock import MagicMock, PropertyMock, patch

from ops.testing import Harness

from charm import LxdCharm


def _make_loki_client():
    client = MagicMock()
    client.has_api_extension.return_value = True
    client.api.get.return_value.json.return_value = {"metadata": {"config": {}}}
    return client


class TestAdoptionManagement:
    """Exercise pre-adoption guards and post-adoption resumed management."""

    def setup_method(self):
        """Start a harness with adoption requested in config."""
        self.harness = Harness(LxdCharm)
        self.harness.update_config({"adopt-existing": True})
        self.harness.begin()

    def teardown_method(self):
        """Clean up the test harness."""
        self.harness.cleanup()

    def test_config_changed_skips_mutations_while_adoption_is_pending(self):
        """Existing-host adoption should suppress config writes before success."""
        charm = self.harness.charm
        event = MagicMock()
        charm.unit_blocked("existing host requires inspection")

        with patch.object(charm, "juju_set_proxy") as juju_set_proxy, patch.object(
            charm, "lxd_set_address"
        ) as lxd_set_address:
            charm._on_charm_config_changed(event)

        juju_set_proxy.assert_not_called()
        lxd_set_address.assert_not_called()
        assert charm.unit.status.name == "blocked"
        assert charm.unit.status.message == "existing host requires inspection"

    def test_config_changed_resumes_normal_management_after_adoption(self):
        """Once adoption succeeded, normal config management should resume."""
        charm = self.harness.charm
        event = MagicMock()
        charm._stored.lxd_initialized = True

        with patch.object(charm, "juju_set_proxy") as juju_set_proxy, patch.object(
            charm, "config_changed", return_value={}
        ), patch.object(charm, "config_is_valid", return_value=True), patch.object(
            charm, "_update_metrics_target"
        ), patch.object(
            charm, "lxd_update_prometheus_manual_scrape_job"
        ):
            charm._on_charm_config_changed(event)

        juju_set_proxy.assert_called_once_with()

    def test_logging_relation_is_guarded_while_adoption_is_pending(self):
        """The logging relation should not touch LXD before adoption succeeds."""
        charm = self.harness.charm
        event = MagicMock()

        with patch("charm.pylxd.Client") as client_cls:
            charm._on_loki_push_api_endpoint_joined(event)

        client_cls.assert_not_called()

    def test_metrics_relation_is_guarded_while_adoption_is_pending(self):
        """The metrics relation should not add trust before adoption succeeds."""
        charm = self.harness.charm
        event = MagicMock()
        event.app = MagicMock()
        event.app.name = "prometheus"

        with patch.object(charm, "lxd_trust_add") as lxd_trust_add, patch.object(
            charm, "_update_metrics_endpoint_app_data"
        ) as update_app_data:
            charm._on_metrics_endpoint_relation_changed(event)

        lxd_trust_add.assert_not_called()
        update_app_data.assert_not_called()

    def test_https_relation_is_guarded_while_adoption_is_pending(self):
        """The https relation should not trust remote certificates before adoption."""
        charm = self.harness.charm
        event = MagicMock()

        with patch.object(charm, "lxd_trust_add") as lxd_trust_add:
            charm._on_https_relation_changed(event)

        lxd_trust_add.assert_not_called()

    def test_logging_relation_resumes_after_adoption(self):
        """Relation-driven management should resume once adoption succeeded."""
        charm = self.harness.charm
        charm._stored.lxd_initialized = True
        event = MagicMock()

        loki_endpoints = [{"url": "http://loki.example:3100/loki/api/v1/push"}]
        client = _make_loki_client()

        with patch.object(
            type(charm._loki_consumer), "loki_endpoints", new_callable=PropertyMock
        ) as loki_endpoints_prop, patch(
            "charm.pylxd.Client", return_value=client
        ):
            loki_endpoints_prop.return_value = loki_endpoints
            charm._on_loki_push_api_endpoint_joined(event)

        client.api.put.assert_called_once_with(
            json={"config": {"loki.api.url": "http://loki.example:3100"}}
        )
