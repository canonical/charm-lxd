"""Unit tests for the initial adoption install flow."""

import unittest
from unittest.mock import MagicMock, patch

from ops.testing import Harness

from adoption import AdoptionError
from charm import LxdCharm


class TestInstallAdoption(unittest.TestCase):
    """Exercise bootstrap-vs-adoption install dispatch."""

    def setUp(self):
        """Start a harness with adoption requested in config."""
        self.harness = Harness(LxdCharm)
        self.harness.update_config({"adopt-existing": True})
        self.harness.begin()
        self.addCleanup(self.harness.cleanup)

    def test_install_bootstraps_when_existing_lxd_is_absent(self):
        """Blank hosts should keep the upstream bootstrap path."""
        charm = self.harness.charm
        event = MagicMock()

        with patch.object(
            charm._adoption, "should_adopt_existing", return_value=False
        ), patch.object(
            charm._adoption, "adopt_existing_lxd"
        ) as adopt_existing, patch.object(
            charm, "_install_bootstrap_lxd"
        ) as bootstrap_install:
            charm._on_charm_install(event)

        bootstrap_install.assert_called_once_with(event)
        adopt_existing.assert_not_called()

    def test_install_adopts_existing_lxd_when_present(self):
        """Installed standalone hosts should use the adoption path."""
        charm = self.harness.charm
        event = MagicMock()

        with patch.object(
            charm._adoption, "should_adopt_existing", return_value=True
        ), patch.object(
            charm._adoption, "adopt_existing_lxd"
        ) as adopt_existing, patch.object(
            charm, "_install_bootstrap_lxd"
        ) as bootstrap_install:
            charm._on_charm_install(event)

        adopt_existing.assert_called_once_with()
        bootstrap_install.assert_not_called()

    def test_seed_adopted_state_marks_lxd_initialized(self):
        """Adoption state seeding should mark the host initialized."""
        charm = self.harness.charm
        charm._stored.existing_lxd_unmanaged = True

        with patch.object(charm._adoption, "_detect_inside_container", return_value=False):
            charm._adoption.seed_adopted_stored_state(
                {"server_clustered": False, "storage_pools": ["default"]}
            )

        self.assertTrue(charm._stored.lxd_initialized)
        self.assertFalse(charm._stored.lxd_clustered)
        self.assertFalse(charm._stored.existing_lxd_unmanaged)
        self.assertEqual(charm._stored.config["adopt-existing"], True)

    def test_install_keeps_blocked_status_when_adoption_fails(self):
        """The install hook should not fall back to bootstrap after an adoption failure."""
        charm = self.harness.charm
        event = MagicMock()
        charm.unit_blocked("pre-existing failure")

        with patch.object(
            charm._adoption, "should_adopt_existing", return_value=True
        ), patch.object(
            charm._adoption,
            "adopt_existing_lxd",
            side_effect=AdoptionError("pre-existing failure"),
        ), patch.object(
            charm, "_install_bootstrap_lxd"
        ) as bootstrap_install:
            charm._on_charm_install(event)

        bootstrap_install.assert_not_called()
        self.assertTrue(charm._stored.existing_lxd_unmanaged)
        self.assertEqual(charm.unit.status.name, "blocked")
        self.assertEqual(charm.unit.status.message, "pre-existing failure")

    def test_config_changed_skips_mutations_for_existing_lxd_adoption_mode(self):
        """Adoption mode should not mutate an already-installed host on config-changed."""
        charm = self.harness.charm
        event = MagicMock()
        charm.unit_blocked("existing host requires inspection")

        with patch.object(
            charm._adoption, "config_mutations_allowed", return_value=False
        ), patch.object(charm, "juju_set_proxy") as juju_set_proxy, patch.object(
            charm, "lxd_set_address"
        ) as lxd_set_address:
            charm._on_charm_config_changed(event)

        juju_set_proxy.assert_not_called()
        lxd_set_address.assert_not_called()
        self.assertEqual(charm.unit.status.name, "blocked")
        self.assertEqual(charm.unit.status.message, "existing host requires inspection")
