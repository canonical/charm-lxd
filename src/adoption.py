"""Adoption helpers for existing LXD hosts."""

import logging
import subprocess
from typing import TYPE_CHECKING, Dict

import pylxd

if TYPE_CHECKING:
    from charm import LxdCharm


logger = logging.getLogger(__name__)


class AdoptionError(RuntimeError):
    """Raised when an existing LXD host cannot be adopted safely."""


class AdoptionManager:
    """Encapsulate adoption-related detection, inventory, and state seeding."""

    def __init__(self, charm: "LxdCharm"):
        """Store a reference to the owning charm."""
        self._charm = charm

    def adoption_requested(self) -> bool:
        """Whether the operator requested adoption behavior."""
        return bool(self._charm.config.get("adopt-existing", False))

    def existing_lxd_present(self) -> bool:
        """Whether LXD is already installed on the host."""
        try:
            result = subprocess.run(
                ["snap", "list", "lxd"],
                capture_output=True,
                check=False,
                timeout=600,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

        return result.returncode == 0

    def existing_lxd_initialized(self) -> bool:
        """Whether the existing LXD looks initialized enough to adopt safely."""
        inventory = self.inventory_existing_lxd()
        if inventory["server_clustered"]:
            return True
        if inventory["storage_pools"]:
            return True

        return False

    def should_adopt_existing(self) -> bool:
        """Whether install should take the adoption path."""
        return self.adoption_requested() and self.existing_lxd_present()

    def pending_adoption_restrictions_active(self) -> bool:
        """Whether the charm should still suppress normal management writes.

        The safety gate is only active while adoption has been requested for an
        already-present LXD installation and the charm has not yet marked that
        host as initialized/adopted in stored state.
        """
        return self.should_adopt_existing() and not self._charm._stored.lxd_initialized

    def adopt_existing_lxd(self) -> None:
        """Adopt an existing standalone LXD installation without bootstrapping it."""
        if not self.existing_lxd_present():
            raise AdoptionError("LXD is not installed")

        if not self._charm.lxd_is_active():
            msg = "LXD is installed but the daemon is inactive; refusing adoption"
            self._charm.unit_blocked(msg)
            raise AdoptionError(msg)

        inventory = self.inventory_existing_lxd()

        if inventory["server_clustered"]:
            msg = "Clustered LXD adoption is not supported yet"
            self._charm.unit_blocked(msg)
            raise AdoptionError(msg)

        if not self.existing_lxd_initialized():
            msg = (
                "LXD is installed but does not appear initialized "
                "(no storage pools detected); refusing adoption"
            )
            self._charm.unit_blocked(msg)
            raise AdoptionError(msg)

        self.seed_adopted_stored_state(inventory)

    def seed_adopted_stored_state(self, inventory: Dict) -> None:
        """Seed charm stored state for an adopted host."""
        self._charm._stored.inside_container = self._detect_inside_container()
        self._charm._stored.lxd_initialized = True
        self._charm._stored.lxd_clustered = bool(inventory["server_clustered"])
        self._charm._stored.addresses = {}

        for key, value in self._charm.config.items():
            self._charm._stored.config[key] = value

    def inventory_existing_lxd(self) -> Dict:
        """Collect readonly inventory from an existing LXD installation."""
        try:
            client = pylxd.Client()
            host_info = client.host_info
            environment = host_info.get("environment", {})
            profile = client.profiles.get("default")
            storage_pools = sorted(pool.name for pool in client.storage_pools.all())
            networks = sorted(network.name for network in client.networks.all())
            devices = sorted(profile.devices.keys())
        except Exception as exc:
            msg = f"Unable to inspect existing LXD host: {exc}"
            self._charm.unit_blocked(msg)
            raise AdoptionError(msg) from exc

        return {
            "server_version": environment.get("server_version", ""),
            "server_clustered": bool(environment.get("server_clustered", False)),
            "addresses": environment.get("addresses", []),
            "storage_pools": storage_pools,
            "networks": networks,
            "default_profile_devices": devices,
        }

    def relation_mutations_allowed(self) -> bool:
        """Whether relation handlers may mutate adopted LXD state."""
        return not self.pending_adoption_restrictions_active()

    def config_mutations_allowed(self) -> bool:
        """Whether config-changed may mutate adopted LXD state."""
        return not self.pending_adoption_restrictions_active()

    def listener_mutations_allowed(self) -> bool:
        """Whether listener changes may mutate adopted LXD state."""
        return not self.pending_adoption_restrictions_active()

    def log_mutation_skip(self, scope: str) -> None:
        """Log why a normal management path is being skipped."""
        logger.info(
            "Skipping %s mutations while adopt-existing=true and an existing LXD "
            "installation is pending adoption",
            scope,
        )

    def _detect_inside_container(self) -> bool:
        """Whether the current host is itself running in a container."""
        result = subprocess.run(
            ["systemd-detect-virt", "--quiet", "--container"],
            check=False,
            timeout=600,
        )
        return result.returncode == 0
