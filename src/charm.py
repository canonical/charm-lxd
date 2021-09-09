#!/usr/bin/env python3

"""LXD charm."""

from ops.charm import (
    CharmBase,
    ConfigChangedEvent,
    InstallEvent,
    StartEvent,
)
from ops.framework import StoredState
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
)

import logging
import os
import subprocess

logger = logging.getLogger(__name__)

REBOOT_REQUIRED_FILE = '/run/lxd-reboot-required'


class LxdCharm(CharmBase):
    """LXD charm class."""

    _stored = StoredState()

    def __init__(self, *args):
        """Initialize charm's variables."""
        super().__init__(*args)

        # Initialize the persistent storage if needed
        self._stored.set_default(
            addresses={},
            config={},
            lxd_initialized=False,
            lxd_installed=False,
            reboot_required=False,
        )

        # Main event handlers
        self.framework.observe(self.on.install, self._on_charm_install)
        self.framework.observe(self.on.config_changed, self._on_charm_config_changed)
        self.framework.observe(self.on.start, self._on_charm_start)
        self.framework.observe(self.on.upgrade_charm, self._on_charm_upgrade)

    def _on_charm_install(self, event: InstallEvent) -> None:
        logger.info("Installing the LXD charm")
        # Confirm that the config is valid
        if not self.config_is_valid():
            return

        # Install LXD itself
        try:
            self.snap_install_lxd()
            self._stored.lxd_installed = True
            logger.info("LXD installed successfully")
        except RuntimeError:
            logger.error("Failed to install LXD")
            event.defer()
            return

        # Apply various configs
        self.snap_config_set()

        # Initial configuration
        try:
            self.lxd_init()
            self._stored.lxd_initialized = True
            logger.info("LXD initialized successfully")
        except RuntimeError:
            logger.error("Failed to initialize LXD")
            event.defer()
            return

        # All done
        self.unit_active()

    def _on_charm_config_changed(self, event: ConfigChangedEvent) -> None:
        """React to configuration changes.

        Some configuration items can be set only once
        while others are changable, sometimes requiring
        a service reload or even a machine reboot.
        """
        logger.info("Updating charm config")

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
            elif [k for k in changed if k.startswith("snap-config-")]:
                self.snap_config_set()
        except RuntimeError:
            msg = "Failed to apply some configuration change(s): %s" % ", ".join(changed)
            self.unit_blocked(msg)
            event.defer()
            return

        # If some changes needed a reboot to take effect, enter blocked status
        if self._stored.reboot_required:
            self.unit_blocked("Machine reboot required")
            return

        # All done
        self.unit_active("Configuration change(s) applied successfully")

    def _on_charm_start(self, event: StartEvent) -> None:
        logger.info("Starting the LXD charm")

        if not self._stored.lxd_initialized:
            logger.debug("LXD is not initialized yet, not starting the charm")
            return

        # Check if any required reboot was done
        self.system_clear_reboot_required()

        if not self._stored.reboot_required and isinstance(self.unit.status, BlockedStatus):
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
            if k.startswith("lxd-"):
                logger.warning(f"The new \"{k}\" key won't be applied to existing units "
                               "as their LXD is already initialized")
                self._stored.config[k] = v

    def config_changed(self) -> dict:
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
        if "local" in self.model.storages and len(self.model.storages['local']) > 1:
            self.unit_blocked("LXD charm only supports a single storage volume")
            return False

        config_changed = self.config_changed()

        # If nothing changed and we were blocked due to a lxd- key
        # change (post-init), we can assume the change was reverted thus unblocking us
        if not config_changed and isinstance(self.unit.status, BlockedStatus) and \
                "Can't modify lxd- keys after initialization:" in str(self.unit.status):
            self.unit_active("Unblocking as the lxd- keys were reset to their initial values")

        for k in config_changed:
            if k.startswith("lxd-") and self._stored.lxd_initialized:
                self.unit_blocked(f"Can't modify lxd- keys after initialization: {k}")
                return False

        return True

    def juju_set_proxy(self) -> None:
        """Apply proxy config."""
        juju_proxy = "/etc/juju-proxy.conf"
        if not os.path.exists(juju_proxy):
            logger.debug("No proxy config from Juju.")
            return

        http_proxy = None
        https_proxy = None
        no_proxy = None

        with open(juju_proxy, encoding="UTF-8") as f:
            for line in f.read().splitlines():
                # Only consider lines exporting variables
                if not line.startswith("export "):
                    continue

                # Parse export lines
                try:
                    # Strip "export " prefix and split variable/value
                    k, v = line.replace("export ", "", 1).split("=", 1)
                except (IndexError, ValueError):
                    continue

                if k == "HTTP_PROXY":
                    http_proxy = v
                elif k == "HTTPS_PROXY":
                    https_proxy = v
                elif k == "NO_PROXY":
                    no_proxy = v

        try:
            if http_proxy:
                logger.debug(f"Configuring core.proxy_http={http_proxy}")
                subprocess.run(["lxc", "config", "set", "core.proxy_http",
                               http_proxy], check=True)

            if https_proxy:
                logger.debug(f"Configuring core.proxy_https={https_proxy}")
                subprocess.run(["lxc", "config", "set", "core.proxy_https",
                               https_proxy], check=True)
            if no_proxy:
                logger.debug(f"Configuring core.proxy_ignore_hosts={no_proxy}")
                subprocess.run(["lxc", "config", "set", "core.proxy_ignore_hosts",
                               no_proxy], check=True)

        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run \"{e.cmd}\": {e.returncode}")
            raise RuntimeError

    def lxd_init(self) -> None:
        """Apply initial configuration of LXD."""
        self.unit_maintenance("Initializing LXD in standalone mode")

        preseed = self.config.get("lxd-preseed")

        if preseed:
            self.unit_maintenance("Applying LXD preseed")

            try:
                # NOTE: When preseeding, no further configuration is applied.
                subprocess.run(["lxd", "init", "--preseed"], check=True, input=preseed.encode())
            except subprocess.CalledProcessError as e:
                self.unit_blocked(f"Failed to run \"{e.cmd}\": {e.returncode}")
                raise RuntimeError
        else:
            self.unit_maintenance("Performing initial configuration")

            try:
                # Configure the storage
                if "local" in self.model.storages and len(self.model.storages['local']) == 1:
                    src = f"source={self.model.storages['local'][0].location}"
                    self.unit_maintenance(f"Configuring external storage pool (zfs, {src})")
                    subprocess.run(["lxc", "storage", "create", "local", "zfs", src],
                                   check=True)
                else:
                    self.unit_maintenance("Configuring local storage pool (dir)")
                    subprocess.run(["lxc", "storage", "create", "local", "dir"], check=True)
                subprocess.run(["lxc", "profile", "device", "add",
                                "default", "root", "disk", "pool=local", "path=/"], check=True)

                # Configure the network
                self.unit_maintenance("Configuring network bridge (lxdbr0)")

                subprocess.run(["lxc", "network", "create", "lxdbr0"], check=True)

                subprocess.run(["lxc", "profile", "device", "add", "default", "eth0", "nic",
                                "network=lxdbr0", "name=eth0"], check=True)

            except subprocess.CalledProcessError as e:
                self.unit_blocked(f"Failed to run \"{e.cmd}\": {e.returncode}")
                raise RuntimeError

        # Initial configuration of core.proxy_* keys
        self.juju_set_proxy()

        # Done with the initialization
        self._stored.config['lxd-preseed'] = preseed

        # Flag any `lxd-*` keys not handled, there should be none
        for k in self.config_changed():
            if k.startswith("lxd-"):
                logger.error(f"lxd_init did not handle the key config named: {k}")

    def lxd_is_active(self) -> bool:
        """Indicate if the lxd daemon is active."""
        c = subprocess.run(["systemctl", "is-active", "--quiet", "snap.lxd.daemon.service"],
                           check=False)
        return c.returncode == 0

    def lxd_reload(self) -> None:
        """Reload the lxd daemon."""
        self.unit_maintenance("Reloading LXD")
        try:
            # Avoid occasional race during startup where a reload could cause a failure
            subprocess.run(["lxd", "waitready", "--timeout=30"], check=False)
            # Start a monitor process and wait for it to exit due to the service
            # reloading and the old lxd process closing the monitor's socket.
            mon = subprocess.Popen(["lxc", "monitor", "--type=nonexistent"],
                                   stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "reload", "snap.lxd.daemon.service"], check=True)
            mon.wait(timeout=600)

        except subprocess.TimeoutExpired:
            if not mon.returncode:
                mon.kill()
            self.unit_maintenance("Timeout while reloading the LXD service")
            raise RuntimeError

        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run \"{e.cmd}\": {e.returncode}")
            raise RuntimeError

    def snap_config_set(self) -> None:
        """Apply snap set to LXD."""
        logger.debug("Applying snap set lxd")

        # Get all the `snap-config-*` configs to set
        snap_set = {k: v for k, v in self.config_changed().items() if k.startswith("snap-config-")}

        if not snap_set:
            return

        # Apply the changes
        snap_set_list = []
        reboot_needed = False
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
            snap_set_list.append("%s=%s" % (snap_key, snap_value))

            # Keys that require a reboot
            if k.startswith("snap-config-lxcfs-"):
                # `snap-config-lxcfs-*` cannot be applied live
                reboot_needed = True
                continue

        self.unit_maintenance("Setting snap configuration(s): " + ", ".join(snap_set_list))

        try:
            subprocess.run(["snap", "set", "lxd"] + snap_set_list, check=True)
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run \"{e.cmd}\": {e.returncode}")
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
        """Install LXD from snap."""
        channel = self.config['snap-channel']
        if channel:
            channel_name = channel
        else:
            channel_name = "latest/stable"
        self.unit_maintenance(f"Installing LXD snap (channel={channel_name})")

        try:
            subprocess.run(["snap", "install", "lxd", f"--channel={channel}"], check=True)
            subprocess.run(["snap", "refresh", "lxd", f"--channel={channel}"], check=True)
            if os.path.exists("/var/lib/lxd"):
                subprocess.run(["lxd.migrate", "-yes"], check=True)
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f"Failed to run \"{e.cmd}\": {e.returncode}")
            raise RuntimeError

        # Done with the snap installation
        self._stored.config['snap-channel'] = channel

    def system_clear_reboot_required(self) -> None:
        """Clear the reboot_required flag if a reboot occurred."""
        # If the required reboot occurred so let's clear the flag
        if self._stored.reboot_required and not os.path.exists(REBOOT_REQUIRED_FILE):
            self._stored.reboot_required = False
            logger.debug("Required reboot done")

    def system_set_reboot_required(self) -> None:
        """Indicate that a reboot is required to reach a clean state."""
        # Touch a flag file indicating that a reboot is required.
        try:
            open(REBOOT_REQUIRED_FILE, 'a').close()
            self._stored.reboot_required = True
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
