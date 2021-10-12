#!/usr/bin/env python3

"""https-client charm."""

import logging
import subprocess

import pylxd
from ops.charm import (
    CharmBase,
    ConfigChangedEvent,
    InstallEvent,
    RelationChangedEvent,
    RelationCreatedEvent,
    StartEvent,
)
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

logger = logging.getLogger(__name__)

# Reduce verbosity of API calls made by pylxd
logging.getLogger("urllib3").setLevel(logging.WARNING)


class HttpsClientCharm(CharmBase):
    """https-client charm class."""

    _stored = StoredState()

    def __init__(self, *args):
        """Initialize charm's variables."""
        super().__init__(*args)

        # Initialize the persistent storage if needed
        self._stored.set_default(
            cert=None,
        )

        # Main event handlers
        self.framework.observe(self.on.config_changed, self._on_charm_config_changed)
        self.framework.observe(self.on.install, self._on_charm_install)
        self.framework.observe(self.on.start, self._on_charm_start)

        # Relation event handlers
        self.framework.observe(self.on.https_relation_changed, self._on_https_relation_changed)
        self.framework.observe(self.on.https_relation_created, self._on_https_relation_created)

    def config_to_databag(self) -> dict:
        """Translate config data to be storable in a data bag."""
        # Prepare data to be sent (only strings, no bool nor None)
        d = {
            "version": "1.0",
            "certificate": self._stored.cert,
        }

        autoremove = self.config.get("autoremove")
        if autoremove:
            d["autoremove"] = str(autoremove)

        projects = self.config.get("projects")
        if projects:
            d["projects"] = projects

        return d

    def _on_charm_config_changed(self, event: ConfigChangedEvent) -> None:
        """React to configuration changes.

        If the "https" relation was already established, retrigger
        the _on_https_relation_changed hook to update the remote unit
        based on our updated configuration.
        """
        logger.info("Updating charm config")
        https_relation = self.model.get_relation("https")
        if https_relation:
            # updating the unit's data bag to trigger a relation-changed on
            # the remote units
            logger.debug(f"Updating {self.unit} data bag")
            https_relation.data[self.unit].clear()
            https_relation.data[self.unit].update(self.config_to_databag())

    def _on_charm_install(self, event: InstallEvent) -> None:
        """Generate a self-signed cert."""
        if not self._stored.cert:
            self.unit_maintenance("Generating a self-signed cert")
            cmd = [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                "client.key",
                "-out",
                "client.crt",
                "-nodes",
                "-subj",
                f"/CN={self.unit.name.replace('/', '-')}",
            ]
            try:
                subprocess.run(cmd, capture_output=True, check=True)
            except subprocess.CalledProcessError as e:
                self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
                return

            # Save the self-signed certificate for later use
            with open("client.crt") as f:
                self._stored.cert = f.read()

    def _on_charm_start(self, event: StartEvent) -> None:
        """Start the unit if a cert was properly generated on install."""
        if self._stored.cert:
            self.unit_active("Starting the https-client charm")

    def _on_https_relation_changed(self, event: RelationChangedEvent) -> None:
        """Retrieve and display the connection information of the newly formed https relation."""
        d = event.relation.data[event.unit]
        version = d.get("version")

        if not version:
            logger.error(f"No version found in {event.unit.name}")
            return

        if version != "1.0":
            logger.error(f"Incompatible version ({version}) found in {event.unit.name}")
            return

        certificate = d.get("certificate")
        certificate_fingerprint = d.get("certificate_fingerprint")
        addresses = d.get("addresses", [])

        # Convert string to list
        if addresses:
            addresses = addresses.split(",")

        logger.info(
            f"Connection information for {event.unit.name}:\n"
            f"certificate={certificate}\n"
            f"certificate_fingerprint={certificate_fingerprint}\n"
            f"addresses={addresses}"
        )

        if not addresses:
            logger.info(
                f"Unable to test https connectivity to {event.unit.name}"
                " as no address was provided"
            )
            return

        if not certificate:
            logger.info(
                f"Unable to test https connectivity to {event.unit.name}"
                " as no certificate was provided"
            )
            return

        # pylxd needs a CA cert on disk for verification
        with open("server.crt", "w") as f:
            f.write(certificate)

        # Connect to the remote lxd unit
        client = pylxd.Client(
            endpoint=f"https://{addresses[0]}",
            cert=("client.crt", "client.key"),
            verify="server.crt",
        )

        # Report remote LXD version to show the connection worked
        server_version = client.host_info["environment"]["server_version"]
        logger.info(f"{event.unit.name} runs LXD version: {server_version}")

    def _on_https_relation_created(self, event: RelationCreatedEvent) -> None:
        """Upload our client certificate to the remote unit."""
        if not self._stored.cert:
            logger.error("no cert available")
            return

        d = self.config_to_databag()
        event.relation.data[self.unit].update(d)
        # XXX: the remote unit name is still unknown at this point (_relation_created is too early)
        logger.debug("Client certificate uploaded to remote unit")

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
    main(HttpsClientCharm)
