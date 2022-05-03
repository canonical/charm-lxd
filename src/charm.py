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
from ops.charm import (
    ActionEvent,
    CharmBase,
    ConfigChangedEvent,
    InstallEvent,
    RelationChangedEvent,
    RelationCreatedEvent,
    RelationDepartedEvent,
    StartEvent,
)
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, ModelError

logger = logging.getLogger(__name__)

# Reduce verbosity of API calls made by pylxd
logging.getLogger("urllib3").setLevel(logging.WARNING)

SYSCTL_CONFIGS = {
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

SYSTEMD_TMPFILES_CONFIGS = [
    "z /proc/sched_debug 0400 - - -",
    "z /sys/kernel/slab  0700 - - -",
]

REBOOT_REQUIRED_FILE = "/run/lxd-reboot-required"


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
            lxd_binary_path=None,
            lxd_clustered=False,
            lxd_initialized=False,
            lxd_snap_path=None,
            ovn_certificates_present=False,
            reboot_required=False,
        )

        # Action event handlers
        self.framework.observe(
            self.on.add_trusted_client_action, self._on_action_add_trusted_client
        )
        self.framework.observe(self.on.debug_action, self._on_action_debug)
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
            self.on.certificates_relation_changed, self._on_certificates_relation_changed
        )
        self.framework.observe(self.on.cluster_relation_changed, self._on_cluster_relation_changed)
        self.framework.observe(self.on.cluster_relation_created, self._on_cluster_relation_created)
        self.framework.observe(
            self.on.cluster_relation_departed, self._on_cluster_relation_departed
        )
        self.framework.observe(
            self.on.grafana_dashboard_relation_changed, self._on_grafana_dashboard_relation_changed
        )
        self.framework.observe(self.on.https_relation_changed, self._on_https_relation_changed)
        self.framework.observe(self.on.https_relation_departed, self._on_https_relation_departed)
        self.framework.observe(
            self.on.ovsdb_cms_relation_changed, self._on_ovsdb_cms_relation_changed
        )
        self.framework.observe(
            self.on.prometheus_manual_relation_changed, self._on_prometheus_manual_relation_changed
        )
        self.framework.observe(
            self.on.prometheus_manual_relation_departed,
            self._on_prometheus_manual_relation_departed,
        )

    def _on_action_add_trusted_client(self, event: ActionEvent) -> None:
        """Retrieve and add a client certificate to the trusted list."""
        name = event.params.get("name", "unknown")
        cert = event.params.get("cert")
        cert_url = event.params.get("cert-url")
        projects = event.params.get("projects")

        if not cert and not cert_url:
            msg = "One of cert or cert-url parameter needs to be provided."
            event.fail(msg)
            logger.error(msg)
            return

        if cert:
            # The received PEM needs to be mangled to be able to split()
            # on spaces without breaking the "-----BEGIN CERTIFICATE-----"
            # and "-----END CERTIFICATE-----" lines
            cert = (
                "\n".join(cert.replace(" CERTIFICATE", "CERTIFICATE", 2).split())
                .replace("CERTIFICATE", " CERTIFICATE", 2)
                .encode()
            )
            # Ignore the cert-url param if a cert was provided
            cert_url = None

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
                cert = response.read()

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
            b = subprocess.run(["lxd.buginfo"], capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            msg = f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})'
            event.fail(msg)
            logger.error(msg)
            raise RuntimeError

        event.set_results({"buginfo": b.stdout})
        logger.debug("lxd.buginfo called successfully")

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

        # Space binding changes will trigger this event but won't show up in self.config
        # so those need to be processed even when config_changed() returns nothing
        for listener in ("bgp", "dns", "https", "metrics"):
            # Check if we should listen
            toggle_key = f"lxd-listen-{listener}"
            toggle_value = self.config.get(toggle_key)
            if toggle_value:
                space_addr = self.juju_space_get_address(listener)

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

        # Keep the metrics_endpoint data up to date
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
            msg = "Failed to apply some configuration change(s): %s" % ", ".join(changed)
            self.unit_blocked(msg)
            event.defer()
            return

        # If some changes needed a reboot to take effect, enter blocked status
        if self._stored.reboot_required:
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
            # lxd-listen-* keys can be toggled at any time
            if k.startswith("lxd-listen-"):
                continue

            if k.startswith("lxd-"):
                logger.warning(
                    f'The new "{k}" key won\'t be applied to existing units '
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
        key = event.relation.data[event.unit].get("key")
        if not key:
            logger.error(f"Missing key in {event.unit.name}")
            return

        # Get the list of monitor hosts' IPs
        hosts = []
        for unit in event.relation.units:
            # Do as charm-ceph-osd which looks for "ceph-public-address"
            # and falls back to the "private-address"
            unit_data = event.relation.data[unit]
            host = unit_data.get("ceph-public-address") or unit_data.get("private-address")
            if host:
                logger.debug(f"Related {event.unit.name} has the IP: {host}")
                hosts.append(host)
            else:
                logger.debug(f"Related {event.unit.name} did not provide any IP")

        if not hosts:
            logger.error(f"No monitor IP found in {event.app.name} relation data")
            return

        # Create the config dir if needed
        ceph_dir = "/var/snap/lxd/common/ceph"
        if not os.path.exists(ceph_dir):
            os.mkdir(ceph_dir)

        # Creds issued by ceph-mon are for the name of the related app (i.e: lxd)
        ceph_user = self.app.name

        # Save the credentials in the appropriate keyring file
        keyring = f"{ceph_dir}/ceph.client.{ceph_user}.keyring"
        if os.path.exists(keyring):
            os.remove(keyring)
        old_umask = os.umask(0o077)
        with open(keyring, "w") as f:
            f.write(f"[client.{ceph_user}]\n\tkey = {key}\n")
        os.umask(old_umask)

        # Save a minimal ceph.conf
        ceph_conf = f"{ceph_dir}/ceph.conf"
        with open(ceph_conf, "w") as f:
            f.write(f"[global]\n\tmon host = {' '.join(hosts)}\n")

        logger.debug(f"The unit {self.unit.name} can now interact with Ceph")

    def _on_certificates_relation_changed(self, event: RelationChangedEvent) -> None:
        """Retrieve and save the PKI files required to connect to OVN using SSL."""
        if not event.unit:
            logger.debug("event.unit is not set")
            return

        d = event.relation.data[event.unit]
        ca = d.get("ca")
        cert = d.get("client.cert")
        key = d.get("client.key")

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
        ovn_dir = "/var/snap/lxd/common/ovn"
        if not os.path.exists(ovn_dir):
            os.mkdir(ovn_dir)

        # Reuse Openstack file names
        ca_crt = f"{ovn_dir}/ovn-central.crt"
        with open(ca_crt, "w") as f:
            f.write(ca)

        cert_host = f"{ovn_dir}/cert_host"
        with open(cert_host, "w") as f:
            f.write(cert)

        # Save the credentials in the appropriate keyring file
        key_host = f"{ovn_dir}/key_host"
        if os.path.exists(key_host):
            os.remove(key_host)
        old_umask = os.umask(0o077)
        with open(key_host, "w") as f:
            f.write(key)
        os.umask(old_umask)

        self._stored.ovn_certificates_present = True
        logger.debug(f"PKI files required to connect to OVN using SSL saved to {ovn_dir}")

        # If we were previously waiting on a certificates relation we should now unblock
        if isinstance(self.unit.status, BlockedStatus) and "'certificates' missing" in str(
            self.unit.status
        ):
            self.unit_active()

    def _on_cluster_relation_changed(self, event: RelationChangedEvent) -> None:
        """If not in cluster mode: do nothing.

        * If we are a leader: update the prometheus-manual data and issue a join token.
        * If we are a new unit: use the newly minted token to join the cluster.
        """
        # All units automatically get a cluster peer relation irrespective of the mode
        # so do nothing if not in cluster mode
        if self.config.get("mode") != "cluster":
            return

        if self.unit.is_leader():
            if not event.unit:
                logger.debug("No available data yet")
                return

            # The leader needs to look for join token to issue in the unit data bag
            d = event.relation.data[event.unit]
            version = d.get("version")

            if not version:
                logger.error(f"Missing version in {event.unit.name}")
                return

            if version != "1.0":
                logger.error(f"Incompatible version ({version}) found in {event.unit.name}")
                return

            hostname = d.get("hostname")
            if not hostname:
                # Clear the app data bag of any consumed token associated with the remote unit
                if event.relation.data[self.app].pop(event.unit.name, None):
                    logger.debug(f"Cleared consumed token for {event.unit.name}")
                else:
                    logger.error(f"Missing hostname in {event.unit.name}")
                return

            logger.debug(f"Cluster join token request received from {event.unit.name}")

            token = self.lxd_cluster_add_token(hostname)
            if not token:
                logger.error(f"Unable to add a join token for hostname={hostname}")
                return

            member_config = pylxd.Client().cluster.get().member_config

            # Strip the "description" and convert to compact JSON string
            for c in member_config:
                _ = c.pop("description", None)
            member_config = json.dumps(member_config, separators=(",", ":"))

            # Update the members list in the app data bag with the hostname of the unit that is
            # about to join the cluster
            members = event.relation.data[self.app].get("members")
            if members:
                members = json.loads(members)
            else:
                # If there is no members list, it means we need to add ourself first
                # and then the newly joined member
                my_hostname = os.uname().nodename
                logger.debug(
                    f"Initializing the members list with {self.unit.name} ({my_hostname})"
                )
                members = {self.unit.name: my_hostname}

            logger.debug(f"Adding {event.unit.name} ({hostname}) to members list")
            members[event.unit.name] = hostname

            # Convert the members list to a compact JSON string
            members = json.dumps(members, separators=(",", ":"))

            event.relation.data[self.app].update(
                {
                    "version": "1.0",
                    event.unit.name: token,
                    "member_config": member_config,
                    "members": members,
                }
            )
            logger.debug(f"Cluster joining information added for {event.unit.name}")
        elif not self._stored.lxd_clustered:  # Exit early if already clustered

            # As a non leader, check if we received a token in the app data bag
            d = event.relation.data[self.app]
            version = d.get("version")

            if not version:
                logger.error(f"Missing version in {self.app.name}")
                return

            if version != "1.0":
                logger.error(f"Incompatible version ({version}) found in {self.app.name}")
                return

            token = d.get(self.unit.name)
            if not token:
                logger.error(f"Missing token for {self.unit.name} in {self.app.name}")
                return

            member_config = d.get("member_config")
            if not member_config:
                logger.error(f"Missing member_config in {self.app.name}")
                return

            # Hand over the token and member_config
            logger.debug(f"Cluster joining information found in {self.app.name}")
            self.lxd_cluster_join(token, member_config)

            # Remove our hostname from our unit data bag to signify
            # we no longer need a join token to be emitted
            _ = event.relation.data[self.unit].pop("hostname", None)

            logger.debug(f"The unit {self.unit.name} is now part of the cluster")

    def _on_cluster_relation_created(self, event: RelationCreatedEvent) -> None:
        """If not in cluster mode: do nothing.

        Add our hostname to the unit data bag which will be used to issue a join token later on.
        """
        # All units automatically get a cluster peer relation irrespective of the mode
        # so do nothing if not in cluster mode
        if self.config.get("mode") != "cluster":
            return

        # Save our metrics endpoint address for later reuse
        metrics_endpoint = self.lxd_get_metrics_endpoint()
        event.relation.data[self.unit].update(
            {
                "metrics_endpoint": metrics_endpoint,
            }
        )
        logger.debug(f"Saved metrics endpoint ({metrics_endpoint}) to {self.unit.name}")

        # The leader will be the one creating the cluster so no join token needed
        if self.unit.is_leader():
            logger.debug("Not requesting cluster join token (we are leader)")
            return

        # Request a join token by adding our hostname to the unit data bag
        event.relation.data[self.unit].update(
            {
                "version": "1.0",
                "hostname": os.uname().nodename,
            }
        )
        logger.debug("Cluster join token requested")

    def _on_cluster_relation_departed(self, event: RelationDepartedEvent) -> None:
        # All units automatically get a cluster peer relation irrespective of the mode
        if self.config.get("mode") != "cluster":
            return

        # If we never joined, no point in departing
        if not self._stored.lxd_clustered:
            return

        # Only the leader will deal with node removal
        if not self.unit.is_leader():
            return

        # Load the list of cluster members
        members = event.relation.data[self.app].get("members")
        if not members:
            logger.error(f"Unable to get the cluster members list from {self.app.name}")
            return

        members = json.loads(members)

        # Lookup the hostname of the unit that left
        hostname = members.pop(event.unit.name, None)
        if not hostname:
            logger.error(
                f"Unable to find the hostname of {event.unit.name}, not removing from the cluster"
            )
            return
        else:
            logger.debug(f"Removing {event.unit.name} ({hostname}) from members list")

        # Remove it from the cluster
        self.lxd_cluster_remove(hostname)

        # Save the updated cluster members list
        members = json.dumps(members, separators=(",", ":"))
        event.relation.data[self.app].update(
            {
                "members": members,
            }
        )

        logger.debug(f"The unit {event.unit.name} is no longer part of the cluster")

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
        dashboard_file = "LXD.json"
        if not os.path.exists(dashboard_file):
            logger.error("No LXD dashboard for Grafana was bundled in the charm")
            return

        with open(dashboard_file) as f:
            data = f.read()
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
        # juju run-action --wait grafana/leader get-admin-password
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

    def _on_https_relation_changed(self, event: RelationChangedEvent) -> None:
        """Add the received client certificate to the trusted list."""
        # Relation cannot be rejected so notify the operator if it won't
        # be usable and don't touch the remote unit data bag at all
        if not self._stored.config["lxd-listen-https"]:
            logger.error(
                "The https relation is not usable (lxd-listen-https=false), "
                "please update the config and relate again"
            )
            return

        # In cluster mode, only the leader needs to handle the received cert
        if self._stored.lxd_clustered and not self.unit.is_leader():
            return

        d = event.relation.data[event.unit]
        version = d.get("version")

        if not version:
            logger.error(f"Missing version in {event.unit.name}")
            return

        if version != "1.0":
            logger.error(f"Incompatible version ({version}) found in {event.unit.name}")
            return

        cert = d.get("certificate")
        if not cert:
            logger.error(f"Missing certificate in {event.unit.name}")
            return
        else:
            cert = cert.encode()

        # Convert from string to bool
        autoremove = d.get("autoremove", False)
        autoremove = autoremove in ("True", "true")

        projects = d.get("projects")

        name = f"juju-relation-{event.unit.name}"

        # Unconditionally remove the cert (ignoring the :autoremove suffix) prior to adding it
        self.lxd_trust_remove(name, opportunistic=True)
        if autoremove:
            name += ":autoremove"

        if self.lxd_trust_add(cert=cert, name=name, projects=projects):
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

        host_env = pylxd.Client().host_info["environment"]
        d = {
            "version": "1.0",
            "certificate": host_env["certificate"],
            "certificate_fingerprint": host_env["certificate_fingerprint"],
            # Only strings are allowed so convert list to comma separated string
            "addresses": ",".join(host_env["addresses"]),
        }

        # In cluster mode, put the info in the app data bag
        # otherwise put it in the unit data bag
        if self._stored.lxd_clustered:
            event.relation.data[self.app].update(d)
            logger.debug(f"Connection information put in {self.app.name}")
        else:
            event.relation.data[self.unit].update(d)
            logger.debug(f"Connection information put in {self.unit.name}")

    def _on_https_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Remove the client certificate of the departed unit.

        Look through all the certificate to see if one matches the name of
        the departed unit and with the ":autoremove" suffix.
        """
        to_delete = f"juju-relation-{event.unit.name}:autoremove"
        self.lxd_trust_remove(name=to_delete)

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
        hosts = []
        for unit in event.relation.units:
            unit_data = event.relation.data[unit]
            host = unit_data.get("bound-address")
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

        db = ",".join(sorted(hosts))

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
        bound_address = self.juju_space_get_address("ovsdb-cms")
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
            f"Connection information put in {self.unit.name} (cms-client-bound-address={bound_address})"
        )

    def _on_prometheus_manual_relation_changed(self, event: RelationChangedEvent) -> None:
        """Send scrape config job info to Prometheus."""
        if (
            not self._stored.config["lxd-listen-https"]
            and not self._stored.config["lxd-listen-metrics"]
        ):
            logger.error(
                "The prometheus-manual relation is not usable (lxd-listen-https=false and "
                "lxd-listen-metrics=false), please update the config and relate again"
            )
            return

        if event.unit:
            remote_unit_name = f"{event.unit.name}-metrics:autoremove".replace("/", "_")
        else:
            remote_unit_name = ""
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

        to_delete = f"{event.unit.name}-metrics:autoremove".replace("/", "_")
        self.lxd_trust_remove(name=to_delete)

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
        if "local" in self.model.storages and len(self.model.storages["local"]) > 1:
            self.unit_blocked("LXD charm only supports a single storage volume")
            return False

        config_changed = self.config_changed()

        # If nothing changed and we were blocked due to a lxd- key
        # change (post-init), we can assume the change was reverted thus unblocking us
        if (
            not config_changed
            and isinstance(self.unit.status, BlockedStatus)
            and "Can't modify lxd- keys after initialization:" in str(self.unit.status)
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

        # lxd-preseed can only be set when mode=standalone
        if self.config.get("lxd-preseed") and self.config.get("mode") != "standalone":
            self.unit_blocked("Can't provide lxd-preseed when mode != standalone")
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

        if not require_ipv4:
            return str(net.ingress_address)

        addrs = net.ingress_addresses
        ipv4_addrs = [a for a in addrs if a.version == 4]
        if ipv4_addrs:
            return str(ipv4_addrs[0])

        return ""

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
            client = pylxd.Client()
            conf = client.api.get().json()["metadata"]["config"]
            orig_conf = conf
            if http_proxy:
                logger.debug(f"Configuring core.proxy_http={http_proxy}")
                conf["core.proxy_http"] = http_proxy
            if https_proxy:
                logger.debug(f"Configuring core.proxy_https={https_proxy}")
                conf["core.proxy_https"] = https_proxy
            if no_proxy:
                logger.debug(f"Configuring core.proxy_ignore_hosts={no_proxy}")
                conf["core.proxy_ignore_hosts"] = no_proxy

            if conf != orig_conf:
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
                for k, v in SYSCTL_CONFIGS.items():
                    f.write(f"{k} = {v}\n")

            try:
                subprocess.run(
                    ["sysctl", "--quiet", "--load", sysctl_file], capture_output=True, check=True
                )
            except subprocess.CalledProcessError as e:
                self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
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
                f.write("\n".join(SYSTEMD_TMPFILES_CONFIGS) + "\n")
            try:
                subprocess.run(["systemd-tmpfiles", "--create"], capture_output=True, check=True)
            except subprocess.CalledProcessError as e:
                self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
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
        )
        if c.returncode != 0 or not c.stdout:
            logger.debug(
                f'The command "lxc cluster add {hostname}" did not produce '
                f"any output (rc={c.returncode})"
            )
            return ""

        try:
            token = c.stdout.splitlines()[1]
        except IndexError:
            return ""

        return token

    def lxd_cluster_join(self, token: str, member_config: str) -> None:
        """Join an existing cluster."""
        logger.debug("Joining cluster")
        conf = json.loads(member_config)

        # If a local storage device was provided, it needs to be added in the storage-pool
        if "local" in self.model.storages and len(self.model.storages["local"]) == 1:
            for m in conf:
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
                "member_config": conf,
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
            subprocess.run(["lxd", "init", "--preseed"], check=True, input=preseed_yaml)
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')

            # Leave a copy of the YAML preseed that didn't work
            handle, tmp_file = tempfile.mkstemp()
            with os.fdopen(handle, "wb") as f:
                f.write(preseed_yaml)
            logger.error(f"The YAML preseed that caused a failure was saved to {tmp_file}")
            raise RuntimeError

        self.unit_active()
        self._stored.lxd_clustered = True
        logger.debug(f"Cluster joined successfully consuming the token: {token}")

    def lxd_cluster_remove(self, member: str) -> None:
        """Remove a member from the cluster."""
        try:
            subprocess.run(
                ["lxc", "cluster", "remove", "--force", member],
                capture_output=True,
                check=True,
                input="yes".encode(),
            )
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')

    def lxd_generate_cert_key_pair(self, name: str) -> Tuple[str, str]:
        """Generate a certificate and key pair."""
        if not name:
            logger.error("The name cannot be empty.")
            return ("", "")

        if "/" in name:
            logger.error('The name cannot contain a "/".')
            return ("", "")

        cmd = [
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
            )
        except subprocess.CalledProcessError as e:
            logger.error(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
            return ("", "")

        # The key data was output to stdout and never touched the disk
        # but the certificate data needs to be read from the file that
        # can then be discarded
        key = c.stdout
        with open("certificate.crt") as f:
            cert = f.read()
        os.remove("certificate.crt")

        return (cert, key)

    def lxd_get_metrics_endpoint(self) -> str:
        """Get the metrics endpoint.

        First check if there is a dedicated metrics endpoint and fallback to the generic https
        listener where metrics are also available.
        """
        addr = self.juju_space_get_address("metrics") or self.juju_space_get_address("https")
        if not addr:
            return ""

        if ":" in addr:
            addr = f"[{addr}]"
        return f"{addr}:8443"

    def lxd_get_prometheus_targets(self) -> List[str]:
        """Return a list of targets to be scraped by Prometheus."""
        if self.config.get("mode") != "cluster":
            # The unit's metrics_endpoint is the only target for the scape_job
            return [self.lxd_get_metrics_endpoint()]

        if not self.unit.is_leader():
            # The unit is part of a cluster but not the app leader, so nothing to report
            return []

        if not self._stored.lxd_clustered:
            # Not clustered yet, no prometheus targets to report.
            return []

        # At this point, the unit is the app leader so it needs to get the metrics_endpoint
        # of the other units part of the cluster relation
        cluster_relation = self.model.get_relation("cluster")
        if not cluster_relation:
            logger.error("Missing cluster relation while mode=cluster")
            return []

        targets: List[str] = []
        for unit in cluster_relation.units:
            unit_metrics_endpoint = cluster_relation.data[unit].get("metrics_endpoint")
            if not unit_metrics_endpoint:
                logger.error(f"Couldn't obtain {unit.name}'s metrics_endpoint")
                continue
            targets.append(unit_metrics_endpoint)

        # If the targets list doesn't match the units count, return an empty list
        if len(targets) != len(cluster_relation.units):
            logger.error(
                f"Only got metrics_endpoint for {len(targets)} units out of the"
                f" {len(cluster_relation.units)} part of the cluster relation"
            )
            return []

        # Add leader's own metrics_endpoint
        targets.append(self.lxd_get_metrics_endpoint())

        targets.sort()
        return targets

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

        # Get the targets list which corresponds the units' metrics_endpoint
        targets = self.lxd_get_prometheus_targets()
        if not targets:
            logger.debug(f"{self.unit.name} isn't aware of any targets for prometheus-manual")
            return

        # Ensure request_id uniqueness
        if self._stored.lxd_clustered:
            my_id = self.app.name
        else:
            # Replace foo/0 by foo_0 as `openssl req -subj` doesn't like '/'
            my_id = self.unit.name.replace("/", "_")

        # Include our own model name in the request_id to avoid potential
        # collisions when doing Cross-Model Relations (CMRs) because the unit
        # name is not subject to the normal unit name translation done during CMR
        my_id = f"{self.model.name}_{my_id}"
        scrape_job_key = f"request_{my_id}"

        # The scrape_job can be generated on the fly with the exception of the
        # client_cert/client_key that should be preserved.
        old_scrape_job = prometheus_relation.data[self.unit].get(scrape_job_key)
        if old_scrape_job:
            old_data = json.loads(old_scrape_job)
            client_cert = old_data["client_cert"]
            client_key = old_data["client_key"]
        elif remote_unit_name:
            (client_cert, client_key) = self.lxd_generate_cert_key_pair(remote_unit_name)

            if client_cert:
                self.lxd_trust_add(
                    cert=client_cert.encode(),
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
                    "job_name": "lxd",
                    "request_id": my_id,
                    "job_data": {
                        "metrics_path": "/1.0/metrics",
                        "scheme": "https",
                        "static_configs": [
                            {
                                "targets": targets,
                            },
                        ],
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
        mode = self.config.get("mode")
        self.unit_maintenance(f"Initializing LXD in {mode} mode")

        preseed = self.config.get("lxd-preseed")

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
                )
            except subprocess.CalledProcessError as e:
                self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
                raise RuntimeError
        else:
            self.unit_maintenance("Performing initial configuration")

            if mode == "standalone":
                configure_storage = True
                network_dev = "lxdbr0"
            elif self.unit.is_leader():  # leader and mode=cluster
                configure_storage = True
                network_dev = "lxdfan0"
            else:  # non-leader and mode=cluster
                configure_storage = False
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
                            network_config = None
                    else:
                        network_config = None

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
                        subprocess.run(
                            ["lxc", "cluster", "enable", os.uname().nodename],
                            capture_output=True,
                            check=True,
                        )
                        self._stored.lxd_clustered = True

                # Persist profile changes
                profile.save()

            except pylxd.exceptions.LXDAPIException as e:
                self.unit_blocked(f"Failed to configure LXD: {e}")
                raise RuntimeError
            except subprocess.CalledProcessError as e:
                self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
                raise RuntimeError

        # Initial configuration of core.proxy_* keys
        self.juju_set_proxy()

        # Done with the initialization
        self._stored.config["mode"] = mode
        self._stored.config["lxd-preseed"] = preseed

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
        )
        return c.returncode == 0

    def lxd_monitor_lifecycle(self) -> None:
        """Monitor lifecycle events (blocking)."""
        event_types = set([pylxd.EventType.Lifecycle])
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
                ["systemctl", "reload", "snap.lxd.daemon.service"], capture_output=True, check=True
            )
            mon.join(timeout=600.0)

            # If the monitor thread is still alive, it means LXD didn't reload
            if mon.is_alive():
                # There is no easy way to terminate the hanging thread but the charm
                # process is short-lived anyway.
                self.unit_maintenance("Timeout while reloading the LXD service")
                raise RuntimeError

        except subprocess.CalledProcessError as e:
            self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
            raise RuntimeError

    def lxd_set_address(self, listener: str, addr: str) -> bool:
        """Configure the core.<listener>_address and save the configured address.

        Also save the boolean toggle to enable/disable the listener.
        """
        # default ports
        ports = {
            "bgp": 179,
            "dns": 53,
            "https": 8443,
            "metrics": 9100,
        }
        if not ports.get(listener):
            logger.error(f"Invalid listener ({listener}) provided")
            return False

        # Some listeners require a special API extension
        api_extensions = {
            "bgp": "network_bgp",
            "dns": "network_dns",
            "metrics": "metrics",
        }

        required_api = api_extensions.get(listener)

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

        # Save the addr instead of the socket because it makes it easier
        # to compare with the IP returned by get_binding()
        self._stored.addresses[listener] = addr

        # open/close-port
        if addr:
            cmd = ["open-port"]
        else:
            cmd = ["close-port"]
        cmd += [str(ports[listener]), "--endpoints", listener]
        logger.debug(f"Calling {cmd}")

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
            return False

        return True

    def lxd_trust_add(
        self, cert: str, name: str, projects: str = "", metrics: bool = False
    ) -> bool:
        """Add a client certificate to the trusted list."""
        msg = f"Adding {name}'s certificate to the trusted list"
        config: Dict[str, Union[str, List[str], bool]] = {
            "name": name,
            "password": "",
            "cert_data": cert,
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
        except pylxd.exceptions.LXDAPIException as e:
            logger.error(f"Failed to add certificated: {e}")
            return False

        return True

    def lxd_trust_remove(
        self,
        name: str = "",
        fingerprint: str = "",
        opportunistic: bool = False,
    ) -> bool:
        """Remove a client certificate from the trusted list."""
        if not name and not fingerprint:
            logger.error("No name nor fingerprint provided, not removing any certificate")
            return False

        client = pylxd.Client()

        # If no fingerprint was provided, enumerate all certs looking for one with a matching
        # name with or without a ":autoremove" suffix
        if not fingerprint:
            possible_names = (name, f"{name}:autoremove")
            for c in client.certificates.all():
                if c.name in possible_names:
                    fingerprint = c.fingerprint
                    logger.debug(
                        f"The certificate named {c.name} has the fingerprint: {fingerprint}"
                    )
                    break

        if not fingerprint:
            if not opportunistic:
                logger.error(f"No certificate found with the name {name}")
            return False

        try:
            c = client.certificates.get(fingerprint)
            logger.info(f"Removing {c.name}'s certificate ({fingerprint}) from the trusted list")
            c.delete()
            return True
        except pylxd.exceptions.NotFound:
            logger.error(f"No certificate with fingerprint {fingerprint} found")
            return False

    def resource_sideload(self) -> None:
        """Sideload resources."""
        # Multi-arch support
        arch = os.uname().machine
        if arch == "x86_64":
            possible_archs = ["x86_64", "amd64"]
        else:
            possible_archs = [arch]

        # LXD snap
        lxd_snap_resource = None
        fname_suffix = ".snap"
        try:
            # Note: self._stored can only store simple data types (int/float/dict/list/etc)
            lxd_snap_resource = str(self.model.resources.fetch("lxd-snap"))
        except ModelError:
            pass

        tmp_dir = None
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
        else:
            self._stored.lxd_snap_path = lxd_snap_resource

        if self._stored.lxd_snap_path:
            self.snap_sideload_lxd()
            if tmp_dir:
                os.remove(self._stored.lxd_snap_path)
                os.rmdir(tmp_dir)

        # LXD binary
        lxd_binary_resource = None
        fname_suffix = ""
        try:
            # Note: self._stored can only store simple data types (int/float/dict/list/etc)
            lxd_binary_resource = str(self.model.resources.fetch("lxd-binary"))
        except ModelError:
            pass

        tmp_dir = None
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
            subprocess.run(["snap", "set", "lxd"] + snap_set_list, capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
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
        channel = self.config["snap-channel"]
        if channel:
            channel_name = channel
        else:
            channel_name = "latest/stable"
        self.unit_maintenance(f"Installing LXD snap (channel={channel_name})")

        # During the install phase, there won't be anything in self._stored.config
        # so fallback to the live configuration
        mode = self._stored.config.get("mode")
        if not mode:
            mode = self.config["mode"]

        # Cluster members all need to get the same snap version so set a cohort
        if mode == "cluster":
            logger.debug("Using snap cohort due to mode=cluster")
            cohort = ["--cohort=+"]
        else:
            cohort = []

        try:
            subprocess.run(
                ["snap", "install", "lxd", f"--channel={channel}"] + cohort,
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["snap", "refresh", "lxd", f"--channel={channel}"] + cohort,
                capture_output=True,
                check=True,
            )
            if os.path.exists("/var/lib/lxd"):
                subprocess.run(["lxd.migrate", "-yes"], capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
            raise RuntimeError

        # Done with the snap installation
        self._stored.config["snap-channel"] = channel

    def snap_sideload_lxd(self) -> None:
        """Sideload LXD snap resource."""
        logger.debug("Applying LXD snap sideload changes")

        # A 0 byte file will unload the resource
        if os.path.getsize(self._stored.lxd_snap_path) == 0:
            logger.debug("Reverting to LXD snap from snapstore")
            channel = self._stored.config["snap-channel"]
            cmd = ["snap", "refresh", "lxd", f"--channel={channel}", "--amend"]
            alias = None
            enable = None
        else:
            logger.debug("Sideloading LXD snap")
            cmd = ["snap", "install", "--dangerous", self._stored.lxd_snap_path]
            # Since the sideloaded snap doesn't have an assertion, some things need
            # to be done manually
            alias = ["snap", "alias", "lxd.lxc", "lxc"]
            enable = ["systemctl", "enable", "--now", "snap.lxd.daemon.unix.socket"]

        try:
            subprocess.run(cmd, capture_output=True, check=True)
            if alias:
                subprocess.run(alias, capture_output=True, check=True)
            if enable:
                subprocess.run(enable, capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            self.unit_blocked(f'Failed to run "{e.cmd}": {e.stderr} ({e.returncode})')
            raise RuntimeError

    def snap_sideload_lxd_binary(self) -> None:
        """Sideload LXD binary resource."""
        logger.debug("Applying LXD binary sideload changes")
        lxd_debug = "/var/snap/lxd/common/lxd.debug"

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
        if self._stored.reboot_required and not os.path.exists(REBOOT_REQUIRED_FILE):
            self._stored.reboot_required = False
            logger.debug("Required reboot done")

    def system_set_reboot_required(self) -> None:
        """Indicate that a reboot is required to reach a clean state."""
        # Touch a flag file indicating that a reboot is required.
        try:
            open(REBOOT_REQUIRED_FILE, "a").close()
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
