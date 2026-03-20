# LXD

The [LXD charmed operator](https://github.com/canonical/charm-lxd) provides a simple way to deploy [LXD](https://ubuntu.com/lxd) at scale using [Juju](https://jaas.ai/).

## What is LXD?

<img align="right" alt="LXD logo" src="https://documentation.ubuntu.com/lxd/en/latest/_static/tag.png">

[LXD](https://linuxcontainers.org/lxd/introduction/) is a next generation system container and virtual machine manager. It offers a unified user experience around full Linux systems running inside containers or virtual machines.

LXD is image based and provides images for a wide number of Linux distributions. It provides flexibility and scalability for various use cases, with support for different storage backends and network types and the option to install on hardware ranging from an individual laptop or cloud instance to a full server rack.

## Getting started with Juju

Follow `Juju`'s [Charmed Operator Lifecycle Manager](https://juju.is/docs/olm) to boostrap your cloud of choice and create a model to host your LXD application. Once done, deploying a LXD unit is as simple as:

```shell
juju deploy ch:lxd
```

Or for a set of 4 units using the `5.0/stable` snap with the HTTPS listener enabled:

```shell
juju deploy ch:lxd --num-units 4 --config snap-channel="5.0/stable" --config lxd-listen-https=true
```

Or a unit using local storage as `ZFS` storage backend:

```shell
juju deploy ch:lxd --storage local=100G,1
```

Or a cluster of 3 members:

```shell
juju deploy ch:lxd --num-units 3 --config mode=cluster
```

## Development

Charm library dependencies are declared in `charmcraft.yaml` and should be
fetched locally for development rather than copied into git.

Fetch the required libraries with:

```shell
./scripts/fetch-libs.sh
```

For local test runs, use:

```shell
PYTHONPATH=src:lib pytest tests/unit -q
```

## Adoption mode for existing hosts

This fork adds a narrow adoption mode for already installed standalone LXD
hosts.

Example:

```shell
juju deploy ./lxd_ubuntu@24.04-amd64.charm lxd --config adopt-existing=true
```

Behavior:

- if LXD is absent, the charm falls back to the normal bootstrap path
- if LXD is present but not initialized, the unit blocks and does not mutate the host
- if LXD is present and initialized, the charm adopts it without re-running the
  install/bootstrap mutation path

During the initial adoption attempt, the charm suppresses:

- snap install/refresh
- proxy writes
- listener writes
- relation-driven writes for `logging`, `metrics-endpoint`, and `https`

Once adoption succeeds, normal management resumes even if `adopt-existing=true`
remains set. That means later config changes and supported relations behave as
they do for a normally managed host.

Practical examples:

```shell
# Existing host is installed but not yet initialized: safe blocked status
juju deploy ./lxd_ubuntu@24.04-amd64.charm lxd --to 10 --config adopt-existing=true

# Existing initialized standalone host: adopt, then resume normal management
juju deploy ./lxd_ubuntu@24.04-amd64.charm lxd --to 11 --config adopt-existing=true

# Fresh blank host: bootstrap normally even with adopt-existing=true
juju deploy ./lxd_ubuntu@24.04-amd64.charm lxd --to 12 --config adopt-existing=true
```

If the host blocks because it is not initialized yet, you can initialize LXD
manually and redeploy the unit to re-run the adoption path.

For a quick standalone repro from a model that already contains one machine,
use:

```shell
./examples/test-adopt-existing-standalone.sh <model> <machine-id>
```

## Resources

For debugging purposes, the charm allows sideloading a LXD binary (`lxd-binary`) or a full LXD snap (`lxd-snap`) by attaching resources at deploy time or later on. Both resources also accept tarballs containing architecture specific assets to support mixed architecture deployments. Those tarballs need to contain files at the root named as lxd_${ARCH} for the `lxd-binary` resource and lxd_${ARCH}.snap for the `lxd-snap` resource.

```shell
juju attach-resource lxd lxd-snap=lxd_21550.snap
```

To detach a resource, the operator will need to attach an empty file as Juju does not provide a mechanism to do this.

```shell
touch lxd_empty.snap
juju attach-resource lxd lxd-snap=lxd_empty.snap
```

## Storage

To use local storage with one disk of at least `10GiB` as local `ZFS` storage backend:

```shell
juju deploy ch:lxd --storage local=10G,1
```

To use remote storage, this charm can be related to the [ceph-mon](https://charmhub.io/ceph-mon) charm:

```shell
juju relate lxd ceph-mon
```

A Ceph storage pool then needs to be created, first in Ceph and then in LXD. Here's how to create a pool named `foo`:

```shell
# create the pool on the Ceph cluster
juju run --wait=2m ceph-mon/leader create-pool name=foo app-name=lxd

# then on LXD depending on the mode= setting

# if mode=standalone:
lxc storage create remote ceph source=foo ceph.user.name=lxd

# if mode=cluster: the pool needs to be created on each cluster
# members before being created at the cluster level
lxc storage create remote ceph source=foo --target lxd1
lxc storage create remote ceph source=foo --target lxd2
lxc storage create remote ceph source=foo --target lxd3
lxc storage create remote ceph ceph.user.name=lxd
```

## What about feature XYZ?

In general, if something is doable by the LXD API, the charm won't replicate the feature to avoid duplication and other problems like desynchronisation between the charm's view and LXD's view. If however you find a feature that would be a worthwhile addition to the charm, please open an issue or send a pull request.

## Supported LXD versions

The charm only supports currently supported versions of LXD, including both long term support and feature releases. Please see the known issues section below.

## Known issues

### LXD 4.0 does not support the `https` relation

With LXD 4.0, `lxc config trust list --format csv` does not show the certificate name provided when adding the certificate. This prevents the charm from adding the `juju-relation-` prefix that is required to later remove the certificate when the relation is broken. Because of this, the charm will refuse to add the certificate if the LXD is too old to allow proper trust management.

### Cluster leader removal

When in `mode=cluster`, removing the LXD application leader risks taking the whole cluster down.

**Workaround**: do not remove the leader unit (`lxd/leader`) when `mode=cluster`

### Removing a unit from a cluster might leave the offline member part of the cluster

When force removing a machine/unit, Juju doesn't always emit the `cluster_relation_departed` event ([LP: #1947416](https://bugs.launchpad.net/bugs/1947416)) preventing the proper cleanup on the LXD side.

**Workaround**: either avoid force removals or do a manual cleanup by connecting to another unit and removing the offline/departed unit using `lxc cluster remove --force <hostname of departed unit>`

## Additional information

- [LXD web site](https://ubuntu.com/lxd)
- [LXD GitHub](https://github.com/canonical/lxd/)
- [LXD Docs](https://documentation.ubuntu.com/lxd/en/latest/)
