# LXD

The [LXD charmed operator](https://github.com/canonical/charm-lxd) provides a simple way to deploy [LXD](https://linuxcontainers.org/lxd/) at scale using [Juju](https://jaas.ai/).

## What is LXD?

<img align="right" alt="LXD logo" src="https://linuxcontainers.org/static/img/containers.svg">

[LXD](https://linuxcontainers.org/lxd/introduction/) is a next generation system container and virtual machine manager. It offers a unified user experience around full Linux systems running inside containers or virtual machines.

LXD is image based and provides images for a wide number of Linux distributions. It provides flexibility and scalability for various use cases, with support for different storage backends and network types and the option to install on hardware ranging from an individual laptop or cloud instance to a full server rack.

## Getting started with Juju

Follow `Juju`'s [Charmed Operator Lifecycle Manager](https://juju.is/docs/olm) to boostrap your cloud of choice and create a model to host your LXD application. Once done, deploying a LXD unit is as simple as:

```shell
juju deploy lxd
```

Or for a set of 4 units using the `4.0/stable` snap with the HTTPS listener enabled:

```shell
juju deploy lxd --num-units 4 --config snap-channel="4.0/stable" --config lxd-listen-https=true
```

Or a unit using local storage as `ZFS` storage backend:

```shell
juju deploy lxd --storage local=100G,1
```

Or a cluster of 3 members:

```shell
juju deploy lxd --num-units 3 --config mode=cluster
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
juju deploy lxd --storage local=10G,1
```

To use remote storage, this charm can be related to the [ceph-mon](https://charmhub.io/ceph-mon) charm:

```shell
juju relate lxd ceph-mon
```

A Ceph storage pool then needs to be created, first in Ceph and then in LXD. Here's how to create a pool named `foo`:

```shell
# create the pool on the Ceph cluster
juju run-action --wait ceph-mon/leader create-pool name=foo app-name=lxd

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

## Known issues

### Cluster leader removal

When in `mode=cluster`, removing the LXD application leader risks taking the whole cluster down.

**Workaround**: do not remove the leader unit (`lxd/leader`) when `mode=cluster`

### Removing a unit from a cluster might leave the offline member part of the cluster

When force removing a machine/unit, Juju doesn't always emit the `cluster_relation_departed` event ([LP: #1947416](https://bugs.launchpad.net/bugs/1947416)) preventing the proper cleanup on the LXD side.

**Workaround**: either avoid force removals or do a manual cleanup by connecting to another unit and removing the offline/departed unit using `lxc cluster remove --force <hostname of departed unit>`

## Additional information

- [LXD web site](https://linuxcontainers.org/lxd/)
- [LXD GitHub](https://github.com/lxc/lxd/)
- [LXD Docs](https://linuxcontainers.org/lxd/docs/master/)
