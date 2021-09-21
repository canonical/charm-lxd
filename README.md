# LXD

The [LXD charmed operator](https://github.com/canonical/charm-lxd) provides a simple way to deploy [LXD](https://linuxcontainers.org/lxd/) at scale using [Juju](https://jaas.ai/).

## What is LXD?

<img align="right" alt="LXD logo" src="icon.svg">

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

## Additional information

- [LXD web site](https://linuxcontainers.org/lxd/)
- [LXD GitHub](https://github.com/lxc/lxd/)
- [LXD Docs](https://linuxcontainers.org/lxd/docs/master/)
