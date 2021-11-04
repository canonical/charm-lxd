# Bundles

The [bundles/](bundles/) directory contains various [Juju bundles](https://juju.is/docs/sdk/bundle-reference) that can be used as references.

## Integration between LXD and Ceph

[lxd-and-ceph.yaml](bundles/lxd-and-ceph.yaml) can be used to setup a cluster of 5 machines each running a LXD instance colocated with a Ceph OSD. A separated/additional machine will run 3 containers each running a Ceph monitor.
