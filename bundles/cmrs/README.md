# Cross Model Relations (CMRs)

## Ceph and LXD

Setup the `test` model and deploy the Ceph OSDs and LXD instances using [ceph-osd-and-lxd.yaml](ceph/ceph-osd-and-lxd.yaml):

``shell
juju add-model test maas
juju create-storage-pool -m test local maas
juju deploy -m test ./ceph-osd-and-lxd.yaml
``

Setup the `ctrl` model and deploy the Ceph MONs using [ceph-mon.yaml](ceph/ceph-mon.yaml):

``shell
juju add-model ctrl maas
juju deploy -m ctrl ./ceph-mon.yaml
``

Create the CMRs:

``shell
# offer ceph-osd's mon interface for consumption by ceph-mon
juju offer test.ceph-osd:mon

# relate ceph-mon to the remote ceph-osd
juju add-relation -m ctrl ceph-mon admin/test.ceph-osd

# offer lxd's ceph interface for consumption by ceph-mon
juju offer test.lxd:ceph

# relate ceph-mon to the remote lxd
juju add-relation -m ctrl ceph-mon admin/test.lxd
``

At the end of a successful deployment, LXD will need to be configured to interact with the freshly deployed Ceph cluster following those [instructions](../../README.md#Storage).

## Known issues

The order used to `offer` and `add-relation` is important despite what `juju add-relation --help` might say.
Establishing the `ceph-osd` to `ceph-mon` relation in the wrong order might result in a broken relation.

Establishing the `lxd` to `ceph-mon` relation in the wrong order will have the `ceph-mon` charm enter the `blocked`
state with the error message `Unsupported CMR relation`.

Solution: use the steps outline above as they are known to work.
