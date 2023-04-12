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


## OVN and LXD

Setup the `test` model and deploy the OVN chassis and LXD instances using [ovn-chassis-and-lxd.yaml](ovn/ovn-chassis-and-lxd.yaml):

``shell
juju add-model test maas
juju deploy -m test ./ovn-chassis-and-lxd.yaml
``

Setup the `ctrl` model and deploy the OVN central units and Vault using [ovn-central-and-vault.yaml](ovn/ovn-central-and-vault.yaml):

``shell
juju add-model ctrl maas
juju deploy -m ctrl ./ovn-central-and-vault.yaml
``

Create the CMRs:

``shell
# offer ovn-dedicated-chassis' certificates interface for consumption by vault
#       and the ovsdb interface for consumption by ovn-central
juju offer test.ovn-dedicated-chassis:certificates,ovsdb

# relate vault to the remote ovn-dedicated-chassis
juju add-relation -m ctrl vault admin/test.ovn-dedicated-chassis

# relate ovn-central to the remote ovn-dedicated-chassis
echo "XXX: this currently doesn't work, see LP: #1976537"
juju add-relation -m ctrl ovn-central admin/test.ovn-dedicated-chassis

# offer lxd' certificates interface for consumption by vault
#       and the ovsdb-cms interface for consumption by ovn-central
juju offer test.lxd:certificates,ovsdb-cms

# relate vault to the remote lxd
juju add-relation -m ctrl vault admin/test.lxd

# relate ovn-central to the remote lxd
juju add-relation -m ctrl ovn-central admin/test.lxd
``

## Known issues

The order used to `offer` and `add-relation` is important despite what `juju add-relation --help` might say.
Establishing the `ceph-osd` to `ceph-mon` relation in the wrong order might result in a broken relation.

Establishing the `lxd` to `ceph-mon` relation in the wrong order will have the `ceph-mon` charm enter the `blocked`
state with the error message `Unsupported CMR relation`.

Solution: use the steps outline above as they are known to work.

## LXD and COS Lite

The COS Lite stack should be deployed as [documented upstream](https://charmhub.io/cos-lite). Let's assume the COS Lite model
is named `cos`. Here is what needs to be done to have LXD integrated with the COS Lite stack:

```shell
# assumes Juju 3.0+

# expose some interfaces
juju offer cos.grafana:grafana-dashboard
juju offer cos.loki:logging
juju offer cos.prometheus:metrics-endpoint

# integrate/relate LXD with COS Lite services
juju integrate lxd admin/cos.grafana
juju integrate lxd admin/cos.loki
juju integrate lxd admin/cos.prometheus
```
