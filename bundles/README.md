# Bundles

The [bundles/](bundles/) directory contains various [Juju bundles](https://juju.is/docs/sdk/bundle-reference) that can be used as references.

## Integration between LXD and Ceph

[lxd-and-ceph.yaml](bundles/lxd-and-ceph.yaml) can be used to setup a cluster of 5 machines each running a LXD instance colocated with a Ceph OSD. A separated/additional machine will run 3 containers each running a Ceph monitor.

At the end of a successful deployment, LXD will need to be configured to interact with the freshly deployed Ceph cluster following those [instructions](../README.md#Storage).

## Integration between LXD and OVN

[lxd-and-ovn.yaml](bundles/lxd-and-ovn.yaml) can be used to setup a cluster of 5 machines each running a LXD instance and an OVN dedicated chassis. On top of that, 3 machines will have an additional charm: OVN central. A separated/additional machine will run 2 containers to host a PostgreSQL DB used by Vault. At the end of a successful deployment, LXD will be able to interact with OVN.

## Integration between LXD and Prometheus2 & Grafana

[lxd-and-prometheus2+grafana.yaml](bundles/lxd-and-prometheus2+grafana.yaml) can be used to setup a LXD cluster of 3 machines along with a Prometheus2 machine that will scrape the metrics endpoint of each of the LXD machines and a Grafana dashboard to visualize them.

*Caveat*: there seems to be a race between LXD injecting the dashboard into Grafana and Grahana having a relation with Prometheus2. Because of this, it is possible for the dashboard to show as empty. To workaround this problem:

```shell
# remove the relation
juju remove-relation lxd:grafana-dashboard grafana:dashboards
# log to grafana using the admin password obtained with:
juju run-action --wait grafana/leader get-admin-password
# delete the bogus LXD dashboard
# recreate the relation
juju add-relation lxd:grafana-dashboard grafana:dashboards
```

## Integration between LXD, OVN, Ceph, Prometheus2 & Grafana

[all-in-one.yaml](bundles/all-in-one.yaml) can be used to setup a cluster of 5 machines each running a LXD instance colocated with a Ceph OSD and an OVN dedicated chassis. On top of that, 3 machines will have an additional charm: OVN central. A separated/additional machine will run: 2 containers to host a PostgreSQL DB used by Vault, 1 container to run Prometheus2, another to run Grafana and 3 additional containers each running a Ceph monitor.

Note: see the *caveat* in the LXD and Prometheus2 & Grafana section.
