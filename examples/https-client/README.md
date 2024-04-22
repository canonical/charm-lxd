# https-client

This simple example charm is used to establish a relation with the LXD charm:

```shell
juju deploy ./https-client_ubuntu-20.04-amd64.charm
juju relate https-client lxd
```

Note: the `https-client_ubuntu-20.04-amd64.charm` can be built locally with `charmcraft pack` or downloaded from GitHub tests artifacts.
