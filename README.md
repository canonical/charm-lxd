# LXD Charm

## Build and Deploy

First build and deploy the LXD charm

    $ snap install --classic --beta charmcraft
    $ charmcraft
    $ juju add-model lxd-test
    $ juju deploy ./build
