#!/usr/bin/env python3
#
# (c) 2020 Canonical Ltd. All right reservered
#

from ops.charm import CharmBase
from ops.main import main
from ops.framework import StoredState
from ops.model import ActiveStatus

from subprocess import check_call, CalledProcessError

import logging
import os

logger = logging.getLogger(__name__)


class LxdCharm(CharmBase):
    state = StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self.framework.observe(self.on.start, self.on_start)
        self.framework.observe(self.on.config_changed, self.on_config_changed)

    def on_start(self, event):
        self._install_lxd()
        self._bootstrap_lxd()
        self.model.unit.status = ActiveStatus()

    def _install_lxd(self):
        if os.path.exists("/usr/bin/lxd"):
            check_call(['apt', 'purge', '-y', 'lxd', 'lxd-client'])

        try:
            channel_arg = '--channel={}'.format(self.model.config['snap_channel'])
            check_call(['snap', 'install', channel_arg, 'lxd'])
        except CalledProcessError as err:
            logger.warn('Failed to install LXD snap: {}'.format(err))
            raise err

    def _bootstrap_lxd(self):
        try:
            # FIXME Use a preseed here to provide a more focused default configuration
            check_call(['/snap/bin/lxd', 'init', '--auto'])
        except CalledProcessError as err:
            logger.error('Failed to bootstrap LXD: {}'.format(err))
            raise err

    def on_config_changed(self, event):
        pass


if __name__ == "__main__":
    main(LxdCharm)
