from __future__ import absolute_import

import pkg_resources

from eth_tester.backends.base import BaseChainBackend
from eth_tester.backends.pyevm.utils import (
    get_pyevm_version,
    is_pyevm_available,
)
from eth_tester.constants import (
    FORK_HOMESTEAD,
    FORK_DAO,
    FORK_ANTI_DOS,
    FORK_STATE_CLEANUP,
)
from eth_tester.exceptions import (
    UnknownFork,
)


class PyEvmBackend(BaseChainBackend):
    def __init__(self):
        if not is_pyevm_available():
            version = get_pyevm_version()
            if version is None:
                raise pkg_resources.DistributionNotFound(
                    "The `py-evm` package is not available.  The "
                    "`PyEvmBackend` requires a 0.2.x version of the "
                    "py-evm package to be installed."
                )
        self.reset_to_genesis()

    def reset_to_genesis(self):
        from evm.tools import tester
        self.evm = tester.state()

    #
    # Fork Rules
    #
    def set_fork_block(self, fork_name, fork_block):
        if fork_name == FORK_HOMESTEAD:
            self.evm.config['HOMESTEAD_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_DAO:
            self.evm.config['DAO_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_ANTI_DOS:
            self.evm.config['ANTI_DOS_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_STATE_CLEANUP:
            self.evm.config['CLEARING_FORK_BLKNUM'] = fork_block
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))

    #
    # Accounts
    #
    def get_accounts(self):
        from evm.tools import tester
        return tester.accounts
