from __future__ import absolute_import

import pkg_resources

from semantic_version import (
    Spec,
)

from eth_tester.backends.base import BaseChainBackend
from eth_tester.backends.pyevm.utils import (
    get_pyevm_version,
    is_pyevm_available,
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
    # Accounts
    #
    def get_accounts(self):
        from pyevm.tools import tester

        for account in tester.accounts:
            yield account