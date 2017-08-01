from __future__ import absolute_import

import pkg_resources

from semantic_version import (
    Spec,
)

from eth_utils import (
    to_checksum_address,
    to_tuple,
)

from ..base import BaseChainBackend
from .utils import (
    get_pyethereum_version,
    is_pyethereum20_available,
)


class PyEthereum20Backend(BaseChainBackend):
    tester_module = None

    def __init__(self):
        if not is_pyethereum20_available():
            version = get_pyethereum_version()
            if version is None:
                raise pkg_resources.DistributionNotFound(
                    "The `ethereum` package is not available.  The "
                    "`PyEthereum20Backend` requires a 2.0.x version of the "
                    "ethereum package to be installed."
                )
            elif version not in Spec('>=2.0.0,<2.1.0'):
                raise pkg_resources.DistributionNotFound(
                    "The `PyEthereum20Backend` requires a 2.0.x version of the "
                    "`ethereum` package.  Found {0}".format(version)
                )
        from ethereum.tools import tester
        self.tester_module = tester
        self.evm = tester.Chain()

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        for account in self.tester_module.accounts:
            yield to_checksum_address(account)

    #
    # Chain data
    #
    def get_block_by_number(self, block_number):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_block_by_hash(self, block_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_latest_block(self):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_transaction_by_hash(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_transaction_receipt(self, txn_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Account state
    #
    def get_nonce(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_balance(self, account, block_number=None):
        return self.evm.head_state.get_balance(account)

    def get_code(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Transactions
    #
    def send_transaction(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    def estimate_gas(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    def call(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Filters
    #
    def new_block_filter(self, *args, **kwargs):
        raise NotImplementedError("Must be implemented by subclasses")

    def new_pending_transaction_filter(self, *args, **kwargs):
        raise NotImplementedError("Must be implemented by subclasses")

    def create_filter(self, from_block=None, to_block=None, address=None, topics=None):
        raise NotImplementedError("Must be implemented by subclasses")

    def delete_filter(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_filter_changes(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_filter_logs(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")
