from __future__ import absolute_import

import pkg_resources

from semantic_version import (
    Spec,
)

from eth_utils import (
    remove_0x_prefix,
    to_checksum_address,
    to_tuple,
    decode_hex,
)

from eth_tester.backends.base import BaseChainBackend
from eth_tester.backends.pyethereum.utils import (
    get_pyethereum_version,
    is_pyethereum16_available,
)

from .serializers import (
    serialize_txn_receipt,
    serialize_txn,
    serialize_txn_hash,
    serialize_block,
    serialize_log,
)


#
# Internal getters for EVM objects
#
def _get_transaction_by_hash(evm, txn_hash):
    # TODO: Add caching.
    txn_hash_as_bytes = decode_hex(txn_hash)

    for block in reversed(evm.blocks):
        for index, candidate in enumerate(block.get_transaction_hashes()):
            if candidate == txn_hash_as_bytes:
                transaction = block.transaction_list[index]
                return block, transaction, index
    else:
        raise ValueError("Transaction not found")


def _get_block_by_number(evm, block_number="latest"):
    if block_number == "latest":
        if len(evm.blocks) == 0:
            raise ValueError("Chain has no blocks")
        elif len(evm.blocks) == 1:
            return evm.blocks[0]
        else:
            return evm.blocks[-2]
    elif block_number == "earliest":
        return evm.blocks[0]
    elif block_number == "pending":
        return evm.block
    else:
        if block_number >= len(evm.blocks):
            raise ValueError("Block number is longer than current chain.")
        return evm.blocks[block_number]


def _get_block_by_hash(evm, block_hash):
    # TODO: Add caching.
    block_hash_as_bytes = decode_hex(block_hash)

    for block in reversed(evm.blocks):
        if block.hash == block_hash_as_bytes:
            return block
    else:
        raise ValueError("Could not find block for provided hash")


class PyEthereum16Backend(BaseChainBackend):
    tester_module = None

    def __init__(self):
        if not is_pyethereum16_available():
            version = get_pyethereum_version()
            if version is None:
                raise pkg_resources.DistributionNotFound(
                    "The `ethereum` package is not available.  The "
                    "`PyEthereum16Backend` requires a 1.6.x version of the "
                    "ethereum package to be installed."
                )
            elif version not in Spec('>=1.6.0,<1.7.0'):
                raise pkg_resources.DistributionNotFound(
                    "The `PyEthereum16Backend` requires a 1.6.x version of the "
                    "`ethereum` package.  Found {0}".format(version)
                )
        from ethereum import tester
        self.tester_module = tester
        self.evm = tester.state()

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
    def get_block_by_number(self, block_number, full_transactions=False):
        if full_transactions:
            txn_serialize_fn = serialize_txn
        else:
            txn_serialize_fn = serialize_txn_hash

        block = _get_block_by_number(
            self.evm,
            block_number,
            txn_serialize_fn,
        )
        return serialize_block(block)

    def get_block_by_hash(self, block_hash, full_transactions=False):
        if full_transactions:
            txn_serialize_fn = serialize_txn
        else:
            txn_serialize_fn = serialize_txn_hash

        block = _get_block_by_hash(
            self.evm,
            block_hash,
            txn_serialize_fn,
        )
        return serialize_block(block)

    def get_latest_block(self, full_transactions=False):
        if full_transactions:
            txn_serialize_fn = serialize_txn
        else:
            txn_serialize_fn = serialize_txn_hash

        block = _get_block_by_hash(
            self.evm,
            block_hash,
        )
        return serialize_block(self.evm.block, txn_serialize_fn)

    def get_transaction_by_hash(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_transaction_receipt(self, txn_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Account state
    #
    def get_nonce(self, account, block_number=None):
        if block_number is not None:
            raise NotImplementedError("Not yet handled")
        block = self.evm.block
        return block.get_nonce(remove_0x_prefix(account))

    def get_balance(self, account, block_number=None):
        if block_number is not None:
            raise NotImplementedError("Not yet handled")
        block = self.evm.block
        return block.get_balance(remove_0x_prefix(account))

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
