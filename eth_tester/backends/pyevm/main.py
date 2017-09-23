from __future__ import absolute_import

import pkg_resources
import time

from .serializers import (
    serialize_block,
)
from .utils import is_pyevm_available


ZERO_ADDRESS = 20 * b'\x00'
ZERO_HASH32 = 32 * b'\x00'


EMPTY_RLP_LIST_HASH = b'\x1d\xccM\xe8\xde\xc7]z\xab\x85\xb5g\xb6\xcc\xd4\x1a\xd3\x12E\x1b\x94\x8at\x13\xf0\xa1B\xfd@\xd4\x93G'  # noqa: E501
BLANK_ROOT_HASH = b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n\x5bH\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!'  # noqa: E501


GENESIS_BLOCK_NUMBER = 0
GENESIS_DIFFICULTY = 131072
GENESIS_GAS_LIMIT = 3141592
GENESIS_PARENT_HASH = ZERO_HASH32
GENESIS_COINBASE = ZERO_ADDRESS
GENESIS_NONCE = b'\x00\x00\x00\x00\x00\x00\x00*'  # 42 encoded as big-endian-integer
GENESIS_MIX_HASH = ZERO_HASH32
GENESIS_EXTRA_DATA = b''
GENESIS_INITIAL_ALLOC = {}


def setup_tester_chain():
    from evm.vm.flavors import MainnetTesterChain

    chain = MainnetTesterChain.initialize()
    return chain


class PyEVMBackend(object):
    def __init__(self):
        if not is_pyevm_available():
            raise pkg_resources.DistributionNotFound(
                "The `py-evm` package is not available.  The "
                "`PyEVMBackend` requires py-evm to be installed and importable. "
                "Please install the `py-evm` library."
            )

        self.reset_to_genesis()

    #
    # Snapshot API
    #
    def take_snapshot(self):
        raise NotImplementedError("Must be implemented by subclasses")

    def revert_to_snapshot(self, snapshot):
        raise NotImplementedError("Must be implemented by subclasses")

    def reset_to_genesis(self):
        self.chain = setup_tester_chain()

    #
    # Fork block numbers
    #
    def set_fork_block(self, fork_name, fork_block):
        # TODO: actually do something here
        return
        raise NotImplementedError("Must be implemented by subclasses")

    def get_fork_block(self, fork_name):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Meta
    #
    def time_travel(self, timestamp):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Mining
    #
    def mine_blocks(self, num_blocks=1, coinbase=None):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Accounts
    #
    def get_accounts(self):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transaction=True):
        block = self.chain.get_canonical_block_by_number(block_number)
        return serialize_block(block)

    def get_block_by_hash(self, block_hash, full_transaction=True):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_transaction_by_hash(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_transaction_receipt(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Account state
    #
    def get_nonce(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_balance(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

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
