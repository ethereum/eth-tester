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

from eth_tester.constants import (
    FORK_HOMESTEAD,
    FORK_DAO,
    FORK_ANTI_DOS,
    FORK_STATE_CLEANUP,
)

from eth_tester.utils.accounts import (
    private_key_to_address,
)

class PyEthereum20Backend(BaseChainBackend):
    tester_module = None

    def __init__(self):
        if not is_pyethereum20_available():
            version = get_pyethereum_version()
            if version is None:
                raise pkg_resources.DistributionNotFound(
                    "The `ethereum` package is not available.  The "
                    "`PyEthereum20Backend` requires a 2.0.0+ version of the "
                    "ethereum package to be installed."
                )
            elif version not in Spec('>=2.0.0,<2.2.0'):
                raise pkg_resources.DistributionNotFound(
                    "The `PyEthereum20Backend` requires a 2.0.0+ version of the "
                    "`ethereum` package.  Found {0}".format(version)
                )
        from ethereum.tools import tester
        self.tester_module = tester
        self.evm = tester.Chain()
        # NOTE: This is probably bad, but it solves get/set_fork_block() issues
        self.evm.env = self.tester_module.get_env(None)
    #
    # Snapshot API
    #
    def take_snapshot(self):
        return self.evm.snapshot()

    def revert_to_snapshot(self, snapshot):
        return self.evm.revert(snapshot)

    def reset_to_genesis(self):
        # NOTE: Not sure if this is right,
        #       but it does reset to genesis
        self.evm = tester.Chain()

    #
    # Fork block numbers
    #
    def set_fork_block(self, fork_name, fork_block):
        if fork_name == FORK_HOMESTEAD:
            self.evm.env.config['HOMESTEAD_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_DAO:
            self.evm.env.config['DAO_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_ANTI_DOS:
            self.evm.env.config['ANTI_DOS_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_STATE_CLEANUP:
            self.evm.env.config['CLEARING_FORK_BLKNUM'] = fork_block
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))

    def get_fork_block(self, fork_name):
        if fork_name == FORK_HOMESTEAD:
            return self.evm.env.config['HOMESTEAD_FORK_BLKNUM']
        elif fork_name == FORK_DAO:
            return self.evm.env.config['DAO_FORK_BLKNUM']
        elif fork_name == FORK_ANTI_DOS:
            return self.evm.env.config['ANTI_DOS_FORK_BLKNUM']
        elif fork_name == FORK_STATE_CLEANUP:
            return self.evm.env.config['CLEARING_FORK_BLKNUM']
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))

    #
    # Meta
    #
    def time_travel(self, to_timestamp):
        while to_timestamp >= self.get_state().timestamp:
            self.mine_blocks()

    #
    # Mining
    #
    def mine_blocks(self, num_blocks=1, coinbase=None):
        if not coinbase:
            coinbase=self.get_accounts()[0]
        block_hashes = []
        for _ in range(num_blocks):
            block_hashes.append(
                    self.evm.mine(number_of_blocks=num_blocks, coinbase=coinbase)
                )
        return block_hashes

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        # NOTE: Had issue with this, expected bytestrings
        return self.tester_module.accounts

    # NOTE: Added this
    def get_key_for_account(self, account):
        index = self.tester_module.accounts.index(account)
        return self.tester_module.keys[index]

    def add_account(self, private_key):
        account = private_key_to_address(private_key)
        self.tester_module.accounts.append(account)
        self.tester_module.keys.append(private_key)

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transaction=True):
        # TODO: Work on implementation of full_transaction
        return self.evm.chain.get_block_by_number(block_number)

    def get_block_by_hash(self, block_hash, full_transaction=True):
        # TODO: Work on implementation of full_transaction
        return self.evm.chain.get_block(block_hash)

    # NOTE: Added as a helper, might be more broadly useful
    def get_state(self, block_hash=None, block_number=None):
        # Ignore block_hash if block_number is provided
        # (Avoids handling additional case if both are provided)
        if block_number and block_number is not "latest":
            block = self.get_block_by_number(block_number)
            assert block is not None, "Could not find blocknum {}".format(block_number)
            block_hash = block.hash
        if block_hash:
            # Compute state at specific block
            return self.evm.mk_poststate_of_blockhash(block_hash)
        else:
            # Return the most recent block if not specified
            return self.evm.head_state

    def get_transaction_by_hash(self, transaction_hash):
        return self.evm.get_transaction(transaction_hash)

    def get_transaction_receipt(self, transaction_hash):
        transaction = self.get_transaction_by_hash(transaction_hash)
        state = self.get_state(block_hash=transaction.block_hash)
        return state.receipts

    #
    # Account state
    #
    def get_nonce(self, account, block_number=None):
        state = self.get_state(block_number=block_number)
        return state.get_nonce(account)

    def get_balance(self, account, block_number=None):
        state = self.get_state(block_number=block_number)
        return state.get_balance(account)

    def get_code(self, account, block_number=None):
        state = self.get_state(block_number=block_number)
        return state.get_code(account)

    #
    # Transactions
    #
    def send_transaction(self, transaction):
        # TODO: Needs to handle given sender
        #try this sender = tester.keys[tester.accounts.index(transaction['from'])]
        print(transaction.keys())
        sender = self.get_key_for_account(transaction['from'])
        self.evm.tx(sender=sender, data=transaction['data'], \
                    value=transaction['value'], to=transaction['to'], \
                    startgas=transaction['gas'])
        return self.evm.last_tx.hash

    def estimate_gas(self, transaction):
        snapshot = self.take_snapshot()
        self.send_transaction(transaction)
        gas_used = self.evm.last_gas_used()
        self.revert_to_snapshot(snapshot)
        return gas_used

    def call(self, transaction, block_number="latest"):
        # Implement with block_number
        snapshot = self.take_snapshot()
        self.send_transaction(transaction)
        receipt = self.get_transaction_receipt(transaction.hash)
        self.revert_to_snapshot(snapshot)
        # NOTE: Not sure if this what we should return
        return receipt
