from __future__ import absolute_import

import pkg_resources

from semantic_version import (
    Spec,
)

from cytoolz.dicttoolz import (
    assoc,
)

import rlp

from eth_utils import (
    remove_0x_prefix,
    to_tuple,
    encode_hex,
)

from eth_tester.constants import (
    FORK_HOMESTEAD,
    FORK_DAO,
    FORK_ANTI_DOS,
    FORK_STATE_CLEANUP,
)
from eth_tester.exceptions import (
    BlockNotFound,
    TransactionNotFound,
    UnknownFork,
)
from eth_tester.backends.base import BaseChainBackend
from eth_tester.backends.pyethereum.utils import (
    get_pyethereum_version,
    is_pyethereum20_available,
)

from eth_tester.utils.accounts import (
    private_key_to_address,
)

from eth_tester.backends.pyethereum.serializers import (
    serialize_block,
    serialize_transaction,
    serialize_transaction_hash,
    serialize_transaction_receipt,
)
from eth_tester.backends.pyethereum.validation import (
    validate_transaction,
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
    #
    # Fork block numbers
    #
    def set_fork_block(self, fork_name, fork_block):
        if fork_name == FORK_HOMESTEAD:
            self.evm.chain.env.config['HOMESTEAD_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_DAO:
            self.evm.chain.env.config['DAO_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_ANTI_DOS:
            self.evm.chain.env.config['ANTI_DOS_FORK_BLKNUM'] = fork_block
        elif fork_name == FORK_STATE_CLEANUP:
            self.evm.chain.env.config['CLEARING_FORK_BLKNUM'] = fork_block
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))

    def get_fork_block(self, fork_name):
        if fork_name == FORK_HOMESTEAD:
            return self.evm.chain.env.config['HOMESTEAD_FORK_BLKNUM']
        elif fork_name == FORK_DAO:
            return self.evm.chain.env.config['DAO_FORK_BLKNUM']
        elif fork_name == FORK_ANTI_DOS:
            return self.evm.chain.env.config['ANTI_DOS_FORK_BLKNUM']
        elif fork_name == FORK_STATE_CLEANUP:
            return self.evm.chain.env.config['CLEARING_FORK_BLKNUM']
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))

    #
    # Snapshot API
    #
    def take_snapshot(self):
        block_number = self.evm.block.number
        return (block_number, self.evm.snapshot())

    def revert_to_snapshot(self, snapshot):
        snapshot_block_number, snapshot_data = snapshot
        # We need to remove blocks to revert past the current one
        if self.evm.block.number > snapshot_block_number:
            self.evm.change_head(self.get_block_by_number(snapshot_block_number))
        self.evm.revert(snapshot_data)

    def reset_to_genesis(self):
        self.evm = self.tester_module.Chain()
        self.mine_blocks()

    #
    # Meta
    #
    def time_travel(self, to_timestamp):
        # NOTE: Redo to mining a block with the new block timestamp
        while to_timestamp >= self.get_state().timestamp:
            self.mine_blocks()

    #
    # Mining
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=None):
        if not coinbase:
            coinbase=self.get_accounts()[0]
        # NOTE: Has a problem when using 'yield'
        block_hashes = self.evm.mine(number_of_blocks=num_blocks, coinbase=coinbase)
        if not isinstance(block_hashes, list):
            return [block_hashes] # So to_tuple works
        return block_hashes

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        # NOTE: Had issue with this, expected bytestrings
        return self.tester_module.accounts

    # NOTE: Added as a helper, might be more broadly useful
    def get_key_for_account(self, account):
        assert account in self.get_accounts(), "Account {} not in accounts".format(account)
        index = self.tester_module.accounts.index(account)
        return self.tester_module.keys[index]

    def add_account(self, private_key):
        account = private_key_to_address(private_key)
        if account not in self.get_accounts():
            self.tester_module.accounts.append(account)
            self.tester_module.keys.append(private_key)

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash
        if block_number == "pending":
            block = self.evm.block # Get pending block
        elif block_number == "latest":
            block = self.evm.chain.head # Get latest block added to chain
        else:
            block = self.evm.chain.get_block_by_number(block_number)
        assert block is not None, "Block not found! Given #{}".format(block_number)
        is_pending = block == self.evm.block
        # NOTE: Hack to compute total difficulty
        # NOTE: As far as I could tell, this didn't really do anything in 1.6
        setattr(block, 'chain_difficulty', lambda: 0)
        return serialize_block(block, transaction_serialize_fn, is_pending)

    def get_block_by_hash(self, block_hash, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash
        block = self.evm.chain.get_block(block_hash)
        assert block is not None, "Block not found! Given 0x{}".format(block_hash)
        is_pending = block == self.evm.block
        # NOTE: Hack to compute total difficulty
        # NOTE: As far as I could tell, this didn't really do anything in 1.6
        setattr(block, 'chain_difficulty', lambda: 0)
        return serialize_block(block, transaction_serialize_fn, is_pending)
    
    # NOTE: Added internal helper
    def _get_transaction_by_hash(self, transaction_hash):
        transaction = None
        # Start with unmined block
        for tx in self.evm.block.transactions:
            if transaction_hash == tx.hash:
                transaction = tx
                block = self.evm.block
                tx_index = block.transactions.index(transaction)
                is_pending = True
                receipt = self.evm.head_state.receipts[tx_index]

                break
        # Then check rest of chain
        if transaction is None:
            blknum, tx_index = self.evm.chain.get_tx_position(transaction_hash)
            block = self.get_block_by_number(blknum)
            transaction = block.transactions[index]
            is_pending = False
            receipt = self.get_state(block.hash).receipts[tx_index]


        # Exact format for serialize functions
        return (block, receipt), transaction, tx_index, is_pending

    def get_transaction_by_hash(self, transaction_hash):
        return serialize_transaction(*self._get_transaction_by_hash(transaction_hash))

    def get_transaction_receipt(self, transaction_hash):
        return serialize_transaction_receipt(*self._get_transaction_by_hash(transaction_hash))

    #
    # Account state
    #
    # NOTE: Added as a helper, might be more broadly useful
    def get_state(self, block_hash=None, block_number=None):
        # Ignore block_hash if block_number is provided
        # (Avoids handling additional case if both are provided)
        if block_number and block_number is not "latest":
            block = self.get_block_by_number(block_number)
            assert block is not None, "Could not find blocknum {}".format(block_number)
            block_hash = block.hash
        # Double check it's not the unmined block
        if block_hash and block_hash is not self.evm.block.hash:
            # Compute state at specific block
            return self.evm.chain.mk_poststate_of_blockhash(block_hash)
        else:
            # Return the most recent block if not specified
            return self.evm.head_state

    def get_nonce(self, account, block_number="latest"):
        state = self.get_state(block_number=block_number)
        return state.get_nonce(remove_0x_prefix(account))

    def get_balance(self, account, block_number="latest"):
        state = self.get_state(block_number=block_number)
        return state.get_balance(remove_0x_prefix(account))

    def get_code(self, account, block_number="latest"):
        state = self.get_state(block_number=block_number)
        return state.get_code(remove_0x_prefix(account))

    #
    # Transactions
    #
    def send_transaction(self, transaction):
        validate_transaction(transaction)
        # Need to readjust some transaction keynames for ethereum.tester
        if 'from' in transaction.keys():
            transaction['sender'] = self.get_key_for_account(transaction['from'])
            del transaction['from']
        if 'gas' in transaction.keys():
            transaction['startgas'] = transaction['gas']
            del transaction['gas']
        if 'gas_price' in transaction.keys():
            transaction['gasprice'] = transaction['gas_price']
            del transaction['gas_price']
        # Apply transaction
        self.evm.tx(**transaction)
        return self.evm.last_tx.hash

    def estimate_gas(self, transaction):
        validate_transaction(transaction)
        snapshot = self.take_snapshot()
        self.send_transaction(transaction)
        gas_used = self.evm.last_gas_used()
        self.revert_to_snapshot(snapshot)
        return gas_used

    def call(self, transaction, block_number="latest"):
        # Why? Just why
        if block_number != "latest":
            raise NotImplementedError("Block number must be 'latest'.")
        validate_transaction(transaction)
        snapshot = self.take_snapshot()
        tx_hash = self.send_transaction(transaction)
        receipt = self.get_transaction_receipt(tx_hash)
        self.revert_to_snapshot(snapshot)
        # NOTE: Not sure if this what we should return
        return receipt
