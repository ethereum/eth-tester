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
            # NOTE: REALLY WEIRD HACK to get the dao_fork_blk to accept block 0
            if not fork_block:
                self.evm.chain.env.config['DAO_FORK_BLKNUM'] = 999999999999999
            else:
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
            block = self._get_block_by_number(snapshot_block_number)
            self.evm.change_head(block)
        self.evm.revert(snapshot_data)

    def reset_to_genesis(self):
        self.evm = self.tester_module.Chain()
        # NOTE: don't need to mine the block here after reset
        #self.mine_blocks()
        # NOTE: reset keys back to starting 10 elements
        self.tester_module.accounts = self.tester_module.accounts[:-10]
        self.tester_module.keys = self.tester_module.keys[:-10]

    #
    # Meta
    #
    def time_travel(self, to_timestamp):
        assert self.evm.block.header.timestamp < to_timestamp
        self.evm.block.header.timestamp = to_timestamp-1
        self.mine_blocks()

    #
    # Mining
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=None):
        if not coinbase:
            coinbase = self.get_accounts()[0]
        # NOTE: Might solve the hack present in set_fork_block() above
        #if 0 <= abs(self.get_fork_block(FORK_DAO) - self.evm.block.number) < 10:
        #    self.evm.block.extra_data = encode_hex(self.evm.chain.env.config['DAO_FORK_BLKEXTRA'])

        for _ in range(num_blocks):
            block = self.evm.mine(coinbase=coinbase)
            yield block.hash

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        # NOTE: Had issue with this, expected bytestrings
        return self.tester_module.accounts

    # NOTE: Added as a helper, might be more broadly useful
    def get_key_for_account(self, account):
        assert account in self.get_accounts(), "Account {:#x} not in accounts".format(account)
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
    def _get_block_by_number(self, block_number):
        if block_number == "pending":
            block = self.evm.block # Get pending block
        elif block_number == "latest":
            block = self.evm.chain.head # Get latest block added to chain
        elif block_number == "earliest":
            block = self.evm.chain.genesis
        else:
            block = self.evm.chain.get_block_by_number(block_number)
        assert block is not None, "Block not found! Given {}".format(block_number)
        
        # NOTE: ethereum.tester doesn't have these as bytes sometimes
        if isinstance(block.nonce, str):
            block.nonce = block.nonce.encode('utf-8') # This is the empty string (unmined)
        if isinstance(block.extra_data, str):
            block.extra_data = block.extra_data.encode('utf-8') # This is unencoded
        return block
        
    def get_block_by_number(self, block_number, full_transactions=False):
        block = self._get_block_by_number(block_number)

        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash
        
        is_pending = block == self.evm.block
        return serialize_block(block, transaction_serialize_fn, is_pending)

    def get_block_by_hash(self, block_hash, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash
        
        block = self.evm.chain.get_block(block_hash)
        assert block is not None, "Block not found! Given {:#x}".format(block_hash)
        
        is_pending = block == self.evm.block
        return serialize_block(block, transaction_serialize_fn, is_pending)
    
    # Internal helper for obtaining transaction artifacts for serializer.py
    def _get_transaction_by_hash(self, transaction_hash):
        transaction = None
        # Start with unmined block
        for tx in self.evm.block.transactions:
            if transaction_hash == tx.hash:
                transaction = tx
                block = self.evm.block
                tx_index = block.transactions.index(transaction)
                is_pending = True
                # NOTE: Hack for serializers.py to work
                setattr(block, 'receipts', self.evm.head_state.receipts)
                # Receipt getter
                setattr(block, 'get_receipt', lambda tx_idx: getattr(block, 'receipts')[tx_idx])
                break

        # Then check rest of chain
        if transaction is None:
            blknum, tx_index = self.evm.chain.get_tx_position(transaction_hash)
            block = self._get_block_by_number(blknum)
            transaction = block.transactions[tx_index]
            is_pending = False
            state = self.get_state(block.hash)
            # NOTE: Hack for serializers.py to work
            #assert tx_index < len(state.receipts)
            setattr(block, 'receipts', state.receipts)
            # Receipt getter
            setattr(block, 'get_receipt', lambda tx_idx: getattr(block, 'receipts')[tx_idx])


        # Modified format for serialize functions (we combine blocks and receipts)
        return block, transaction, tx_index, is_pending

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
            block = self._get_block_by_number(block_number)
            assert block is not None, "Could not find blocknum {}".format(block_number)
            block_hash = block.hash
        # Double check it's not the unmined block
        if block_hash and block_hash is not self.evm.block.hash:
            # Compute state at specific block
            return self.evm.chain.mk_poststate_of_blockhash(block_hash).ephemeral_clone()
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
