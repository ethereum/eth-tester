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
    is_pyethereum16_available,
)

from eth_tester.utils.accounts import (
    private_key_to_address,
)

from .serializers import (
    serialize_block,
    serialize_transaction,
    serialize_transaction_hash,
    serialize_transaction_receipt,
)
from .validation import (
    validate_transaction,
)


#
# Internal getters for EVM objects
#
def _get_transaction_by_hash(evm, transaction_hash, mined=True):
    # first check unmined transactions
    for index, candidate in enumerate(evm.block.get_transaction_hashes()):
        if candidate == transaction_hash:
            transaction = evm.block.transaction_list[index]
            return evm.block, transaction, index

    # then check work backwards through the blocks looking for mined transactions.
    for block in reversed(evm.blocks[:-1]):
        for index, candidate in enumerate(block.get_transaction_hashes()):
            if candidate == transaction_hash:
                transaction = block.transaction_list[index]
                return block, transaction, index
    else:
        raise TransactionNotFound(
            "No transaction found for transaction hash {0}".format(
                encode_hex(transaction_hash),
            )
        )


def _get_block_by_number(evm, block_number="latest"):
    if block_number == "latest":
        if len(evm.blocks) == 0:
            raise BlockNotFound("Chain has no blocks")
        elif len(evm.blocks) == 1:
            return evm.blocks[0]
        else:
            return evm.blocks[-2]
    elif block_number == "earliest":
        return evm.blocks[0]
    elif block_number == "pending":
        return evm.block
    elif block_number == evm.block.number:
        return evm.block
    else:
        if block_number >= len(evm.blocks):
            raise BlockNotFound("Block number is longer than current chain.")
        return evm.blocks[block_number]


def _get_block_by_hash(evm, block_hash):
    block_hash = block_hash

    for block in reversed(evm.blocks):
        if block.hash == block_hash:
            return block
    else:
        if block_hash == evm.block.hash:
            return evm.block
        raise BlockNotFound("Could not find block for provided hash")


def _send_evm_transaction(tester_module, evm, transaction):
    from ethereum import tester

    try:
        # record the current gas price so that it can be reset after sending
        # the transaction.
        pre_transaction_gas_price = tester.gas_price
        pre_transaction_gas_limit = tester.gas_limit
        # set the evm gas price to the one specified by the transaction.
        tester.gas_price = transaction.get('gas_price', tester.gas_price)
        tester.gas_limit = transaction['gas']

        # get the private key of the sender.
        try:
            sender = tester.keys[tester.accounts.index(transaction['from'])]
        except ValueError:
            sender = evm.extra_accounts[transaction['from']]

        output = evm.send(
            sender=sender,
            to=transaction.get('to', b''),
            value=transaction.get('value', 0),
            evmdata=transaction.get('data', b''),
        )
    finally:
        # revert the tester gas price back to the original value.
        tester.gas_price = pre_transaction_gas_price
        tester.gas_limit = pre_transaction_gas_limit

    return output


def _estimate_evm_transaction(tester_module, evm, transaction):
    transaction_for_estimate = assoc(transaction, 'gas', 50000000)
    return _send_evm_transaction(tester_module, evm, transaction_for_estimate)


def _call_evm_transaction(tester_module, evm, transaction):
    if 'gas' not in transaction:
        transaction_for_call = assoc(transaction, 'gas', 50000000)
    else:
        transaction_for_call = transaction
    return _send_evm_transaction(tester_module, evm, transaction_for_call)


class PyEthereum16Backend(BaseChainBackend):
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
        self.reset_to_genesis()

    #
    # Fork Rules
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
    # Snapshots
    #
    def take_snapshot(self):
        return (self.evm.block.number, self.evm.snapshot())

    def revert_to_snapshot(self, snapshot):
        from ethereum import tester

        block_number, snapshot_data = snapshot

        # Remove all blocks after our saved block number.
        del self.evm.blocks[block_number:]

        self.evm.revert(snapshot_data)

        if self.evm.blocks:
            parent = self.evm.blocks[-1]
            block = self.evm.block.init_from_parent(
                parent,
                tester.DEFAULT_ACCOUNT,
                timestamp=parent.timestamp + 6,
            )

            self.evm.block = block
            self.evm.blocks.append(block)
        else:
            self.evm.blocks.append(self.evm.block)

    def reset_to_genesis(self):
        from ethereum import tester
        self.evm = tester.state()
        self.evm.extra_accounts = {}
        self.mine_blocks()

    #
    # Meta
    #
    def time_travel(self, to_timestamp):
        from ethereum import tester

        self.evm.block.finalize()
        self.evm.block.commit_state()
        self.evm.db.put(
            self.evm.block.hash,
            rlp.encode(self.evm.block),
        )

        block = self.evm.block.init_from_parent(
            self.evm.block,
            tester.DEFAULT_ACCOUNT,
            timestamp=to_timestamp,
        )

        self.evm.block = block
        self.evm.blocks.append(block)
        return to_timestamp

    #
    # Mining
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=None):
        from ethereum import tester

        if coinbase is None:
            coinbase = tester.DEFAULT_ACCOUNT

        self.evm.mine(
            number_of_blocks=num_blocks,
            coinbase=coinbase,
        )
        for block in self.evm.blocks[-1 * num_blocks - 1:-1]:
            yield block.hash

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        from ethereum import tester

        for account in tester.accounts:
            yield account

        for account in self.evm.extra_accounts.keys():
            yield account

    def add_account(self, private_key):
        account = private_key_to_address(private_key)
        self.evm.extra_accounts[account] = private_key

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash

        block = _get_block_by_number(
            self.evm,
            block_number,
        )
        is_pending = block == self.evm.block
        return serialize_block(block, transaction_serialize_fn, is_pending)

    def get_block_by_hash(self, block_hash, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash

        block = _get_block_by_hash(
            self.evm,
            block_hash,
        )
        is_pending = block == self.evm.block
        return serialize_block(block, transaction_serialize_fn, is_pending)

    def get_latest_block(self, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash

        return serialize_block(self.evm.block, transaction_serialize_fn)

    def get_transaction_by_hash(self, transaction_hash):
        block, transaction, transaction_index = _get_transaction_by_hash(
            self.evm,
            transaction_hash,
        )
        is_pending = block.number == self.evm.block.number
        return serialize_transaction(block, transaction, transaction_index, is_pending)

    def get_transaction_receipt(self, transaction_hash):
        block, transaction, transaction_index = _get_transaction_by_hash(
            self.evm,
            transaction_hash,
        )
        is_pending = block.number == self.evm.block.number
        return serialize_transaction_receipt(block, transaction, transaction_index, is_pending)

    #
    # Account state
    #
    def get_nonce(self, account, block_number="latest"):
        block = _get_block_by_number(self.evm, block_number)
        return block.get_nonce(remove_0x_prefix(account))

    def get_balance(self, account, block_number="latest"):
        block = _get_block_by_number(self.evm, block_number)
        return block.get_balance(remove_0x_prefix(account))

    def get_code(self, account, block_number="latest"):
        block = _get_block_by_number(self.evm, block_number)
        return block.get_code(remove_0x_prefix(account))

    #
    # Transactions
    #
    def send_transaction(self, transaction):
        from ethereum import tester
        validate_transaction(transaction)
        _send_evm_transaction(
            tester_module=tester,
            evm=self.evm,
            transaction=transaction,
        )
        return self.evm.last_tx.hash

    def call(self, transaction, block_number="latest"):
        from ethereum import tester
        validate_transaction(transaction)

        if block_number != "latest":
            raise NotImplementedError("Block number must be 'latest'.")

        snapshot = self.take_snapshot()
        output = _call_evm_transaction(
            tester_module=tester,
            evm=self.evm,
            transaction=transaction,
        )
        self.revert_to_snapshot(snapshot)
        return output

    def estimate_gas(self, transaction):
        from ethereum import tester
        validate_transaction(transaction)

        snapshot = self.take_snapshot()
        _estimate_evm_transaction(
            tester_module=tester,
            evm=self.evm,
            transaction=transaction,
        )
        txn_hash = self.evm.last_tx.hash
        receipt = self.get_transaction_receipt(txn_hash)
        self.revert_to_snapshot(snapshot)
        return receipt['gas_used']
