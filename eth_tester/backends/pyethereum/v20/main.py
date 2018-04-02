from __future__ import absolute_import

import pkg_resources

from semantic_version import (
    Spec,
)

import rlp

from eth_utils import (
    is_integer,
    to_dict,
    to_tuple,
    to_wei,
)

from eth_tester.constants import (
    FORK_HOMESTEAD,
    FORK_DAO,
    FORK_SPURIOUS_DRAGON,
    FORK_TANGERINE_WHISTLE,
    FORK_BYZANTIUM,
)
from eth_tester.exceptions import (
    BlockNotFound,
    TransactionNotFound,
    UnknownFork,
    TransactionFailed,
)
from eth_tester.backends.base import BaseChainBackend
from eth_tester.backends.pyethereum.utils import (
    get_pyethereum_version,
    is_pyethereum21_available,
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
from eth_tester.utils.formatting import (
    replace_exceptions,
)


if is_pyethereum21_available():
    from ethereum.tools.tester import (
        TransactionFailed as Pyeth21TransactionFailed,
    )
else:
    Pyeth21TransactionFailed = None


SUPPORTED_FORKS = {
    FORK_HOMESTEAD,
    FORK_DAO,
    FORK_SPURIOUS_DRAGON,
    FORK_TANGERINE_WHISTLE,
    FORK_BYZANTIUM,
}


def _get_block_by_number(evm, block_number):
    if is_integer(block_number):
        if block_number > evm.block.number:
            raise BlockNotFound("Block number is longer than current chain.")

        block = evm.chain.get_block_by_number(block_number)
        if block is None:
            raise BlockNotFound("Block not found for block number: {0}".format(block_number))
    elif block_number == "pending":
        block = evm.block  # Get pending block
    elif block_number == "latest":
        block = evm.chain.head  # Get latest block added to chain
    elif block_number == "earliest":
        block = evm.chain.genesis
    else:
        raise BlockNotFound(
            "Block identifier was not in a recognized format: Got "
            "{0}".format(block_number)
        )

    return block


def _get_block_by_hash(evm, block_hash):
    block_by_hash = evm.chain.get_block(block_hash)
    if block_by_hash is None or block_by_hash.number == evm.block.number:
        raise BlockNotFound(
            "Block with hash {0} not found on chain".format(block_hash)
        )

    block_by_number = _get_block_by_number(evm, block_by_hash.number)
    if block_by_hash.hash != block_by_number.hash:
        raise BlockNotFound(
            "Block with hash {0} not found on chain".format(block_hash)
        )
    return block_by_hash


EMPTY_RECEIPTS_ROOT = b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n\x5bH\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!'  # noqa: E501


def _get_state_by_block_hash(evm, block_hash, ephemeral=False):
    from ethereum.messages import Receipt
    if block_hash == evm.block.hash:
        block = evm.block
        base_state = evm.head_state
    else:
        block = _get_block_by_hash(evm, block_hash)
        base_state = evm.chain.mk_poststate_of_blockhash(block_hash)

    if ephemeral:
        state = base_state.ephemeral_clone()
    else:
        state = base_state

    if block.header.receipts_root != EMPTY_RECEIPTS_ROOT:
        receipt_list = rlp.decode(evm.chain.db.get(block.header.receipts_root))
        state.receipts = [
            rlp.decode(rlp.encode(receipt_items), Receipt)
            for receipt_items
            in receipt_list
        ]
    return state


def _get_state_by_block_number(evm, block_number, ephemeral=False):
    block = _get_block_by_number(evm, block_number)
    return _get_state_by_block_hash(evm, block.hash, ephemeral)


def _get_transaction_by_hash(evm, transaction_hash):
    for index, candidate in enumerate(evm.block.transactions):
        if transaction_hash == candidate.hash:
            return (
                evm.block,
                candidate,
                index,
                True,
            )

    for block_number in range(evm.chain.head.number, -1, -1):
        block = _get_block_by_number(evm, block_number)
        for index, transaction in enumerate(block.transactions):
            if transaction.hash == transaction_hash:
                return block, transaction, index, False
    else:
        raise TransactionNotFound(
            "Transaction with hash {0} not found".format(
                transaction_hash,
            )
        )


def _get_key_for_account(evm, account):
    from ethereum.tools import tester
    if account in tester.accounts:
        index = tester.accounts.index(account)
        return tester.keys[index]
    elif account in evm.extra_accounts:
        return evm.extra_accounts[account]
    else:
        raise KeyError("Account {:#x} not found in known accounts")


@to_dict
def _format_transaction(evm, transaction):
    if 'from' in transaction:
        yield 'sender', _get_key_for_account(evm, transaction['from'])
    if 'gas' in transaction:
        yield 'startgas', transaction['gas']
    if 'gas_price' in transaction:
        yield 'gasprice', transaction['gas_price']

    if 'to' in transaction:
        yield 'to', transaction['to']
    else:
        yield 'to', b''

    if 'value' in transaction:
        yield 'value', transaction['value']
    if 'data' in transaction:
        yield 'data', transaction['data']


def _send_transaction(evm, raw_transaction):
    validate_transaction(raw_transaction)

    transaction = _format_transaction(evm, raw_transaction)
    output = evm.tx(**transaction)
    return output


class PyEthereum21Backend(BaseChainBackend):
    def __init__(self):
        if not is_pyethereum21_available():
            version = get_pyethereum_version()
            if version is None:
                raise pkg_resources.DistributionNotFound(
                    "The `ethereum` package is not available.  The "
                    "`PyEthereum21Backend` requires a 2.0.0+ version of the "
                    "ethereum package to be installed."
                )
            elif version not in Spec('>=2.0.0,<2.2.0'):
                raise pkg_resources.DistributionNotFound(
                    "The `PyEthereum21Backend` requires a 2.0.0+ version of the "
                    "`ethereum` package.  Found {0}".format(version)
                )
        self.fork_blocks = {}
        self.reset_to_genesis()

    #
    # Fork block numbers
    #
    def get_supported_forks(self):
        return SUPPORTED_FORKS

    def set_fork_block(self, fork_name, fork_block):
        if fork_name == FORK_HOMESTEAD:
            self.evm.chain.env.config['HOMESTEAD_FORK_BLKNUM'] = fork_block or 0
        elif fork_name == FORK_DAO:
            # NOTE: REALLY WEIRD HACK to get the dao_fork_blk to accept block 0
            if not fork_block:
                self.evm.chain.env.config['DAO_FORK_BLKNUM'] = 999999999999999
            else:
                self.evm.chain.env.config['DAO_FORK_BLKNUM'] = fork_block or 0
        elif fork_name == FORK_SPURIOUS_DRAGON:
            # pyethereum seems to use both of these.
            self.evm.chain.env.config['ANTI_DOS_FORK_BLKNUM'] = fork_block or 0
            self.evm.chain.env.config['SPURIOUS_DRAGON_FORK_BLKNUM'] = fork_block or 0
        elif fork_name == FORK_TANGERINE_WHISTLE:
            self.evm.chain.env.config['CLEARING_FORK_BLKNUM'] = fork_block or 0
        elif fork_name == FORK_BYZANTIUM:
            self.evm.chain.env.config['METROPOLIS_FORK_BLKNUM'] = fork_block or 0
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))

        self.fork_blocks[fork_name] = fork_block

    def get_fork_block(self, fork_name):
        if fork_name in self.get_supported_forks():
            return self.fork_blocks.get(fork_name)
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))

    #
    # Snapshot API
    #
    def take_snapshot(self):
        self.evm.head_state.commit()
        block = _get_block_by_number(self.evm, 'latest')
        return block.hash

    def revert_to_snapshot(self, snapshot):
        self.evm.change_head(snapshot)

        latest_state = _get_state_by_block_hash(self.evm, snapshot)
        if latest_state.block_number > 0:
            latest_state.block_number += 1

        self.evm.chain.state = latest_state
        self.evm.chain.head_hash = snapshot

    def reset_to_genesis(self):
        from ethereum.tools import tester
        self.evm = tester.Chain()
        self.evm = tester.Chain(alloc={
            account: {'balance': to_wei(1000000, 'ether')}
            for account
            in tester.accounts
        })
        self.evm.extra_accounts = {}

    #
    # Meta
    #
    def time_travel(self, to_timestamp):
        assert self.evm.block.header.timestamp < to_timestamp
        self.evm.block.header.timestamp = to_timestamp - 1
        self.mine_blocks()

    #
    # Mining
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=None):
        if not coinbase:
            coinbase = self.get_accounts()[0]

        from ethereum.common import mk_receipt_sha

        for _ in range(num_blocks):
            receipts = self.evm.head_state.receipts
            block = self.evm.mine(coinbase=coinbase)
            if block is None:
                # earlier versions of pyethereum21 didn't return the block.
                block = _get_block_by_number(self.evm, self.evm.block.number - 1)

            receipts_root = mk_receipt_sha(receipts)
            self.evm.chain.db.put(receipts_root, rlp.encode(receipts))

            yield block.hash

    #
    # Accounts
    #
    def get_key_for_account(self, account):
        from ethereum.tools import tester
        if account in tester.accounts:
            index = tester.accounts.index(account)
            return tester.keys[index]
        elif account in self.evm.extra_accounts:
            return self.evm.extra_accounts[account]
        else:
            raise KeyError("Account {:#x} not found in known accounts")

    @to_tuple
    def get_accounts(self):
        from ethereum.tools import tester
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
        block = _get_block_by_number(self.evm, block_number)

        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash

        is_pending = block == self.evm.block
        return serialize_block(self.evm, block, transaction_serialize_fn, is_pending)

    def get_block_by_hash(self, block_hash, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash

        block = _get_block_by_hash(self.evm, block_hash)
        assert block is not None, "Block not found! Given {:#x}".format(block_hash)

        is_pending = block == self.evm.block
        return serialize_block(self.evm, block, transaction_serialize_fn, is_pending)

    def get_transaction_by_hash(self, transaction_hash):
        block, transaction, transaction_index, is_pending = _get_transaction_by_hash(
            self.evm,
            transaction_hash,
        )
        return serialize_transaction(block, transaction, transaction_index, is_pending)

    def get_transaction_receipt(self, transaction_hash):
        block, transaction, transaction_index, is_pending = _get_transaction_by_hash(
            self.evm,
            transaction_hash,
        )
        state = _get_state_by_block_hash(self.evm, block.hash)
        return serialize_transaction_receipt(
            block,
            transaction,
            state.receipts[transaction_index],
            transaction_index,
            is_pending,
        )

    #
    # Account state
    #
    # NOTE: Added as a helper, might be more broadly useful
    def get_nonce(self, account, block_number="latest"):
        state = _get_state_by_block_number(self.evm, block_number)
        return state.get_nonce(account)

    def get_balance(self, account, block_number="latest"):
        state = _get_state_by_block_number(self.evm, block_number)
        return state.get_balance(account)

    def get_code(self, account, block_number="latest"):
        state = _get_state_by_block_number(self.evm, block_number)
        return state.get_code(account)

    #
    # Transactions
    #
    def send_raw_transaction(self, raw_transaction):
        from ethereum.transactions import Transaction
        rlp_transaction = rlp.decode(raw_transaction, Transaction)
        self.evm.direct_tx(rlp_transaction)
        return self.evm.last_tx.hash

    def send_transaction(self, transaction):
        _send_transaction(self.evm, transaction)
        return self.evm.last_tx.hash

    def send_signed_transaction(self, transaction):
        raise NotImplementedError("Not implemented in the PyEthereum21Backend backend")

    @replace_exceptions({Pyeth21TransactionFailed: TransactionFailed})
    def estimate_gas(self, transaction):
        snapshot = self.take_snapshot()
        _send_transaction(self.evm, transaction)
        gas_used = self.evm.head_state.receipts[-1].gas_used
        self.revert_to_snapshot(snapshot)
        return gas_used

    @replace_exceptions({Pyeth21TransactionFailed: TransactionFailed})
    def call(self, transaction, block_number="latest"):
        from ethereum.messages import apply_message

        if isinstance(block_number, bytes):
            state = self.evm.chain.mk_poststate_of_blockhash(block_number)
        elif isinstance(block_number, int) or isinstance(block_number, str):
            block = _get_block_by_number(self.evm, block_number)
            state = self.evm.chain.mk_poststate_of_blockhash(block.hash)
        else:
            raise BlockNotFound("Invalid block identifer.")

        output = apply_message(
            state,
            sender=transaction['from'],
            to=transaction['to'],
            code_address=transaction['to'],
            data=transaction['data'],
            gas=transaction['gas'],
        )
        if output is None:
            raise TransactionFailed
        return output
