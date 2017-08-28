import itertools
import copy

from cytoolz.dicttoolz import (
    dissoc,
    assoc,
)
from cytoolz.functoolz import (
    compose,
    partial,
)

from eth_utils import (
    decode_hex,
    int_to_big_endian,
    denoms,
    to_canonical_address,
    to_tuple,
    is_integer,
)

from eth_tester.backends.base import (
    BaseChainBackend,
)
from eth_tester.exceptions import (
    BlockNotFound,
    TransactionNotFound,
    UnknownFork,
)

from eth_tester.utils.encoding import (
    zpad,
)

from .factory import (
    fake_rlp_hash,
    make_genesis_block,
    make_block_from_parent,
    create_transaction,
    make_receipt,
)
from .serializers import (
    serialize_block,
    serialize_full_transaction,
    serialize_transaction_as_hash,
    serialize_receipt,
)


def _generate_dummy_address(idx):
    return to_canonical_address(
        decode_hex('0xabbacadaba') + zpad(int_to_big_endian(idx), 15)
    )


def _get_default_account_data(idx):
    return {
        'balance': 1000000 * denoms.ether,
        'code': b'',
        'nonce': 0,
        'storage': {},
    }


def get_default_alloc(num_accounts=10):
    return {
        _generate_dummy_address(idx): _get_default_account_data(idx)
        for idx
        in range(num_accounts)
    }


class MockBackend(BaseChainBackend):
    alloc = None
    blocks = None
    block = None
    receipts = None
    fork_blocks = None

    def __init__(self, alloc=None, genesis_block=None):
        if alloc is None:
            alloc = get_default_alloc()
        if genesis_block is None:
            genesis_block = make_genesis_block()

        self.fork_blocks = {}

        self.genesis_alloc = copy.deepcopy(alloc)
        self.genesis_block = copy.deepcopy(genesis_block)
        self.reset_to_genesis()

    #
    # Snapshot API
    #
    def take_snapshot(self):
        return copy.deepcopy({
            'alloc': self.alloc,
            'blocks': self.blocks,
            'block': self.block,
            'receipts': self.receipts,
        })

    def revert_to_snapshot(self, snapshot):
        self.alloc = snapshot['alloc']
        self.blocks = snapshot['blocks']
        self.block = snapshot['block']
        self.receipts = snapshot['receipts']

    def reset_to_genesis(self):
        self.alloc = self.genesis_alloc
        self.blocks = []
        self.block = self.genesis_block
        self.receipts = {}
        self.fork_blocks = {}

    #
    # Fork block numbers
    #
    def set_fork_block(self, fork_name, fork_block):
        self.fork_blocks[fork_name] = fork_block

    def get_fork_block(self, fork_name):
        try:
            return self.fork_blocks[fork_name]
        except KeyError:
            raise UnknownFork("Unknown fork: {0}".format(fork_name))

    #
    # Meta
    #
    def time_travel(self, timestamp):
        self.block['timestamp'] = timestamp

    #
    # Mining
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=None):
        for _ in range(num_blocks):
            block_to_mine = dissoc(self.block, 'hash')
            block_hash = fake_rlp_hash(block_to_mine)
            mined_block = assoc(block_to_mine, 'hash', block_hash)
            assign_block_info = compose(
                partial(assoc, key='block_number', value=mined_block['number']),
                partial(assoc, key='block_hash', value=mined_block['hash']),
            )
            mined_block['transactions'] = tuple(
                assign_block_info(transaction)
                for transaction
                in mined_block['transactions']
            )
            self.blocks.append(mined_block)
            self.block = make_block_from_parent(mined_block)
            yield block_hash

    #
    # Accounts
    #
    def get_accounts(self):
        return tuple(self.alloc.keys())

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transactions=False):
        if full_transactions:
            transaction_serializer = serialize_full_transaction
        else:
            transaction_serializer = serialize_transaction_as_hash

        if block_number == self.block['number']:
            block = self.block
        elif block_number == "latest":
            try:
                block = self.blocks[-1]
            except IndexError:
                block = self.block
        elif block_number == "pending":
            block = self.block
        elif block_number == "earliest":
            try:
                block = self.blocks[0]
            except IndexError:
                block = self.block
        elif is_integer(block_number):
            try:
                block = self.blocks[block_number]
            except IndexError:
                raise BlockNotFound("No block found for #{0}".format(block_number))
        else:
            raise Exception(
                "Invariant.  Unrecognized block number format: {0}".format(block_number)
            )

        return serialize_block(
            block,
            transaction_serializer=transaction_serializer,
            is_pending=(block['number'] == self.block['number']),
        )

    def get_block_by_hash(self, block_hash, full_transactions=False):
        if full_transactions:
            transaction_serializer = serialize_full_transaction
        else:
            transaction_serializer = serialize_transaction_as_hash

        for block in itertools.chain([self.block], reversed(self.blocks)):
            if block['hash'] == block_hash:
                block = block
                break
        else:
            raise BlockNotFound("No block found for hash: {0}".format(block_hash))

        return serialize_block(
            block,
            transaction_serializer=transaction_serializer,
            is_pending=(block['number'] == self.block['number']),
        )

    def _get_transaction_by_hash(self, transaction_hash):
        for block in itertools.chain([self.block], reversed(self.blocks)):
            for transaction_index, transaction in enumerate(reversed(block['transactions'])):
                if transaction['hash'] == transaction_hash:
                    return transaction, block, transaction_index
        else:
            raise TransactionNotFound(
                "No transaction found for hash: {0}".format(transaction_hash)
            )

    def get_transaction_by_hash(self, transaction_hash):
        transaction, block, transaction_index = self._get_transaction_by_hash(transaction_hash)
        return serialize_full_transaction(
            transaction,
            block,
            transaction_index,
            is_pending=(block['number'] == self.block['number']),
        )

    def get_transaction_receipt(self, transaction_hash):
        try:
            receipt = self.receipts[transaction_hash]
        except KeyError:
            raise TransactionNotFound(
                "No transaction found for hash: {0}".format(transaction_hash)
            )
        _, block, transaction_index = self._get_transaction_by_hash(transaction_hash)
        return serialize_receipt(
            receipt,
            block,
            transaction_index,
            is_pending=(block['number'] == self.block['number']),
        )

    #
    # Account state
    #
    def get_nonce(self, account, block_number=None):
        try:
            return self.alloc[account]['nonce']
        except KeyError:
            return 0

    def get_balance(self, account, block_number=None):
        try:
            return self.alloc[account]['balance']
        except KeyError:
            return 0

    def get_code(self, account, block_number=None):
        try:
            return self.alloc[account]['code']
        except KeyError:
            return 0

    #
    # Transactions
    #
    def send_transaction(self, transaction):
        full_transaction = create_transaction(
            transaction,
            self.block,
            len(self.block['transactions']) + 1,
            is_pending=True,
        )
        self.receipts[full_transaction['hash']] = make_receipt(
            full_transaction,
            self.block,
            len(self.block['transactions']),
        )
        self.block['transactions'].append(full_transaction)
        return full_transaction['hash']

    def estimate_gas(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    def call(self, transaction, block_number="latest"):
        raise NotImplementedError("Must be implemented by subclasses")
