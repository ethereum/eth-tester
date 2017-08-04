from cytoolz.dicttoolz import (
    dissoc,
    assoc,
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
    fork_blocks = None

    def __init__(self, alloc=None, genesis_block=None):
        if alloc is None:
            alloc = get_default_alloc()
        if genesis_block is None:
            genesis_block = make_genesis_block()

        self.alloc = alloc
        self.blocks = []
        self.block = genesis_block
        self.fork_blocks = {}

    #
    # Snapshot API
    #
    def take_snapshot(self):
        raise NotImplementedError("Must be implemented by subclasses")

    def revert_to_snapshot(self, snapshot):
        raise NotImplementedError("Must be implemented by subclasses")

    def reset_to_genesis(self):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Fork block numbers
    #
    def set_fork_block(self, fork_name, fork_block):
        self.fork_blocks[fork_name] = fork_block

    def get_fork_block(self, fork_name):
        try:
            return self.fork_block[fork_name]
        except KeyError:
            raise UnknownFork("Unknown fork: {0}".format(fork_name))

    #
    # Meta
    #
    def time_travel(self, timestamp):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Mining
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=None):
        for _ in range(num_blocks):
            block_to_mine = dissoc(self.block, 'hash')
            block_hash = fake_rlp_hash(block_to_mine)
            mined_block = assoc(block_to_mine, 'hash', block_hash)
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
        if block_number == self.block['number']:
            return self.block
        elif block_number == "latest":
            try:
                return self.blocks[-1]
            except IndexError:
                raise BlockNotFound("No block found for #{0}".format(block_number))
        elif block_number == "pending":
            return self.block
        elif block_number == "earliest":
            try:
                return self.blocks[0]
            except IndexError:
                return self.block
        elif is_integer(block_number):
            try:
                return self.blocks[block_number]
            except IndexError:
                raise BlockNotFound("No block found for #{0}".format(block_number))
        else:
            raise Exception(
                "Invariant.  Unrecognized block number format: {0}".format(block_number)
            )

    def get_block_by_hash(self, block_hash, full_transactions=False):
        if self.block['hash'] == block_hash:
            return self.block
        for block in reversed(self.blocks):
            if block['hash'] == block_hash:
                return block
        else:
            raise BlockNotFound("No block found for hash: {0}".format(block_hash))

    def get_transaction_by_hash(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_transaction_receipt(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

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
        self.block['transactions'].append(full_transaction)
        return full_transaction['hash']

    def estimate_gas(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    def call(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")
