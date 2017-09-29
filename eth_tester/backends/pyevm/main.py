from __future__ import absolute_import

import pkg_resources
import time
import warnings

from eth_utils import (
    encode_hex,
    int_to_big_endian,
    pad_left,
    to_dict,
    to_tuple,
    to_wei,
    is_integer,
)

from eth_keys import KeyAPI

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

from .serializers import (
    serialize_block,
    serialize_transaction,
    serialize_transaction_receipt,
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


SUPPORTED_FORKS = {FORK_HOMESTEAD, FORK_DAO, FORK_ANTI_DOS}


def get_default_account_state():
    return {
        'balance': to_wei(1000000, 'ether'),
        'storage': {},
        'code': b'',
        'nonce': 0,
    }


@to_tuple
def get_default_account_keys():
    keys = KeyAPI()

    for i in range(1, 11):
        pk_bytes = pad_left(int_to_big_endian(i), 32, b'\x00')
        private_key = keys.PrivateKey(pk_bytes)
        yield private_key


@to_dict
def generate_genesis_state(account_keys):
    for private_key in account_keys:
        account_state = get_default_account_state()
        yield private_key.public_key.to_canonical_address(), account_state


def get_default_genesis_params():
    genesis_params = {
        "bloom": 0,
        "coinbase": GENESIS_COINBASE,
        "difficulty": GENESIS_DIFFICULTY,
        "extra_data": GENESIS_EXTRA_DATA,
        "gas_limit": GENESIS_GAS_LIMIT,
        "gas_used": 0,
        "mix_hash": GENESIS_MIX_HASH,
        "nonce": GENESIS_NONCE,
        "block_number": GENESIS_BLOCK_NUMBER,
        "parent_hash": GENESIS_PARENT_HASH,
        "receipt_root": BLANK_ROOT_HASH,
        "timestamp": int(time.time()),
        "transaction_root": BLANK_ROOT_HASH,
        "uncles_hash": EMPTY_RLP_LIST_HASH
    }
    return genesis_params


def setup_tester_chain():
    from evm.vm.flavors import MainnetTesterChain
    from evm.db import get_db_backend

    db = get_db_backend()
    genesis_params = get_default_genesis_params()
    account_keys = get_default_account_keys()
    genesis_state = generate_genesis_state(account_keys)

    chain = MainnetTesterChain.from_genesis(db, genesis_params, genesis_state)
    return account_keys, chain


def _get_block_by_number(chain, block_number):
    if block_number == "latest":
        head_block = chain.get_block()
        return chain.get_canonical_block_by_number(max(0, head_block.number - 1))
    elif block_number == "earliest":
        return chain.get_canonical_block_by_number(0)
    elif block_number == "pending":
        return chain.get_block()
    elif is_integer(block_number):
        head_block = chain.get_block()
        if block_number == head_block.number:
            return head_block
        elif block_number < head_block.number:
            return chain.get_canonical_block_by_number(block_number)

    # fallback
    raise BlockNotFound("No block found for block number: {0}".format(block_number))


def _get_block_by_hash(chain, block_hash):
    block = chain.get_block_by_hash(block_hash)

    if block.number >= chain.get_block().number:
        raise BlockNotFound("No block fuond for block hash: {0}".format(block_hash))

    block_at_height = chain.get_canonical_block_by_number(block.number)
    if block != block_at_height:
        raise BlockNotFound("No block fuond for block hash: {0}".format(block_hash))

    return block


def _get_transaction_by_hash(chain, transaction_hash):
    head_block = chain.get_block()
    for index, transaction in enumerate(head_block.transactions):
        if transaction.hash == transaction_hash:
            return head_block, transaction, index
    for block_number in range(head_block.number - 1, -1, -1):
        # TODO: the chain should be able to look these up directly by hash...
        block = chain.get_canonical_block_by_number(block_number)
        for index, transaction in enumerate(block.transactions):
            if transaction.hash == transaction_hash:
                return block, transaction, index
    else:
        raise TransactionNotFound(
            "No transaction found for transaction hash: {0}".format(
                encode_hex(transaction_hash)
            )
        )


def _execute_and_revert_transaction(chain, transaction, block_number="latest"):
    vm = _get_vm_for_block_number(chain, block_number, mutable=True)

    snapshot = vm.snapshot()
    computation = vm.execute_transaction(transaction)
    vm.revert(snapshot)
    return computation


def _get_vm_for_block_number(chain, block_number, mutable=False):
    block = _get_block_by_number(chain, block_number)
    if mutable and not block.header.is_mutable():
        block.header.make_mutable()
    vm = chain.get_vm(header=block.header)
    return vm


class PyEVMBackend(object):
    chain = None
    fork_blocks = None

    def __init__(self):
        self.fork_blocks = {}

        if not is_pyevm_available():
            raise pkg_resources.DistributionNotFound(
                "The `py-evm` package is not available.  The "
                "`PyEVMBackend` requires py-evm to be installed and importable. "
                "Please install the `py-evm` library."
            )

        self.reset_to_genesis()

    #
    # Private Accounts API
    #
    @property
    def _key_lookup(self):
        return {
            key.public_key.to_canonical_address(): key
            for key
            in self.account_keys
        }

    #
    # Snapshot API
    #
    def take_snapshot(self):
        block = _get_block_by_number(self.chain, 'latest')
        return block.hash

    def revert_to_snapshot(self, snapshot):
        block = self.chain.get_block_by_hash(snapshot)
        header = self.chain.create_header_from_parent(block.header)
        self.chain = type(self.chain)(db=self.chain.db, header=header)

    def reset_to_genesis(self):
        self.account_keys, self.chain = setup_tester_chain()

    #
    # Fork block numbers
    #
    def set_fork_block(self, fork_name, fork_block):
        if fork_name in SUPPORTED_FORKS:
            if fork_block:
                self.fork_blocks[fork_name] = fork_block
        elif fork_name == FORK_STATE_CLEANUP:
            warnings.warn(UserWarning(
                "Py-EVM does not currently support the SpuriousDragon hard fork."
            ))
            # TODO: get EIP160 rules implemented in py-evm
            self.fork_blocks[fork_name] = fork_block
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))
        self.chain.configure_forks()

    def get_fork_block(self, fork_name):
        if fork_name in SUPPORTED_FORKS:
            return self.fork_blocks.get(fork_name, 0)
        elif fork_name == FORK_STATE_CLEANUP:
            # TODO: get EIP160 rules implemented in py-evm
            return self.fork_blocks.get(fork_name, 0)
        else:
            raise UnknownFork("Unknown fork name: {0}".format(fork_name))

    def configure_fork_blocks(self):
        self.chain.configure_forks(
            homestead=self.fork_blocks.get(FORK_HOMESTEAD),
            dao=self.fork_blocks.get(FORK_DAO),
            anti_dos=self.fork_blocks.get(FORK_ANTI_DOS),
        )

    #
    # Meta
    #
    def time_travel(self, to_timestamp):
        self.chain.header.timestamp = to_timestamp
        return to_timestamp

    #
    # Mining
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=None):
        if coinbase is not None:
            mine_kwargs = {'coinbase': coinbase}
        else:
            mine_kwargs = {}
        for _ in range(num_blocks):
            block = self.chain.mine_block(**mine_kwargs)
            yield block.hash

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        for private_key in self.account_keys:
            yield private_key.public_key.to_canonical_address()

    def add_account(self, private_key):
        keys = KeyAPI()
        self.account_keys = self.account_keys + (keys.PrivateKey(private_key),)

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transaction=True):
        block = _get_block_by_number(self.chain, block_number)
        is_pending = block.number == self.chain.get_block().number
        return serialize_block(block, full_transaction, is_pending)

    def get_block_by_hash(self, block_hash, full_transaction=True):
        block = _get_block_by_hash(self.chain, block_hash)
        is_pending = block.number == self.chain.get_block().number
        return serialize_block(block, full_transaction, is_pending)

    def get_transaction_by_hash(self, transaction_hash):
        block, transaction, transaction_index = _get_transaction_by_hash(
            self.chain,
            transaction_hash,
        )
        is_pending = block.number == self.chain.get_block().number
        return serialize_transaction(block, transaction, transaction_index, is_pending)

    def get_transaction_receipt(self, transaction_hash):
        block, transaction, transaction_index = _get_transaction_by_hash(
            self.chain,
            transaction_hash,
        )
        is_pending = block.number == self.chain.get_block().number
        return serialize_transaction_receipt(block, transaction, transaction_index, is_pending)

    #
    # Account state
    #
    def get_nonce(self, account, block_number="latest"):
        vm = _get_vm_for_block_number(self.chain, block_number)
        with vm.state_db(read_only=True) as state_db:
            return state_db.get_nonce(account)

    def get_balance(self, account, block_number="latest"):
        vm = _get_vm_for_block_number(self.chain, block_number)
        with vm.state_db(read_only=True) as state_db:
            return state_db.get_balance(account)

    def get_code(self, account, block_number="latest"):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Transactions
    #
    @to_dict
    def _normalize_transaction(self, transaction):
        for key in transaction:
            if key == 'from':
                continue
            yield key, transaction[key]
        if 'nonce' not in transaction:
            yield 'nonce', self.get_nonce(transaction['from'])
        if 'data' not in transaction:
            yield 'data', b''
        if 'gas_price' not in transaction:
            yield 'gas_price', 1
        if 'value' not in transaction:
            yield 'value', 0
        if 'to' not in transaction:
            yield 'to', b''

    def _get_normalized_and_signed_evm_transaction(self, transaction):
        signing_key = self._key_lookup[transaction['from']]
        normalized_transaction = self._normalize_transaction(transaction)
        evm_transaction = self.chain.create_unsigned_transaction(**normalized_transaction)
        signed_evm_transaction = evm_transaction.as_signed_transaction(signing_key)
        return signed_evm_transaction

    def send_transaction(self, transaction):
        signed_evm_transaction = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )
        self.chain.apply_transaction(signed_evm_transaction)
        return signed_evm_transaction.hash

    def estimate_gas(self, transaction):
        # TODO: move this to the VM level (and use binary search approach)
        signed_evm_transaction = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )

        computation = _execute_and_revert_transaction(self.chain, signed_evm_transaction)

        return computation.gas_meter.start_gas - computation.gas_meter.gas_remaining

    def call(self, transaction, block_number="latest"):
        # TODO: move this to the VM level.
        signed_evm_transaction = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )

        computation = _execute_and_revert_transaction(self.chain, signed_evm_transaction)
        return computation.output
