import functools
import time

from eth_utils import (
    apply_to_return_value,
    is_bytes,
    is_dict,
    is_integer,
    is_list_like,
    is_null,
    is_text,
    keccak,
    to_bytes,
    to_dict,
    to_tuple,
)

from eth_utils.toolz import (
    assoc,
)

from eth_tester.backends.common import merge_genesis_overrides
from eth_tester.utils.address import (
    generate_contract_address,
)


ZERO_32BYTES = b'\x00' * 32
ZERO_8BYTES = b'\x00' * 8
ZERO_ADDRESS = b'\x00' * 20


@apply_to_return_value(b'|'.join)
@to_tuple
def bytes_repr(value):
    if is_bytes(value):
        yield value
    elif is_text(value):
        yield to_bytes(text=value)
    elif is_list_like(value):
        yield b''.join((
            b'(',
            b','.join(bytes_repr(item) for item in value),
            b')',
        ))
    elif is_dict(value):
        yield b''.join((
            b'{',
            b','.join((
                b":".join((bytes_repr(key), bytes_repr(item)))
                for key, item
                in value.items()
            )),
            b'}',
        ))
    elif is_integer(value):
        yield to_bytes(value)
    elif is_null(value):
        yield 'None@{}'.format(id(value))
    else:
        raise TypeError("Unsupported type for bytes_repr: {}".format(type(value)))


def fake_rlp_hash(value):
    return keccak(bytes_repr(value))


def add_hash(fn):
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        value = fn(*args, **kwargs)
        if 'hash' in value:
            return value
        else:
            return assoc(value, 'hash', keccak(bytes_repr(value)))
    return inner


def create_transaction(transaction, block, transaction_index, is_pending, overrides=None):
    filled_txn = _fill_transaction(transaction, block, transaction_index, is_pending, overrides)
    if 'hash' in filled_txn:
        return filled_txn
    else:
        return assoc(filled_txn, 'hash', fake_rlp_hash(filled_txn))


@to_dict
def _fill_transaction(transaction, block, transaction_index, is_pending, overrides=None):
    if overrides is None:
        overrides = {}

    if 'nonce' in overrides:
        yield 'nonce', overrides['nonce']
    else:
        yield 'nonce', 0

    if 'hash' in overrides:
        yield 'hash', overrides['hash']
    else:
        # calculate hash after all fields are filled
        pass

    if 'from' in overrides:
        yield 'from', overrides['from']
    else:
        yield 'from', transaction['from']

    if 'gas' in overrides:
        yield 'gas', overrides['gas']
    else:
        yield 'gas', transaction['gas']

    if 'gas_price' in overrides:
        yield 'gas_price', overrides['gas_price']
    else:
        yield 'gas_price', transaction.get('gas_price', 1)  # TODO: make configurable

    if 'to' in overrides:
        yield 'to', overrides['to']
    else:
        yield 'to', transaction.get('to', b'')

    if 'data' in overrides:
        yield 'data', overrides['data']
    else:
        yield 'data', transaction.get('data', b'')

    if 'value' in overrides:
        yield 'value', overrides['value']
    else:
        yield 'value', transaction.get('value', 0)

    if 'nonce' in overrides:
        yield 'nonce', overrides['nonce']
    else:
        yield 'nonce', transaction.get('nonce', 0)

    if 'v' in overrides:
        yield 'v', overrides['v']
    else:
        yield 'v', transaction.get('v', 27)

    if 'r' in overrides:
        yield 'r', overrides['r']
    else:
        yield 'r', transaction.get('r', 12345)

    if 's' in overrides:
        yield 's', overrides['s']
    else:
        yield 's', transaction.get('s', 67890)


@to_dict
def make_log(transaction, block, transaction_index, log_index, overrides=None):
    if overrides is None:
        overrides = {}

    is_pending = transaction['block_number'] is None

    if 'type' in overrides:
        yield 'type', overrides['type']
    else:
        yield 'type', 'pending' if is_pending else 'mined'

    if 'transaction_index' in overrides:
        yield 'transaction_index', overrides['transaction_index']
    else:
        yield 'transaction_index', None if is_pending else transaction_index

    if 'block_number' in overrides:
        yield 'block_number', overrides['block_number']
    else:
        yield 'block_number', None if is_pending else block['number']

    if 'block_hash' in overrides:
        yield 'block_hash', overrides['block_hash']
    else:
        yield 'block_hash', None if is_pending else block['hash']

    if 'log_index' in overrides:
        yield 'log_index', overrides['log_index']
    else:
        yield 'log_index', log_index

    if 'address' in overrides:
        yield 'address', overrides['address']
    else:
        yield 'address', transaction.get('to', b'')

    if 'data' in overrides:
        yield 'data', overrides['data']
    else:
        yield 'data', b''

    if 'topics' in overrides:
        yield 'topics', overrides['topics']
    else:
        yield 'topics', []


@to_dict
def make_receipt(transaction, block, transaction_index, overrides=None):
    if overrides is None:
        overrides = {}

    if 'gas_used' in overrides:
        gas_used = overrides['gas_used']
    else:
        gas_used = 21000
    yield 'gas_used', gas_used

    if 'cumulative_gas_used' in overrides:
        yield 'cumulative_gas_used', overrides['cumulative_gas_used']
    else:
        yield 'cumulative_gas_used', block['gas_used'] + gas_used

    if 'contract_address' in overrides:
        yield 'contract_address', overrides['contract_address']
    else:
        contract_address = generate_contract_address(transaction['from'], transaction['nonce'])
        yield 'contract_address', contract_address

    if 'logs' in overrides:
        yield 'logs', overrides['logs']
    else:
        yield 'logs', []

    if 'transaction_hash' in overrides:
        yield 'transaction_hash', overrides['transaction_hash']
    else:
        yield 'transaction_hash', transaction['hash']


GENESIS_NONCE = b'\x00\x00\x00\x00\x00\x00\x00*'  # 42 encoded as big-endian-integer
BLANK_ROOT_HASH = b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n\x5bH\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!'  # noqa: E501
EMPTY_UNCLE_HASH = b'\x1d\xccM\xe8\xde\xc7]z\xab\x85\xb5g\xb6\xcc\xd4\x1a\xd3\x12E\x1b\x94\x8at\x13\xf0\xa1B\xfd@\xd4\x93G'  # noqa: E501


def make_genesis_block(overrides=None):
    default_genesis_block = {
        "number": 0,
        "hash": ZERO_32BYTES,
        "parent_hash": ZERO_32BYTES,
        "nonce": GENESIS_NONCE,
        "sha3_uncles": EMPTY_UNCLE_HASH,
        "logs_bloom": 0,
        "transactions_root": BLANK_ROOT_HASH,
        "receipts_root": BLANK_ROOT_HASH,
        "state_root": BLANK_ROOT_HASH,
        "miner": ZERO_ADDRESS,
        "difficulty": 131072,
        "total_difficulty": 131072,
        "size": 0,
        "extra_data": ZERO_32BYTES,
        "gas_limit": 3141592,
        "gas_used": 0,
        "timestamp": int(time.time()),
        "transactions": [],
        "uncles": [],
    }
    if overrides is not None:
        genesis_block = merge_genesis_overrides(defaults=default_genesis_block,
                                                overrides=overrides)
    else:
        genesis_block = default_genesis_block
    return genesis_block


@add_hash
@to_dict
def make_block_from_parent(parent_block, overrides=None):
    if overrides is None:
        overrides = {}

    if 'number' in overrides:
        yield 'number', overrides['number']
    else:
        yield 'number', parent_block['number'] + 1

    if 'hash' in overrides:
        yield 'hash', overrides['hash']
    else:
        yield 'hash', keccak(parent_block['hash'])

    if 'parent_hash' in overrides:
        yield 'parent_hash', overrides['parent_hash']
    else:
        yield 'parent_hash', parent_block['hash']

    if 'nonce' in overrides:
        yield 'nonce', overrides['nonce']
    else:
        yield 'nonce', parent_block['nonce']

    if 'sha3_uncles' in overrides:
        yield 'sha3_uncles', overrides['sha3_uncles']
    else:
        yield 'sha3_uncles', EMPTY_UNCLE_HASH

    if 'logs_bloom' in overrides:
        yield 'logs_bloom', overrides['logs_bloom']
    else:
        yield 'logs_bloom', 0

    if 'transactions_root' in overrides:
        yield 'transactions_root', overrides['transactions_root']
    else:
        yield 'transactions_root', BLANK_ROOT_HASH

    if 'receipts_root' in overrides:
        yield 'receipts_root', overrides['receipts_root']
    else:
        yield 'receipts_root', BLANK_ROOT_HASH

    if 'state_root' in overrides:
        yield 'state_root', overrides['state_root']
    else:
        yield 'state_root', BLANK_ROOT_HASH

    if 'miner' in overrides:
        yield 'miner', overrides['miner']
    else:
        yield 'miner', ZERO_ADDRESS

    if 'difficulty' in overrides:
        difficulty = overrides['difficulty']
    else:
        difficulty = 131072
    yield 'difficulty', difficulty

    if 'total_difficulty' in overrides:
        yield 'total_difficulty', overrides['total_difficulty']
    else:
        yield 'total_difficulty', parent_block['difficulty'] + difficulty

    if 'size' in overrides:
        yield 'size', overrides['size']
    else:
        yield 'size', 0

    if 'extra_data' in overrides:
        yield 'extra_data', overrides['extra_data']
    else:
        yield 'extra_data', ZERO_32BYTES

    if 'gas_limit' in overrides:
        yield 'gas_limit', overrides['gas_limit']
    else:
        yield 'gas_limit', parent_block['gas_limit']

    if 'gas_used' in overrides:
        yield 'gas_used', overrides['gas_used']
    else:
        yield 'gas_used', 0

    if 'timestamp' in overrides:
        yield 'timestamp', overrides['timestamp']
    else:
        yield 'timestamp', parent_block['timestamp'] + 1

    if 'transactions' in overrides:
        yield 'transactions', overrides['transactions']
    else:
        yield 'transactions', []

    if 'uncles' in overrides:
        yield 'uncles', overrides['uncles']
    else:
        yield 'uncles', []
