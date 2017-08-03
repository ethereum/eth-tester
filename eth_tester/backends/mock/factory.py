import functools
import time

import rlp

from cytoolz.dicttools import (
    assoc,
)

from eth_utils import (
    keccak,
    to_dict,
    is_dict,
    is_integer,
    is_list_like,
    is_text,
    is_bytes,
    force_bytes,
    to_tuple,
    apply_to_return_value,
)


ZERO_32BYTES = b'\x00' * 32
ZERO_8BYTES = b'\x00' * 8
ZERO_ADDRESS = b'\x00' * 20


@apply_to_return_value('|'.join)
@to_tuple
def stringify(value):
    if is_bytes(value):
        yield value
    elif is_text(value):
        yield force_bytes(value)
    elif is_list_like(value):
        yield b''.join((
            b'(',
            b','.join((stringify(item) for item in value)),
            b')',
        ))
    elif is_dict(value):
        yield b''.join((
            b'{',
            b','.join((
                ":".join((stringify(key), stringify(item)))
                for key, item
                in value.items()
            )),
            b'}',
        ))
    elif is_integer(value):
        yield force_bytes(str(value))
    else:
        raise TypeError("Unsupported type for stringification: {0}".format(type(value)))


def add_hash(fn):
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        value = fn(*args, **kwargs)
        if 'hash' in value:
            return value
        else:
            return assoc(value, 'hash', keccak(stringify(value)))
    return inner


@add_hash
@to_dict
def create_transaction(transaction, block, transaction_index, is_pending, overrides):
    if 'transaction_index' in overrides:
        yield 'transaction_index', overrides['transaction_index']
    else:
        yield None if is_pending else transaction_index

    if 'block_number' in overrides:
        yield 'block_number', overrides['block_number']
    else:
        yield None if is_pending else block['number']

    if 'block_hash' in overrides:
        yield 'block_hash', overrides['block_hash']
    else:
        yield None if is_pending else block['hash']

    if 'nonce' in overrides:
        yield 'nonce', overrides['nonce']
    else:
        yield 'nonce', 0

    if 'hash' in overrides:
        yield 'hash', overrides['hash']

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
        yield 'gas_price', transaction['gas_price']

    if 'to' in overrides:
        yield 'to', overrides['to']
    else:
        yield 'to', transaction['to']

    if 'data' in overrides:
        yield 'data', overrides['data']
    else:
        yield 'data', transaction['data']

    if 'value' in overrides:
        yield 'value', overrides['value']
    else:
        yield 'value', transaction['value']

    if 'v' in overrides:
        yield 'v', overrides['v']
    else:
        yield 'v', transaction['v']

    if 'r' in overrides:
        yield 'r', overrides['r']
    else:
        yield 'r', transaction['r']

    if 's' in overrides:
        yield 's', overrides['s']
    else:
        yield 's', transaction['s']


@to_dict
def make_log(transaction, block, transaction_index, log_index, overrides):
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
        yield 'address', transaction['to']

    if 'data' in overrides:
        yield 'data', overrides['data']
    else:
        yield 'data', b''

    if 'topics' in overrides:
        yield 'topics', overrides['topics']
    else:
        yield 'topics', []


def generate_contract_address(address, nonce):
    return keccak(rlp.encode([address, nonce]))[-20:]


def make_receipt(transaction, block, transaction_index, overrides):
    is_pending = transaction['block_number'] is None

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


def make_genesis_block():
    return {
        "number": 0,
        "hash": ZERO_32BYTES,
        "parent_hash": ZERO_32BYTES,
        "nonce": GENESIS_NONCE,
        "sha3_uncles": EMPTY_UNCLE_HASH,
        "logs_bloom": 0,
        "transactions_root": BLANK_ROOT_HASH,
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


@add_hash
@to_dict
def make_block_from_parent(parent_block, overrides):
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

    if 'transaction_root' in overrides:
        yield 'transaction_root', overrides['transaction_root']
    else:
        yield 'transaction_root', BLANK_ROOT_HASH

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
        yield 'timestamp', parent_block['timestamp'] + 15

    if 'transactions' in overrides:
        yield 'transactions', overrides['transactions']
    else:
        yield 'transactions', []

    if 'uncles' in overrides:
        yield 'uncles', overrides['uncles']
    else:
        yield 'uncles', []
