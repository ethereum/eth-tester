from __future__ import unicode_literals

import time

import pytest

from unittest import mock

from eth_utils import (
    to_dict,
    encode_hex,
    decode_hex,
)

from eth_tester.exceptions import (
    ValidationError,
)
from eth_tester.validation import OutputValidationBackend


@pytest.fixture
def output_validator():
    _output_validator = OutputValidationBackend()
    return _output_validator


@pytest.mark.parametrize(
    "block_hash,is_valid",
    (
        (1, False),
        (True, False),
        (b'\x00' * 32, True),
        (b'\xff' * 32, True),
        ('\x00' * 32, False),
        (encode_hex('\x00' * 32), False),
    ),
)
def test_block_hash_output_validation(output_validator, block_hash, is_valid):
    if is_valid:
        output_validator.validate_block_hash(block_hash)
    else:
        with pytest.raises(ValidationError):
            output_validator.validate_block_hash(block_hash)


ZERO_32BYTES = b'\x00' * 32
ZERO_8BYTES = b'\x00' * 8
ZERO_ADDRESS = b'\x00' * 20


def _make_block(number=0,
                hash=ZERO_32BYTES,
                parent_hash=ZERO_32BYTES,
                nonce=ZERO_8BYTES,
                sha3_uncles=ZERO_32BYTES,
                logs_bloom=0,
                transactions_root=ZERO_32BYTES,
                state_root=ZERO_32BYTES,
                miner=ZERO_ADDRESS,
                difficulty=0,
                total_difficulty=0,
                size=0,
                extra_data=ZERO_32BYTES,
                gas_limit=3141592,
                gas_used=21000,
                timestamp=4000000,
                transactions=None,
                uncles=None):
    return {
        "number": number,
        "hash": hash,
        "parent_hash": parent_hash,
        "nonce": nonce,
        "sha3_uncles": sha3_uncles,
        "logs_bloom": logs_bloom,
        "transactions_root": transactions_root,
        "state_root": state_root,
        "miner": miner,
        "difficulty": difficulty,
        "total_difficulty": total_difficulty,
        "size": size,
        "extra_data": extra_data,
        "gas_limit": gas_limit,
        "gas_used": gas_used,
        "timestamp": timestamp,
        "transactions": transactions or [],
        "uncles": uncles or [],
    }


ADDRESS_A = b'\x00' * 19 + b'\x01'
TOPIC_A = b'\x00' * 31 + b'\x01'
TOPIC_B = b'\x00' * 31 + b'\x02'
HASH32_AS_TEXT = '\x00' * 32


#@pytest.mark.parametrize(
#    "block,is_valid",
#    (
#        (_make_block(),  True),
#    )
#)
#def test_block_output_validation(output_validator, block, is_valid):
#    if is_valid:
#        output_validator.validate_block(block)
#    else:
#        with pytest.raises(ValidationError):
#            output_validator.validate_block(block)


def _make_transaction(hash=ZERO_32BYTES,
                      nonce=0,
                      block_hash=ZERO_32BYTES,
                      block_number=0,
                      transaction_index=0,
                      _from=ZERO_ADDRESS,
                      to=ZERO_ADDRESS,
                      value=0,
                      gas=21000,
                      gas_price=1,
                      data=b'',
                      v=0,
                      r=0,
                      s=0):
    return {
        "hash": hash,
        "nonce": nonce,
        "block_hash": block_hash,
        "block_number": block_number,
        "transaction_index": transaction_index,
        "from": _from,
        "to": to,
        "value": value,
        "gas": gas,
        "gas_price": gas_price,
        "data": data,
        "v": v,
        "r": r,
        "s": s,
    }


@pytest.mark.parametrize(
    "transaction,is_valid",
    (
        (_make_transaction(),  True),
        (_make_transaction(hash=HASH32_AS_TEXT),  False),
        (_make_transaction(nonce=-1),  False),
        (_make_transaction(nonce=1.0),  False),
        (_make_transaction(nonce=True),  False),
        (_make_transaction(value=-1),  False),
        (_make_transaction(value=1.0),  False),
        (_make_transaction(value=True),  False),
        (_make_transaction(block_number=-1),  False),
        (_make_transaction(block_number=1.0),  False),
        (_make_transaction(block_number=True),  False),
        (_make_transaction(gas=-1),  False),
        (_make_transaction(gas=1.0),  False),
        (_make_transaction(gas=True),  False),
        (_make_transaction(gas_price=-1),  False),
        (_make_transaction(gas_price=1.0),  False),
        (_make_transaction(gas_price=True),  False),
        (_make_transaction(data=''),  False),
        (_make_transaction(data='0x'),  False),
        (_make_transaction(block_hash=HASH32_AS_TEXT),  False),
        (_make_transaction(transaction_index=None, block_hash=None, block_number=None),  True),
    )
)
def test_transaction_output_validation(output_validator, transaction, is_valid):
    if is_valid:
        output_validator.validate_transaction(transaction)
    else:
        with pytest.raises(ValidationError):
            output_validator.validate_transaction(transaction)


def _make_log(_type="mined",
              log_index=0,
              transaction_index=0,
              transaction_hash=ZERO_32BYTES,
              block_hash=ZERO_32BYTES,
              block_number=0,
              address=ZERO_ADDRESS,
              data=b'',
              topics=None):
    return {
        "type": _type,
        "log_index": log_index,
        "transaction_index": transaction_index,
        "transaction_hash": transaction_hash,
        "block_hash": block_hash,
        "block_number": block_number,
        "address": address,
        "data": data,
        "topics": topics or [],
    }


@pytest.mark.parametrize(
    "log_entry,is_valid",
    (
        (_make_log(), True),
        (_make_log(_type="pending", transaction_index=None, block_hash=None, block_number=None), True),
        (_make_log(_type="invalid-type"), False),
        (_make_log(transaction_index=-1), False),
        (_make_log(block_number=-1), False),
        (_make_log(transaction_hash=b'\x00' * 31), False),
        (_make_log(transaction_hash='\x00' * 32), False),
        (_make_log(block_hash=b'\x00' * 31), False),
        (_make_log(block_hash='\x00' * 32), False),
        (_make_log(address=encode_hex(ADDRESS_A)), False),
        (_make_log(data=''), False),
        (_make_log(data=None), False),
        (_make_log(topics=['\x00'* 32]), False),
        (_make_log(topics=[TOPIC_A, TOPIC_B]), True),
        (_make_log(address=ADDRESS_A), True),
    ),
)
def test_log_entry_output_validation(output_validator, log_entry, is_valid):
    if is_valid:
        output_validator.validate_log_entry(log_entry)
    else:
        with pytest.raises(ValidationError):
            output_validator.validate_log_entry(log_entry)
