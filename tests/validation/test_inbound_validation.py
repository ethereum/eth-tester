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
from eth_tester.validation import DefaultValidator


@pytest.fixture
def validator():
    _validator = DefaultValidator()
    return _validator


@pytest.mark.parametrize(
    "timestamp,is_valid",
    (
        (4000001, True),
        (4000010, True),
        ('4000001', False),
        ('4000010', False),
        (4000001.0, False),
        (4000010.0, False),
        (True, False),
        (False, False),
    ),
)
def test_time_travel_input_timestamp_validation(validator, timestamp, is_valid):
    if is_valid:
        validator.validate_inbound_timestamp(timestamp)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_timestamp(timestamp)


@pytest.mark.parametrize(
    "block_number,is_valid",
    (
        (0, True),
        (1, True),
        (-1, False),
        (False, False),
        (True, False),
        ("latest", True),
        ("pending", True),
        ("earliest", True),
        (2**256, True),
        (b"latest", False),
        (b"pending", False),
        (b"earliest", False),
    ),
)
def test_block_number_intput_validation(validator, block_number, is_valid):
    if is_valid:
        validator.validate_inbound_block_number(block_number)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_block_number(block_number)


@pytest.mark.parametrize(
    "block_hash,is_valid",
    (
        (0, False),
        (1, False),
        (-1, False),
        (False, False),
        (True, False),
        (b'', False),
        ('', False),
        ('0' * 32, False),
        ('0x' + '0' * 32, False),
        ('\x00' * 32, False),
        (b'\x00' * 32, False),
        ('0' * 64, True),
        ('0x' + '0' * 64, True),
        (b'0x' + b'0' * 64, False),
    ),
)
def test_block_hash_input_validation(validator, block_hash, is_valid):
    if is_valid:
        validator.validate_inbound_block_hash(block_hash)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_block_hash(block_hash)


def _make_filter_params(from_block=None, to_block=None, address=None, topics=None):
    return {
        'from_block': from_block,
        'to_block': to_block,
        'address': address,
        'topics': topics,
    }


@pytest.mark.parametrize(
    "filter_id,is_valid",
    (
        (-1, False),
        (0, True),
        (1, True),
        ('0x0', False),
        ('0x00', False),
        ('0x1', False),
        ('0x01', False),
        ('0', False),
        ('1', False),
    ),
)
def test_filter_id_input_validation(validator, filter_id, is_valid):
    if is_valid:
        validator.validate_inbound_filter_id(filter_id)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_filter_id(filter_id)


ADDRESS_A = encode_hex(b'\x00' * 19 + b'\x01')
ADDRESS_B = encode_hex(b'\x00' * 19 + b'\x02')
TOPIC_A = encode_hex(b'\x00' * 31 + b'\x01')
TOPIC_B = encode_hex(b'\x00' * 31 + b'\x02')


@pytest.mark.parametrize(
    "filter_params,is_valid",
    (
        (_make_filter_params(), True),
        (_make_filter_params(from_block=0), True),
        (_make_filter_params(to_block=0), True),
        (_make_filter_params(from_block=-1), False),
        (_make_filter_params(to_block=-1), False),
        (_make_filter_params(from_block=True), False),
        (_make_filter_params(to_block=False), False),
        (_make_filter_params(from_block='0x0'), False),
        (_make_filter_params(to_block='0x0'), False),
        (_make_filter_params(from_block='0x1'), False),
        (_make_filter_params(to_block='0x1'), False),
        (_make_filter_params(address=ADDRESS_A), True),
        (_make_filter_params(address=decode_hex(ADDRESS_A)), False),
        (_make_filter_params(address=[ADDRESS_A, ADDRESS_B]), True),
        (_make_filter_params(address=TOPIC_A), False),
        (_make_filter_params(address=decode_hex(TOPIC_A)), False),
        (_make_filter_params(address=[TOPIC_A, ADDRESS_B]), False),
        (_make_filter_params(topics=[TOPIC_A]), True),
        (_make_filter_params(topics=[TOPIC_A, TOPIC_B]), True),
        (_make_filter_params(topics=[[TOPIC_A], [TOPIC_B]]), True),
        (_make_filter_params(topics=[ADDRESS_A]), False),
        (_make_filter_params(topics=[ADDRESS_A, TOPIC_B]), False),
        (_make_filter_params(topics=[[ADDRESS_A], [TOPIC_B]]), False),
    ),
)
def test_filter_params_input_validation(validator, filter_params, is_valid):
    if is_valid:
        validator.validate_inbound_filter_params(**filter_params)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_filter_params(**filter_params)


@to_dict
def _make_transaction(_from=None, to=None, gas=None, gas_price=None, value=None, data=None):
    if _from is not None:
        yield 'from', _from
    if to is not None:
        yield 'to', to
    if gas is not None:
        yield 'gas', gas
    if gas_price is not None:
        yield 'gas_price', gas_price
    if value is not None:
        yield 'value', value
    if data is not None:
        yield 'data', data


@pytest.mark.parametrize(
    "transaction,is_valid",
    (
        ({}, False),
        (_make_transaction(to=ADDRESS_B, gas=21000), False),
        (_make_transaction(_from=ADDRESS_A, gas=21000), True),
        (_make_transaction(_from=ADDRESS_A, to=ADDRESS_B), False),
        (_make_transaction(_from=ADDRESS_A, to=ADDRESS_B, gas=21000), True),
        (_make_transaction(_from='', to=ADDRESS_B, gas=21000), False),
        (_make_transaction(_from=ADDRESS_A, to='', gas=21000), True),
        (_make_transaction(_from=decode_hex(ADDRESS_A), to=ADDRESS_B, gas=21000), False),
        (_make_transaction(_from=ADDRESS_A, to=decode_hex(ADDRESS_B), gas=21000), False),
        (_make_transaction(_from=ADDRESS_A, to='', gas=21000, value=0), True),
        (_make_transaction(_from=ADDRESS_A, to='', gas=21000, value=-1), False),
        (_make_transaction(_from=ADDRESS_A, to='', gas=21000, data=''), True),
        (_make_transaction(_from=ADDRESS_A, to='', gas=21000, data='0x'), True),
        (_make_transaction(_from=ADDRESS_A, to='', gas=21000, data='0x0'), False),
    ),
)
def test_transaction_input_validation(validator, transaction, is_valid):
    if is_valid:
        validator.validate_inbound_transaction(transaction)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_transaction(transaction)
