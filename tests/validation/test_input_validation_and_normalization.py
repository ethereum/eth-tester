import time

import pytest

from unittest import mock

from eth_utils import (
    encode_hex,
    decode_hex,
)

from eth_tester.exceptions import (
    ValidationError,
)


@pytest.fixture
def eth_tester():
    from eth_tester import EthereumTester
    _eth_tester = EthereumTester(chain_backend=mock.MagicMock())
    return _eth_tester


@pytest.mark.parametrize(
    "delta,is_valid",
    (
        (-10, False),
        (-1, False),
        (0, False),
        (1, True),
        (10, True),
    ),
)
def test_cannot_time_travel_backwards_in_time(eth_tester, delta, is_valid):
    now_timestamp = int(time.time())
    eth_tester.chain_backend.get_block_by_number = mock.MagicMock(
        return_value={'timestamp': now_timestamp},
    )

    if is_valid:
        eth_tester.time_travel(now_timestamp + delta)
    else:
        with pytest.raises(ValidationError):
            eth_tester.time_travel(now_timestamp + delta)


@pytest.mark.parametrize(
    "timestamp,is_valid",
    (
        (4000001, True),
        (4000010, True),
        (4000001.0, False),
        (4000010.0, False),
        (True, False),
        (False, False),
    ),
)
def test_time_travel_timestamp_must_be_integer(eth_tester, timestamp, is_valid):
    eth_tester.chain_backend.get_block_by_number = mock.MagicMock(
        return_value={'timestamp': 4000000},
    )

    if is_valid:
        eth_tester.time_travel(timestamp)
    else:
        with pytest.raises(ValidationError):
            eth_tester.time_travel(timestamp)


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
def test_get_block_by_number_validation(eth_tester, block_number, is_valid):
    eth_tester.chain_backend.get_block_by_number = mock.MagicMock(
        return_value="TODO",
    )

    if is_valid:
        eth_tester.get_block_by_number(block_number)
    else:
        with pytest.raises(ValidationError):
            eth_tester.get_block_by_number(block_number)


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
def test_get_block_by_hash_validation(eth_tester, block_hash, is_valid):
    eth_tester.chain_backend.get_block_by_hash = mock.MagicMock(
        return_value="TODO",
    )

    if is_valid:
        eth_tester.get_block_by_hash(block_hash)
    else:
        with pytest.raises(ValidationError):
            eth_tester.get_block_by_hash(block_hash)


def _make_filter_params(from_block=None, to_block=None, address=None, topics=None):
    return {
        'from_block': from_block,
        'to_block': to_block,
        'address': address,
        'topics': topics,
    }


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
def test_filter_params_validation(eth_tester, filter_params, is_valid):
    eth_tester.chain_backend.create_log_filter = mock.MagicMock(
        return_value="TODO",
    )

    if is_valid:
        eth_tester.create_log_filter(**filter_params)
    else:
        with pytest.raises(ValidationError):
            eth_tester.create_log_filter(**filter_params)
