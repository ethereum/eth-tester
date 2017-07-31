import time

import pytest

from unittest import mock

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
