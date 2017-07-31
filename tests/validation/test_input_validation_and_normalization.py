import time

import pytest

from unittest import mock

from eth_tester.exceptions import (
    ValidationError,
)


@pytest.fixture
def eth_tester():
    from eth_tester import EthereumTester
    _eth_tester = EthereumTester(backend=mock.MagicMock())
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
    eth_tester.backend.get_block_by_number = mock.MagicMock(
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
    eth_tester.backend.get_block_by_number = mock.MagicMock(
        return_value={'timestamp': 4000000},
    )

    if is_valid:
        eth_tester.time_travel(timestamp)
    else:
        with pytest.raises(ValidationError):
            eth_tester.time_travel(timestamp)
