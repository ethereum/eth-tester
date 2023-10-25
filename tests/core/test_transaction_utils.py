import pytest

from eth_tester.utils.transactions import (
    remove_matching_transaction_from_list,
)

TX1 = {"from": "0x1", "to": "0x5", "value": 1, "nonce": 0}
TX2 = {"from": "0x2", "to": "0x5", "value": 1, "nonce": 0}
TX3 = {"from": "0x3", "to": "0x5", "value": 1, "nonce": 0}


@pytest.mark.parametrize(
    "tx_list,transaction,expected",
    (
        ([TX1, TX2, TX3], TX2, [TX1, TX3]),
        (
            [TX1, TX2, TX3],
            {"from": "0x2", "to": "0x6", "value": 2, "nonce": 0},
            [TX1, TX3],
        ),
    ),
)
def test_remove_matching_transaction_from_list(tx_list, transaction, expected):
    result = remove_matching_transaction_from_list(tx_list, transaction)
    assert result == expected
