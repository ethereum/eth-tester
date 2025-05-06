import pytest
from typing import (
    Any,
    Dict,
    List,
    Tuple,
    Union,
)

from ethereum.cancun.blocks import (
    Block,
    Log,
    Withdrawal,
)
from ethereum.cancun.transactions import (
    LegacyTransaction,
)

from eth_tester.backends.eels.main import (
    EELSBackend,
)
from eth_tester.backends.eels.serializers import (
    serialize_block,
    serialize_eels_transaction_for_block,
    serialize_eels_withdrawal_for_block,
    serialize_pending_logs,
    serialize_pending_receipt,
    serialize_transaction,
)
from tests.backends.eels.conftest import (
    AnyTransaction,
)


@pytest.mark.parametrize(
    "full_transactions", [True, False], ids=["full_txns", "hash_txns"]
)
def test_serialize_pending_block_returns_camel_case_keys(
    pending_block: Dict[str, Any],
    full_transactions: bool,
    block_keys: List[str],
) -> None:
    serialized_block = serialize_block(
        EELSBackend(),
        pending_block,
        full_transactions=full_transactions,
        is_pending=True,
    )

    assert sorted(list(serialized_block.keys())) == sorted(block_keys)


@pytest.mark.parametrize(
    "full_transactions", [True, False], ids=["full_txns", "hash_txns"]
)
def test_serialize_finalized_block_returns_camel_case_keys(
    finalized_block: Block,
    full_transactions: bool,
    finalized_block_keys: List[str],
) -> None:
    serialized_block = serialize_block(
        EELSBackend(),
        finalized_block,
        full_transactions=full_transactions,
        is_pending=False,
    )

    assert sorted(list(serialized_block.keys())) == sorted(finalized_block_keys)


def test_serialize_block_transactions_returns_camel_case_keys(
    block_transactions: List[AnyTransaction],
    block_transaction_keys: List[str],
) -> None:
    for txn in block_transactions:
        # Check all transaction keys are valid
        serialized_txn = serialize_eels_transaction_for_block(
            EELSBackend(), txn, 0, 0, "0x12345"
        )
        for key in serialized_txn.keys():
            assert (
                key in block_transaction_keys
            ), f"Invalid transaction key found: {key}"


def test_serialize_block_withdrawals(withdrawals: List[Withdrawal]) -> None:
    for withdrawal in withdrawals:
        valid_withdrawal_keys = [
            "index",
            "validatorIndex",
            "address",
            "amount",
        ]

        serialized_withdrawal = serialize_eels_withdrawal_for_block(withdrawal)
        # Check all withdrawal keys are valid
        for key in serialized_withdrawal.keys():
            assert key in valid_withdrawal_keys, f"Invalid withdrawal key found: {key}"


def test_serialize_transaction_returns_camel_case_keys(
    transaction_dict: Dict[str, Any],
    parameterized_pending_block: Union[None, Dict[str, Any]],
) -> None:
    additional_expected_keys = []
    if parameterized_pending_block is not None:
        serialized_transaction = serialize_transaction(
            transaction_dict, parameterized_pending_block
        )

        additional_expected_keys = [
            "blockHash",
            "blockNumber",
            "transactionIndex",
        ]
    else:
        serialized_transaction = serialize_transaction(transaction_dict)

    expected_keys = [
        "nonce",
        "to",
        "value",
        "gas",
        "gasPrice",
        "data",
        "v",
        "r",
        "s",
    ]
    expected_keys.extend(additional_expected_keys)

    assert sorted(list(serialized_transaction.keys())) == sorted(expected_keys)


def test_serialize_transaction_receipt(
    transaction: LegacyTransaction, process_transaction_return: Tuple[int, Log, int]
) -> None:
    serialized_receipt = serialize_pending_receipt(
        EELSBackend(),
        tx=transaction,
        process_transaction_return=process_transaction_return,
        index=0,
        cumulative_gas_used=0,
        contract_address=None,
    )

    expected_keys = [
        "blockHash",
        "blockNumber",
        "contractAddress",
        "cumulativeGasUsed",
        "effectiveGasPrice",
        "from",
        "gasUsed",
        "logs",
        "stateRoot",
        "status",
        "to",
        "transactionHash",
        "transactionIndex",
        "type",
    ]

    assert sorted(list(serialized_receipt.keys())) == sorted(expected_keys)


def test_serialize_pending_logs(log: Log) -> None:
    serialized_pending_logs = serialize_pending_logs((log,))

    expected_keys = [
        "address",
        "topics",
        "data",
        "logIndex",
        "type",
    ]

    assert sorted(list(serialized_pending_logs[0].keys())) == sorted(expected_keys)
