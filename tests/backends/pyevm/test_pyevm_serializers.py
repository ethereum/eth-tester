import pytest
from typing import (
    List,
    Tuple,
)

from eth.vm.forks.berlin.transactions import (
    TypedTransaction,
)

from eth_tester.backends.pyevm.serializers import (
    serialize_block,
    serialize_block_withdrawals,
    serialize_log,
    serialize_transaction,
    serialize_transaction_receipt,
)
from eth_tester.backends.pyevm.utils import (
    is_cancun_block,
    is_london_block,
    is_shanghai_block,
)
from eth_tester.constants import (
    ACCESS_LIST_TX_TYPE,
    BLOB_TX_TYPE,
    DYNAMIC_FEE_TX_TYPE,
)
from tests.backends.pyevm.conftest import (
    FakeBlock,
    FakeLog,
    FakeReceipt,
    FakeState,
    FakeTransaction,
    FakeVM,
    FakeWithdrawal,
)


@pytest.mark.parametrize(
    "full_transaction", [True, False], ids=["txn_full", "txn_hashes"]
)
@pytest.mark.parametrize("is_pending", [True, False], ids=["pending", "finalized"])
def test_serialize_block_returns_camel_case_keys(
    block: FakeBlock,
    full_transaction: bool,
    is_pending: bool,
) -> None:
    serialized_block = serialize_block(
        block=block,
        full_transaction=full_transaction,
        is_pending=is_pending,
    )

    # Base expected keys
    expected_keys = [
        "coinbase",
        "difficulty",
        "extraData",
        "gasLimit",
        "gasUsed",
        "hash",
        "logsBloom",
        "mixHash",
        "nonce",
        "number",
        "parentHash",
        "receiptsRoot",
        "sha3Uncles",
        "size",
        "stateRoot",
        "timestamp",
        "totalDifficulty",
        "transactions",
        "transactionsRoot",
        "uncles",
    ]

    # Add any extra expected keys based on parameters
    if is_london_block(block):
        expected_keys.append("baseFeePerGas")
    if is_shanghai_block(block):
        expected_keys.append("withdrawalsRoot")
        expected_keys.append("withdrawals")
    if is_cancun_block(block):
        expected_keys.append("parentBeaconBlockRoot")
        expected_keys.append("blobGasUsed")
        expected_keys.append("excessBlobGas")

    assert sorted(list(serialized_block.keys())) == sorted(expected_keys)

    # Additional assertions to verify transaction format
    if full_transaction:
        for txn in serialized_block["transactions"]:
            valid_transaction_keys = [
                "type",
                "hash",
                "nonce",
                "blockHash",
                "blockNumber",
                "transactionIndex",
                "from",
                "gas",
                "to",
                "value",
                "data",
                "gasPrice",
                "chainId",
                "accessList",
                "maxFeePerGas",
                "maxPriorityFeePerGas",
                "maxFeePerBlobGas",
                "blobVersionedHashes",
                "r",
                "s",
                "v",
                "yParity",
            ]

            assert isinstance(txn, dict)
            for key in txn.keys():
                if key not in valid_transaction_keys:
                    assert (
                        key in valid_transaction_keys
                    ), f"Invalid transaction key found: {key}"
    else:
        for txn in serialized_block["transactions"]:
            assert isinstance(txn, bytes)
            assert len(txn) == 32


@pytest.mark.parametrize("is_pending", [True, False], ids=["pending", "finalized"])
def test_serialize_transaction_returns_camel_case_keys(
    transaction: TypedTransaction,
    is_pending: bool,
) -> None:
    block = FakeBlock(transactions=(transaction,))

    expected_keys = [
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "gasPrice",
        "type",
        "data",
        "from",
        "gas",
        "hash",
        "nonce",
        "to",
        "value",
        "r",
        "s",
        "v",
    ]

    # Add any extra expected keys based on parameters
    if transaction.type_id == ACCESS_LIST_TX_TYPE:
        expected_keys.append("chainId")
        expected_keys.append("accessList")
        expected_keys.append("yParity")
    elif transaction.type_id == DYNAMIC_FEE_TX_TYPE:
        expected_keys.append("chainId")
        expected_keys.append("accessList")
        expected_keys.append("maxFeePerGas")
        expected_keys.append("maxPriorityFeePerGas")
        expected_keys.append("yParity")
    elif transaction.type_id == BLOB_TX_TYPE:
        expected_keys.append("chainId")
        expected_keys.append("accessList")
        expected_keys.append("maxFeePerGas")
        expected_keys.append("maxPriorityFeePerGas")
        expected_keys.append("maxFeePerBlobGas")
        expected_keys.append("blobVersionedHashes")
        expected_keys.append("yParity")

    serialized_transaction = serialize_transaction(
        block=block,
        transaction=transaction,
        transaction_index=0,
        is_pending=is_pending,
    )

    assert sorted(list(serialized_transaction.keys())) == sorted(expected_keys)


def test_serialize_transaction_receipt_returns_camel_case_keys(
    transaction: FakeTransaction,
    transaction_receipts: List[FakeReceipt],
) -> None:
    block = FakeBlock(transactions=(transaction,))

    # Create VM with state
    state = FakeState(blob_base_fee=1)
    vm = FakeVM(state=state)

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

    serialized_receipt = serialize_transaction_receipt(
        block=block,
        receipts=transaction_receipts,
        transaction=transaction,
        transaction_index=0,
        is_pending=False,
        vm=vm,
    )

    if transaction.type_id == BLOB_TX_TYPE:
        expected_keys.append("blobGasUsed")
        expected_keys.append("blobGasPrice")

    assert sorted(list(serialized_receipt.keys())) == sorted(expected_keys)

    for serialized_log in serialized_receipt["logs"]:
        expected_log_keys = [
            "type",
            "logIndex",
            "transactionIndex",
            "transactionHash",
            "blockHash",
            "blockNumber",
            "address",
            "data",
            "topics",
        ]
        assert sorted(list(serialized_log.keys())) == sorted(expected_log_keys)


def test_serialize_log_returns_camel_case_keys() -> None:
    transaction = FakeTransaction()
    block = FakeBlock(transactions=(transaction,))

    log = FakeLog()

    serialized_log = serialize_log(
        block=block,
        transaction=transaction,
        transaction_index=0,
        log=log,
        log_index=0,
        is_pending=False,
    )

    expected_keys = [
        "type",
        "logIndex",
        "transactionIndex",
        "transactionHash",
        "blockHash",
        "blockNumber",
        "address",
        "data",
        "topics",
    ]

    assert sorted(list(serialized_log.keys())) == sorted(expected_keys)


def test_serialize_block_withdrawals_returns_camel_case_keys(
    withdrawals: Tuple[FakeWithdrawal, ...],
) -> None:
    block = FakeBlock(withdrawals=withdrawals)

    expected_keys = [
        "index",
        "validatorIndex",
        "address",
        "amount",
    ]

    serialized_block_withdrawals = serialize_block_withdrawals(block=block)

    for withdrawal in serialized_block_withdrawals:
        assert sorted(list(withdrawal.keys())) == sorted(expected_keys)
