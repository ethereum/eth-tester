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
)
from ethereum.cancun.transactions import (
    LegacyTransaction,
)

from eth_tester.backends.eels.main import (
    EELSBackend,
)
from eth_tester.backends.eels.serializers import (
    serialize_block,
    serialize_pending_logs,
    serialize_pending_receipt,
    serialize_transaction,
)


def test_serialize_block_returns_camel_case_keys(
    block: Union[Block, Dict[str, Any]],
) -> None:
    is_pending = isinstance(block, dict)
    if isinstance(block, Block):
        # Finalized blocks
        num_transactions = len(block.transactions)
        num_withdrawals = len(block.withdrawals)
        transaction = block.transactions[0] if num_transactions > 0 else None
    elif isinstance(block, dict):
        # Pending blocks
        num_transactions = len(block["transactions"])
        num_withdrawals = len(block["withdrawals"])
        transaction = block["transactions"][0] if num_transactions > 0 else None

    full_transactions = False if isinstance(transaction, bytes) else True

    serialized_block = serialize_block(
        EELSBackend(),
        block,
        full_transactions=full_transactions,
        is_pending=is_pending,
    )

    expected_keys = [
        "number",
        "hash",
        "parentHash",
        "nonce",
        "stateRoot",
        "coinbase",
        "transactionsRoot",
        "receiptsRoot",
        "logsBloom",
        "gasLimit",
        "gasUsed",
        "timestamp",
        "withdrawalsRoot",
        "baseFeePerGas",
        "blobGasUsed",
        "excessBlobGas",
        "transactions",
        "uncles",
        "withdrawals",
        "sha3Uncles",
        "difficulty",
        "totalDifficulty",
        "mixHash",
        "size",
        "extraData",
    ]

    if not is_pending:
        expected_keys.append("parentBeaconBlockRoot")

    assert sorted(list(serialized_block.keys())) == sorted(expected_keys)

    if num_transactions > 0 and full_transactions:
        txns: List[Dict[str, Any]] = serialized_block["transactions"]

        for txn in txns:
            valid_transaction_keys = [
                "type",
                "hash",
                "nonce",
                "blockHash",
                "blockNumber",
                "transactionIndex",
                "gas",
                "to",
                "from",
                "value",
                "data",
                "r",
                "s",
                "v",
                "gasPrice",
                "chainId",
                "maxPriorityFeePerGas",
                "maxFeePerGas",
                "accessList",
                "maxFeePerBlobGas",
                "blobVersionedHashes",
                "yParity",
            ]

            # Check all transaction keys are valid
            for key in txn.keys():
                assert (
                    key in valid_transaction_keys
                ), f"Invalid transaction key found: {key}"

    if num_withdrawals > 0:
        withdrawals = serialized_block["withdrawals"]

        for withdrawal in withdrawals:
            valid_withdrawal_keys = [
                "index",
                "validatorIndex",
                "address",
                "amount",
            ]

            # Check all withdrawal keys are valid
            for key in withdrawal.keys():
                assert (
                    key in valid_withdrawal_keys
                ), f"Invalid withdrawal key found: {key}"


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
