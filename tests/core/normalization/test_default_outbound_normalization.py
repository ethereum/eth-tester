import pytest

from eth_tester.constants import (
    BLANK_ROOT_HASH,
    ZERO_ADDRESS_HEX,
)
from eth_tester.normalization import (
    DefaultNormalizer,
)
from tests.core.normalization.conftest import (
    Block,
    LogEntry,
    Receipt,
    Transaction,
)
from tests.utils import (
    make_receipt,
)


@pytest.mark.parametrize(
    "status,contract_address,expected",
    (
        (1, b"\x01" * 20, f"0x{'01' * 20}"),
        (0, b"\x01" * 20, None),
    ),
)
def test_outbound_receipt_contract_address_status_based_normalization(
    status,
    contract_address,
    expected,
):
    receipt = make_receipt(status=status, contract_address=contract_address)

    assert receipt["status"] == status
    assert receipt["contract_address"] == contract_address

    normalized_receipt = DefaultNormalizer.normalize_outbound_receipt(receipt)

    assert normalized_receipt["status"] == status
    assert normalized_receipt["contractAddress"] == expected


@pytest.mark.parametrize(
    "value,expected",
    (
        (0, f"0x{'00'*32}"),
        (1, f"0x{'00'*31}01"),
        (2, f"0x{'00'*31}02"),
    ),
)
def test_outbound_storage_normalization(value, expected):
    assert DefaultNormalizer.normalize_outbound_storage(value) == expected


def test_outbound_transaction_keys_normalization(transaction: Transaction) -> None:
    normalized_transaction = DefaultNormalizer.normalize_outbound_transaction(
        transaction
    )

    expected_transaction_keys = [
        "type",
        "blobVersionedHashes",
        "chainId",
        "hash",
        "nonce",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "from",
        "to",
        "value",
        "gas",
        "gasPrice",
        "maxFeePerBlobGas",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "data",
        "accessList",
        "authorizationList",
        "r",
        "s",
        "v",
        "yParity",
    ]
    assert sorted(list(dict(normalized_transaction).keys())) == sorted(
        expected_transaction_keys
    )


def test_outbound_transaction_access_list_keys_normalization(
    transaction_with_access_list: Transaction,
) -> None:
    normalized_transaction = DefaultNormalizer.normalize_outbound_transaction(
        transaction_with_access_list
    )
    expected_access_list_keys = [
        "address",
        "storageKeys",
    ]
    assert sorted(list(dict(normalized_transaction["accessList"][0]).keys())) == sorted(
        expected_access_list_keys
    )


def test_outbound_transaction_auth_list_keys_normalization(
    transaction_with_auth_list: Transaction,
) -> None:
    normalized_transaction = DefaultNormalizer.normalize_outbound_transaction(
        transaction_with_auth_list
    )
    expected_auth_list_keys = [
        "chainId",
        "address",
        "nonce",
        "yParity",
        "r",
        "s",
    ]
    assert sorted(
        list(dict(normalized_transaction["authorizationList"][0]).keys())
    ) == sorted(expected_auth_list_keys)


def test_outbound_block_keys_normalization(block: Block) -> None:
    normalized_block = DefaultNormalizer.normalize_outbound_block(block)

    expected_block_keys = [
        "number",
        "hash",
        "parentHash",
        "nonce",
        "baseFeePerGas",
        "sha3Uncles",
        "logsBloom",
        "transactionsRoot",
        "receiptsRoot",
        "stateRoot",
        "coinbase",
        "difficulty",
        "mixHash",
        "totalDifficulty",
        "size",
        "extraData",
        "gasLimit",
        "gasUsed",
        "timestamp",
        "transactions",
        "uncles",
        "withdrawals",
        "withdrawalsRoot",
        "parentBeaconBlockRoot",
        "blobGasUsed",
        "excessBlobGas",
        "requestsHash",
    ]
    assert sorted(list(dict(normalized_block).keys())) == sorted(expected_block_keys)


def test_outbound_block_transaction_object_keys_normalization(
    block_with_transactions: Block,
) -> None:
    normalized_block = DefaultNormalizer.normalize_outbound_block(
        block_with_transactions
    )

    expected_transaction_keys = [
        "type",
        "blobVersionedHashes",
        "chainId",
        "hash",
        "nonce",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "from",
        "to",
        "value",
        "gas",
        "gasPrice",
        "maxFeePerBlobGas",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "data",
        "accessList",
        "authorizationList",
        "r",
        "s",
        "v",
        "yParity",
    ]
    assert sorted(list(dict(normalized_block["transactions"][0]).keys())) == sorted(
        expected_transaction_keys
    )


def test_outbound_block_withdrawals_keys_normalization(
    block_with_withdrawals: Block,
) -> None:
    normalized_block = DefaultNormalizer.normalize_outbound_block(
        block_with_withdrawals
    )

    expected_withdrawals_keys = [
        "index",
        "validatorIndex",
        "amount",
        "address",
    ]
    assert sorted(list(dict(normalized_block["withdrawals"][0]).keys())) == sorted(
        expected_withdrawals_keys
    )


def test_outbound_log_entry_keys_normalization(log_entry: LogEntry) -> None:
    normalized_log_entry = DefaultNormalizer.normalize_outbound_log_entry(log_entry)

    expected_log_entry_keys = [
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
    assert sorted(list(dict(normalized_log_entry).keys())) == sorted(
        expected_log_entry_keys
    )


def test_outbound_receipt_keys_normalization(receipt: Receipt) -> None:
    normalized_receipt = DefaultNormalizer.normalize_outbound_receipt(receipt)
    expected_receipt_keys = [
        "transactionHash",
        "transactionIndex",
        "blockNumber",
        "blockHash",
        "cumulativeGasUsed",
        "effectiveGasPrice",
        "from",
        "gasUsed",
        "contractAddress",
        "logs",
        "stateRoot",
        "status",
        "to",
        "type",
        "baseFeePerGas",
        "blobGasUsed",
        "blobGasPrice",
    ]
    assert sorted(list(dict(normalized_receipt).keys())) == sorted(
        expected_receipt_keys
    )


def test_outbound_receipt_log_entry_keys_normalization(
    receipt_with_logs: Receipt,
) -> None:
    normalized_receipt = DefaultNormalizer.normalize_outbound_receipt(receipt_with_logs)

    expected_log_entry_keys = [
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
    assert sorted(list(dict(normalized_receipt["logs"][0]).keys())) == sorted(
        expected_log_entry_keys
    )
