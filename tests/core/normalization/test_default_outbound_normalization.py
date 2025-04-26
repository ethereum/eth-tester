import pytest
from eth_utils import (
    to_checksum_address,
)

from eth_tester.constants import (
    BLANK_ROOT_HASH,
    ZERO_ADDRESS_HEX,
)
from eth_tester.normalization import (
    DefaultNormalizer,
)
from tests.core.validation.test_inbound_validation import (
    _make_transaction,
)
from tests.core.validation.test_outbound_validation import (
    _make_dynamic_fee_txn,
)
from tests.utils import (
    ZERO_ADDRESS,
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
    assert normalized_receipt["contract_address"] == expected


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


def test_outbound_transaction_normalization() -> None:
    transaction = {
        "type": 2,
        "blob_versioned_hashes": (
            b"\x00" * 32,
            b"\x00" * 32,
            b"\x00" * 32,
            b"\x00" * 32,
        ),
        "chain_id": 131277322940537,
        "hash": b"\x00" * 32,
        "nonce": 0,
        "block_hash": b"\x00" * 32,
        "block_number": 0,
        "transaction_index": 0,
        "from": b"\x00" * 20,
        "to": b"\x00" * 20,
        "value": 0,
        "gas": 21000,
        "gas_price": 1,
        "max_fee_per_blob_gas": 1,
        "max_fee_per_gas": 2000000000,
        "max_priority_fee_per_gas": 1000000000,
        "data": b"",
        "access_list": (
            (
                b"\x00" * 20,
                (
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                ),
            ),
        ),
        "authorization_list": (
            {
                "chain_id": 1,
                "address": b"\x00" * 20,
                "nonce": 0,
                "y_parity": 0,
                "r": 0,
                "s": 0,
            },
        ),
        "r": 0,
        "s": 0,
        "v": 0,
        "y_parity": 0,
    }
    normalized_transaction = DefaultNormalizer.normalize_outbound_transaction(
        transaction
    )

    expected_normalized_transaction = {
        "type": "0x2",
        "blobVersionedHashes": (
            "0x" + "00" * 32,
            "0x" + "00" * 32,
            "0x" + "00" * 32,
            "0x" + "00" * 32,
        ),
        "chainId": 131277322940537,
        "hash": "0x" + "00" * 32,
        "nonce": 0,
        "blockHash": "0x" + "00" * 32,
        "blockNumber": 0,
        "transactionIndex": 0,
        "from": ZERO_ADDRESS_HEX,
        "to": ZERO_ADDRESS_HEX,
        "value": 0,
        "gas": 21000,
        "gasPrice": 1,
        "maxFeePerBlobGas": 1,
        "maxFeePerGas": 2000000000,
        "maxPriorityFeePerGas": 1000000000,
        "data": "0x",
        "accessList": (
            {
                "address": ZERO_ADDRESS_HEX,
                "storageKeys": (
                    "0x" + "00" * 31 + "01",
                    "0x" + "00" * 31 + "02",
                    "0x" + "00" * 31 + "03",
                    "0x" + "00" * 31 + "04",
                ),
            },
        ),
        "authorizationList": (
            {
                "chainId": 1,
                "address": ZERO_ADDRESS_HEX,
                "nonce": 0,
                "yParity": 0,
                "r": 0,
                "s": 0,
            },
        ),
        "r": 0,
        "s": 0,
        "v": 0,
        "yParity": 0,
    }
    assert normalized_transaction == expected_normalized_transaction


def test_outbound_block_normalization() -> None:
    block = {
        "number": 1,
        "hash": b"\x00" * 32,
        "parent_hash": b"\x00" * 32,
        "nonce": b"\x00" * 8,
        "base_fee_per_gas": 0,
        "sha3_uncles": b"\x00" * 32,
        "logs_bloom": 0,
        "transactions_root": b"\x00" * 32,
        "receipts_root": b"\x00" * 32,
        "state_root": b"\x00" * 32,
        "coinbase": b"\x00" * 20,
        "difficulty": 0,
        "mix_hash": b"\x00" * 32,
        "total_difficulty": 0,
        "size": 0,
        "extra_data": b"\x00" * 32,
        "gas_limit": 0,
        "gas_used": 0,
        "timestamp": 0,
        "transactions": (
            b"\x00" * 32,
            b"\x00" * 32,
        ),
        "uncles": (
            b"\x00" * 32,
            b"\x00" * 32,
        ),
        "withdrawals": (
            {
                "index": 0,
                "validator_index": 0,
                "amount": 0,
                "address": b"\x00" * 20,
            },
        ),
        "withdrawals_root": b"\x00" * 32,
        "parent_beacon_block_root": b"\x00" * 32,
        "blob_gas_used": 0,
        "excess_blob_gas": 0,
        "requests_hash": b"\x00" * 32,
    }

    normalized_block = DefaultNormalizer.normalize_outbound_block(block)
    expected_normalized_block = {
        "number": 1,
        "hash": "0x" + "00" * 32,
        "parentHash": "0x" + "00" * 32,
        "nonce": "0x" + "00" * 8,
        "baseFeePerGas": 0,
        "sha3Uncles": "0x" + "00" * 32,
        "logsBloom": 0,
        "transactionsRoot": "0x" + "00" * 32,
        "receiptsRoot": "0x" + "00" * 32,
        "stateRoot": "0x" + "00" * 32,
        "coinbase": ZERO_ADDRESS_HEX,
        "difficulty": 0,
        "mixHash": "0x" + "00" * 32,
        "totalDifficulty": 0,
        "size": 0,
        "extraData": "0x" + "00" * 32,
        "gasLimit": 0,
        "gasUsed": 0,
        "timestamp": 0,
        "transactions": (
            "0x" + "00" * 32,
            "0x" + "00" * 32,
        ),
        "uncles": (
            "0x" + "00" * 32,
            "0x" + "00" * 32,
        ),
        "withdrawals": (
            {
                "index": 0,
                "validatorIndex": 0,
                "amount": 0,
                "address": ZERO_ADDRESS_HEX,
            },
        ),
        "withdrawalsRoot": "0x" + "00" * 32,
        "parentBeaconBlockRoot": "0x" + "00" * 32,
        "blobGasUsed": 0,
        "excessBlobGas": 0,
        "requestsHash": "0x" + "00" * 32,
    }
    assert normalized_block == expected_normalized_block


def test_outbound_log_entry_normalization() -> None:
    log_entry = {
        "type": 1,
        "log_index": 0,
        "transaction_index": 0,
        "transaction_hash": b"\x00" * 32,
        "block_hash": b"\x00" * 32,
        "block_number": 0,
        "address": b"\x00" * 20,
        "data": b"\x00" * 32,
        "topics": (
            b"\x00" * 32,
            b"\x00" * 32,
        ),
    }

    normalized_log_entry = DefaultNormalizer.normalize_outbound_log_entry(log_entry)
    expected_normalized_log_entry = {
        "type": 1,
        "logIndex": 0,
        "transactionIndex": 0,
        "transactionHash": "0x" + "00" * 32,
        "blockHash": "0x" + "00" * 32,
        "blockNumber": 0,
        "address": ZERO_ADDRESS_HEX,
        "data": "0x" + "00" * 32,
        "topics": (
            "0x" + "00" * 32,
            "0x" + "00" * 32,
        ),
    }
    assert normalized_log_entry == expected_normalized_log_entry


def test_outbound_receipt_normalization() -> None:
    receipt = {
        "transaction_hash": b"\x00" * 32,
        "transaction_index": 0,
        "block_number": 0,
        "block_hash": b"\x00" * 32,
        "cumulative_gas_used": 21000,
        "effective_gas_price": 1,
        "from": b"\x00" * 20,
        "gas_used": 21000,
        "contract_address": b"\x00" * 20,
        "logs": (
            {
                "address": b"\x00" * 20,
                "data": b"\x00" * 32,
                "topics": (
                    b"\x00" * 32,
                    b"\x00" * 32,
                ),
            },
        ),
        "state_root": BLANK_ROOT_HASH,
        "status": 1,
        "to": b"\x00" * 20,
        "type": 1,
        "base_fee_per_gas": 1,
        "blob_gas_used": 1,
        "blob_gas_price": 1,
    }

    normalized_receipt = DefaultNormalizer.normalize_outbound_receipt(receipt)
    expected_normalized_receipt = {
        "transactionHash": "0x" + "00" * 32,
        "transactionIndex": 0,
        "blockNumber": 0,
        "blockHash": "0x" + "00" * 32,
        "cumulativeGasUsed": 21000,
        "effectiveGasPrice": 1,
        "from": ZERO_ADDRESS_HEX,
        "gasUsed": 21000,
        "contractAddress": ZERO_ADDRESS_HEX,
        "logs": (
            {
                "address": ZERO_ADDRESS_HEX,
                "data": "0x" + "00" * 32,
                "topics": (
                    "0x" + "00" * 32,
                    "0x" + "00" * 32,
                ),
            },
        ),
        "stateRoot": BLANK_ROOT_HASH,
        "status": 1,
        "to": ZERO_ADDRESS_HEX,
        "type": "0x1",
        "baseFeePerGas": 1,
        "blobGasUsed": 1,
        "blobGasPrice": 1,
    }
    assert normalized_receipt == expected_normalized_receipt
