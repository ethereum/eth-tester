import pytest
from eth_utils import (
    to_checksum_address,
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
        "from": "0x0000000000000000000000000000000000000000",
        "to": "0x0000000000000000000000000000000000000000",
        "value": 0,
        "gas": 21000,
        "gasPrice": 1,
        "maxFeePerBlobGas": 1,
        "maxFeePerGas": 2000000000,
        "maxPriorityFeePerGas": 1000000000,
        "data": "0x",
        "accessList": (
            {
                "address": "0x0000000000000000000000000000000000000000",
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
                "address": "0x0000000000000000000000000000000000000000",
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
