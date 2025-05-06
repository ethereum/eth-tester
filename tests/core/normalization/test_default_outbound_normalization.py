import pytest
from typing import (
    Any,
)

from eth_tester.normalization import (
    DefaultNormalizer,
)
from tests.utils import (
    make_blob_txn,
    make_block,
    make_log,
    make_receipt,
    make_withdrawal,
)


@pytest.mark.parametrize(
    "value,expected",
    (
        (b"\x01" * 20, f"0x{'01' * 20}"),
        (f"0x{'01' * 20}", f"0x{'01' * 20}"),
        (b"\x01" * 32, None),
        (b"\x01" * 21, None),
        (b"\x01" * 19, None),
        (b"\x01" * 0, None),
        (b"\x01" * 1, None),
    ),
)
def test_outbound_account_normalization(value: Any, expected: Any) -> None:
    if expected:
        assert DefaultNormalizer.normalize_outbound_account(value) == expected
    else:
        with pytest.raises(ValueError):
            DefaultNormalizer.normalize_outbound_account(value)


def test_outbound_block_normalization() -> None:
    block = make_block()

    block["number"] = 1
    block["hash"] = b"\x01" * 32
    block["coinbase"] = b"\x01" * 20
    block["logsBloom"] = 1
    block["withdrawals"] = [
        make_withdrawal(
            index=0,
            validator_index=0,
            amount=0,
            address=b"\x01" * 20,
        )
    ]

    normalized_block = DefaultNormalizer.normalize_outbound_block(block)

    assert normalized_block["number"] == 1
    assert normalized_block["hash"] == f"0x{'01' * 32}"
    assert normalized_block["coinbase"] == f"0x{'01' * 20}"
    assert normalized_block["logsBloom"] == 1
    assert normalized_block["withdrawals"] == [
        {
            "index": 0,
            "validatorIndex": 0,
            "amount": 0,
            "address": f"0x{'01' * 20}",
        }
    ]


@pytest.mark.parametrize(
    "value,expected",
    (
        (b"\x01" * 32, f"0x{'01' * 32}"),
        (
            f"0x{'01' * 2}",
            "0x307830313031",
        ),
        ("0x01", "0x30783031"),
        (b"\x01" * 20, "0x0101010101010101010101010101010101010101"),
        (b"\x01", "0x01"),
    ),
)
def test_outbound_block_hash_normalization(value: Any, expected: Any) -> None:
    normalized_block_hash = DefaultNormalizer.normalize_outbound_block_hash(value)

    assert normalized_block_hash == expected


def test_outbound_log_entry_normalization() -> None:
    log_entry = make_log()

    log_entry["address"] = b"\x01" * 20
    log_entry["data"] = b"\x01" * 32
    log_entry["blockHash"] = b"\x01" * 32

    normalized_log_entry = DefaultNormalizer.normalize_outbound_log_entry(log_entry)

    assert normalized_log_entry["address"] == f"0x{'01' * 20}"
    assert normalized_log_entry["data"] == f"0x{'01' * 32}"
    assert normalized_log_entry["blockHash"] == f"0x{'01' * 32}"


def test_outbound_transaction_normalization() -> None:
    transaction = make_blob_txn()

    transaction["from"] = b"\x01" * 20
    transaction["data"] = b""
    transaction["accessList"] = [(b"\x01" * 20, (1, 2, 3))]

    normalized_transaction = DefaultNormalizer.normalize_outbound_transaction(
        transaction
    )

    assert normalized_transaction["from"] == f"0x{'01' * 20}"
    assert normalized_transaction["data"] == "0x"
    assert normalized_transaction["accessList"] == (
        {
            "address": f"0x{'01' * 20}",
            "storageKeys": (
                "0x0000000000000000000000000000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000000000000000000000000000003",
            ),
        },
    )


@pytest.mark.parametrize(
    "status,contract_address,expected",
    (
        (1, b"\x01" * 20, f"0x{'01' * 20}"),
        (0, b"\x01" * 20, None),
    ),
)
def test_outbound_receipt_contract_address_status_based_normalization(
    status: Any,
    contract_address: Any,
    expected: Any,
) -> None:
    receipt = make_receipt(status=status, contract_address=contract_address)

    assert receipt["status"] == status
    assert receipt["contractAddress"] == contract_address

    normalized_receipt = DefaultNormalizer.normalize_outbound_receipt(receipt)

    assert normalized_receipt["status"] == status
    assert normalized_receipt["contractAddress"] == expected


@pytest.mark.parametrize(
    "value,expected",
    (
        (0, f"0x{'00'*32}"),
        (1, f"0x{'00'*31}01"),
        (2, f"0x{'00'*31}02"),
        (None, None),
        ("invalid-value", None),
    ),
)
def test_outbound_storage_normalization(value: Any, expected: Any) -> None:
    if expected:
        assert DefaultNormalizer.normalize_outbound_storage(value) == expected
    else:
        with pytest.raises(AttributeError):
            DefaultNormalizer.normalize_outbound_storage(value)
