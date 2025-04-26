from typing import (
    Any,
    Dict,
)

import pytest

from tests.utils import (
    ZERO_ADDRESS,
    Block,
    LogEntry,
    Receipt,
    Transaction,
)


# Transaction fixtures
@pytest.fixture
def transaction() -> Dict[str, Any]:
    return dict(Transaction())


@pytest.fixture
def transaction_with_auth_list() -> Dict[str, Any]:
    return dict(
        Transaction(
            authorization_list=(
                {
                    "chain_id": 1,
                    "address": ZERO_ADDRESS,
                    "nonce": 0,
                    "y_parity": 0,
                    "r": 0,
                    "s": 0,
                },
            ),
        )
    )


@pytest.fixture
def transaction_with_access_list() -> Dict[str, Any]:
    return dict(
        Transaction(
            access_list=(
                (
                    ZERO_ADDRESS,
                    b"\x00" * 32,
                ),
            ),
        )
    )


# Block fixtures
@pytest.fixture
def block() -> Dict[str, Any]:
    return dict(Block())


@pytest.fixture
def block_with_transactions() -> Dict[str, Any]:
    return dict(
        Block(
            transactions=(
                dict(Transaction(hash=b"\x00" * 32)),
                dict(Transaction(hash=b"\x01" * 32)),
            ),
        )
    )


@pytest.fixture
def block_with_transaction_hashes() -> Dict[str, Any]:
    return dict(
        Block(
            transactions=(
                b"\x00" * 32,
                b"\x01" * 32,
            ),
        )
    )


@pytest.fixture
def block_with_withdrawals() -> Dict[str, Any]:
    return dict(
        Block(
            withdrawals=(
                {
                    "index": 0,
                    "validator_index": 0,
                    "amount": 0,
                    "address": ZERO_ADDRESS,
                },
            ),
        )
    )


# LogEntry fixtures
@pytest.fixture
def log_entry() -> Dict[str, Any]:
    return dict(LogEntry())


# Receipt fixtures
@pytest.fixture
def receipt() -> Dict[str, Any]:
    return dict(Receipt())


@pytest.fixture
def receipt_with_logs() -> Dict[str, Any]:
    return dict(
        Receipt(
            logs=(
                dict(LogEntry(transaction_hash=b"\x00" * 32)),
                dict(LogEntry(transaction_hash=b"\x01" * 32)),
            ),
        )
    )
