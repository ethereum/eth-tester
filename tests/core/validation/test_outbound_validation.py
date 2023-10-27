from __future__ import (
    unicode_literals,
)

from eth_utils import (
    encode_hex,
)
import pytest
from toolz import (
    dissoc,
    merge,
)

from eth_tester.exceptions import (
    ValidationError,
)
from eth_tester.validation import (
    DefaultValidator,
)
from tests.utils import (
    make_receipt,
)


@pytest.fixture
def validator():
    _validator = DefaultValidator()
    return _validator


@pytest.mark.parametrize(
    "block_hash,is_valid",
    (
        (1, False),
        (True, False),
        (b"\x00" * 32, True),
        (b"\xff" * 32, True),
        ("\x00" * 32, False),
        (encode_hex(b"\x00" * 32), False),
    ),
)
def test_block_hash_output_validation(validator, block_hash, is_valid):
    if is_valid:
        validator.validate_outbound_block_hash(block_hash)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_block_hash(block_hash)


ZERO_32BYTES = b"\x00" * 32
ZERO_8BYTES = b"\x00" * 8
ZERO_ADDRESS = b"\x00" * 20


ADDRESS_A = b"\x00" * 19 + b"\x01"
TOPIC_A = b"\x00" * 31 + b"\x01"
TOPIC_B = b"\x00" * 31 + b"\x02"
HASH32_AS_TEXT = "\x00" * 32
HASH31 = b"\x00" * 31


def _make_legacy_txn(
    hash=ZERO_32BYTES,
    nonce=0,
    block_hash=ZERO_32BYTES,
    block_number=0,
    transaction_index=0,
    _from=ZERO_ADDRESS,
    to=ZERO_ADDRESS,
    value=0,
    gas=21000,
    gas_price=1,
    data=b"",
    v=0,
    r=0,
    s=0,
):
    return {
        "type": "0x0",
        "hash": hash,
        "nonce": nonce,
        "block_hash": block_hash,
        "block_number": block_number,
        "transaction_index": transaction_index,
        "from": _from,
        "to": to,
        "value": value,
        "gas": gas,
        "gas_price": gas_price,
        "data": data,
        "v": v,
        "r": r,
        "s": s,
    }


def _make_access_list_txn(
    chain_id=131277322940537,
    access_list=(),
    **kwargs,
):
    legacy_kwargs = dissoc(dict(**kwargs), "chain_id", "access_list")
    return merge(
        _make_legacy_txn(**legacy_kwargs),
        {
            "type": "0x1",
            "chain_id": chain_id,
            "access_list": list(access_list),
        },
    )


# This is an outbound transaction so we still keep the gas_price for now since the
# gas_price is the min(max_fee_per_gas, base_fee_per_gas + max_priority_fee_per_gas).
# TODO: Sometime in 2022 the inclusion of gas_price may be removed from dynamic fee
#  transactions and we can get rid of this behavior.
#  https://github.com/ethereum/execution-specs/pull/251
def _make_dynamic_fee_txn(
    chain_id=131277322940537,
    max_fee_per_gas=2000000000,
    max_priority_fee_per_gas=1000000000,
    access_list=(),
    **kwargs,
):
    legacy_kwargs = dissoc(
        dict(**kwargs),
        "chain_id",
        "max_fee_per_gas",
        "max_priority_fee_per_gas",
        "access_list",
    )
    return merge(
        _make_access_list_txn(
            chain_id=chain_id, access_list=access_list, **legacy_kwargs
        ),
        {
            "type": "0x2",
            "max_fee_per_gas": max_fee_per_gas,
            "max_priority_fee_per_gas": max_priority_fee_per_gas,
        },
    )


@pytest.mark.parametrize(
    "transaction,is_valid",
    (
        (_make_legacy_txn(), True),
        (_make_access_list_txn(), True),
        (_make_dynamic_fee_txn(), True),
        (_make_legacy_txn(hash=HASH32_AS_TEXT), False),
        (_make_legacy_txn(hash=HASH31), False),
        (_make_legacy_txn(nonce=-1), False),
        (_make_legacy_txn(nonce=1.0), False),
        (_make_legacy_txn(nonce=True), False),
        (_make_legacy_txn(value=-1), False),
        (_make_legacy_txn(value=1.0), False),
        (_make_legacy_txn(value=True), False),
        (_make_legacy_txn(block_number=-1), False),
        (_make_legacy_txn(block_number=1.0), False),
        (_make_legacy_txn(block_number=True), False),
        (_make_legacy_txn(gas=-1), False),
        (_make_legacy_txn(gas=1.0), False),
        (_make_legacy_txn(gas=True), False),
        (_make_legacy_txn(gas_price=-1), False),
        (_make_legacy_txn(gas_price=1.0), False),
        (_make_legacy_txn(gas_price=True), False),
        (_make_legacy_txn(data=""), False),
        (_make_legacy_txn(data="0x"), False),
        (_make_legacy_txn(block_hash=HASH32_AS_TEXT), False),
        (_make_legacy_txn(block_hash=HASH31), False),
        (
            _make_legacy_txn(
                transaction_index=None, block_hash=None, block_number=None
            ),
            True,
        ),
        (
            _make_access_list_txn(
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            True,
        ),
        (
            _make_dynamic_fee_txn(
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            True,
        ),
        (_make_access_list_txn(chain_id="1"), False),
        (_make_dynamic_fee_txn(chain_id="1"), False),
        (_make_access_list_txn(chain_id=-1), False),
        (_make_dynamic_fee_txn(chain_id=-1), False),
        (_make_access_list_txn(chain_id=None), False),
        (_make_dynamic_fee_txn(chain_id=None), False),
        (_make_legacy_txn(v=0), True),
        (_make_dynamic_fee_txn(v=0), True),
        (_make_access_list_txn(v=0), True),
        (_make_legacy_txn(v=1), True),
        (_make_dynamic_fee_txn(v=1), True),
        (_make_access_list_txn(v=1), True),
        (_make_legacy_txn(v=27), True),
        (_make_access_list_txn(v=27), False),
        (_make_dynamic_fee_txn(v=27), False),
        (_make_dynamic_fee_txn(max_fee_per_gas=1.0), False),
        (_make_dynamic_fee_txn(max_priority_fee_per_gas=1.0), False),
        (_make_dynamic_fee_txn(max_fee_per_gas="1"), False),
        (_make_dynamic_fee_txn(max_priority_fee_per_gas="1"), False),
        (
            _make_access_list_txn(
                access_list=((b"\xf0" * 20, (0, 2)),),
            ),
            True,
        ),
        (
            _make_dynamic_fee_txn(
                access_list=((b"\xef" * 20, (1, 2, 3, 4)),),
            ),
            True,
        ),
        (_make_access_list_txn(access_list=()), True),
        (_make_dynamic_fee_txn(access_list=()), True),
        (
            _make_access_list_txn(
                access_list=((b"\xf0" * 19, (0, 2)),),
            ),
            False,
        ),
        (
            _make_dynamic_fee_txn(
                access_list=((b"\xf0" * 19, ()),),
            ),
            False,
        ),
        (
            _make_access_list_txn(
                access_list=((b"\xf0" * 20, ("0", 2)),),
            ),
            False,
        ),
        (
            _make_dynamic_fee_txn(
                access_list=((b"\xf0" * 20, (b"", 1)),),
            ),
            False,
        ),
        (
            _make_dynamic_fee_txn(
                access_list=(("", (1, 2)),),
            ),
            False,
        ),
    ),
)
def test_transaction_output_validation(validator, transaction, is_valid):
    if is_valid:
        validator.validate_outbound_transaction(transaction)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_transaction(transaction)


def _make_log(
    _type="mined",
    log_index=0,
    transaction_index=0,
    transaction_hash=ZERO_32BYTES,
    block_hash=ZERO_32BYTES,
    block_number=0,
    address=ZERO_ADDRESS,
    data=b"",
    topics=None,
):
    return {
        "type": _type,
        "log_index": log_index,
        "transaction_index": transaction_index,
        "transaction_hash": transaction_hash,
        "block_hash": block_hash,
        "block_number": block_number,
        "address": address,
        "data": data,
        "topics": topics or [],
    }


@pytest.mark.parametrize(
    "log_entry,is_valid",
    (
        (_make_log(), True),
        (
            _make_log(
                _type="pending",
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            True,
        ),
        (_make_log(_type="invalid-type"), False),
        (_make_log(transaction_index=-1), False),
        (_make_log(block_number=-1), False),
        (_make_log(transaction_hash=HASH31), False),
        (_make_log(transaction_hash=HASH32_AS_TEXT), False),
        (_make_log(block_hash=HASH31), False),
        (_make_log(block_hash=HASH32_AS_TEXT), False),
        (_make_log(address=encode_hex(ADDRESS_A)), False),
        (_make_log(data=""), False),
        (_make_log(data=None), False),
        (_make_log(topics=[HASH32_AS_TEXT]), False),
        (_make_log(topics=[HASH31]), False),
        (_make_log(topics=[TOPIC_A, TOPIC_B]), True),
        (_make_log(address=ADDRESS_A), True),
    ),
)
def test_log_entry_output_validation(validator, log_entry, is_valid):
    if is_valid:
        validator.validate_outbound_log_entry(log_entry)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_log_entry(log_entry)


@pytest.mark.parametrize(
    "receipt,is_valid",
    (
        (make_receipt(), True),
        (make_receipt(transaction_hash=HASH32_AS_TEXT), False),
        (make_receipt(transaction_hash=HASH31), False),
        (make_receipt(block_hash=HASH32_AS_TEXT), False),
        (make_receipt(block_hash=HASH31), False),
        (make_receipt(transaction_index=-1), False),
        (make_receipt(transaction_index=1.0), False),
        (make_receipt(transaction_index=True), False),
        (make_receipt(block_number=-1), False),
        (make_receipt(block_number=1.0), False),
        (make_receipt(block_number=True), False),
        (make_receipt(gas_used=-1), False),
        (make_receipt(gas_used=1.0), False),
        (make_receipt(gas_used=True), False),
        (make_receipt(cumulative_gas_used=-1), False),
        (make_receipt(cumulative_gas_used=1.0), False),
        (make_receipt(cumulative_gas_used=True), False),
        (make_receipt(contract_address=ZERO_ADDRESS), True),
        (make_receipt(contract_address=encode_hex(ZERO_ADDRESS)), False),
        (make_receipt(logs=[_make_log()]), True),
        (make_receipt(logs=[_make_log(_type="invalid")]), False),
        (make_receipt(_from=ADDRESS_A, to=ADDRESS_A), True),
        (make_receipt(_from=ADDRESS_A, to=ZERO_ADDRESS), True),
        (make_receipt(_from=encode_hex(ZERO_ADDRESS), to=ADDRESS_A), False),
        (make_receipt(_from=ADDRESS_A, to=encode_hex(ZERO_ADDRESS)), False),
        (make_receipt(status=0), True),
        (make_receipt(status=1), True),
        (make_receipt(status=2), False),
        (make_receipt(status=-1), False),
    ),
)
def test_receipt_output_validation(validator, receipt, is_valid):
    if is_valid:
        validator.validate_outbound_receipt(receipt)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_receipt(receipt)


def _make_block(
    number=0,
    hash=ZERO_32BYTES,
    parent_hash=ZERO_32BYTES,
    nonce=ZERO_8BYTES,
    sha3_uncles=ZERO_32BYTES,
    logs_bloom=0,
    transactions_root=ZERO_32BYTES,
    receipts_root=ZERO_32BYTES,
    state_root=ZERO_32BYTES,
    coinbase=ZERO_ADDRESS,
    difficulty=0,
    mix_hash=ZERO_32BYTES,
    total_difficulty=0,
    size=0,
    extra_data=ZERO_32BYTES,
    gas_limit=30029122,  # gas limit at London fork block 12965000 on mainnet
    gas_used=21000,
    timestamp=4000000,
    transactions=None,
    uncles=None,
    base_fee_per_gas=1000000000,
    withdrawals=None,
    withdrawals_root=ZERO_32BYTES,
):
    block = {
        "number": number,
        "hash": hash,
        "parent_hash": parent_hash,
        "nonce": nonce,
        "sha3_uncles": sha3_uncles,
        "logs_bloom": logs_bloom,
        "transactions_root": transactions_root,
        "receipts_root": receipts_root,
        "state_root": state_root,
        "coinbase": coinbase,
        "difficulty": difficulty,
        "mix_hash": mix_hash,
        "total_difficulty": total_difficulty,
        "size": size,
        "extra_data": extra_data,
        "gas_limit": gas_limit,
        "gas_used": gas_used,
        "timestamp": timestamp,
        "transactions": transactions or [],
        "uncles": uncles or [],
        "base_fee_per_gas": base_fee_per_gas,
        "withdrawals": withdrawals or [],
        "withdrawals_root": withdrawals_root,
    }
    return block


def _make_withdrawal(
    index: int = 2**64 - 1,
    validator_index: int = 2**64 - 1,
    address: bytes = ZERO_ADDRESS,
    amount: int = 2**64 - 1,
):
    return {
        "index": index,
        "validator_index": validator_index,
        "address": address,
        "amount": amount,
    }


@pytest.mark.parametrize(
    "block,is_valid",
    (
        (_make_block(), True),
        (_make_block(number=-1), False),
        (_make_block(number=1.0), False),
        (_make_block(number=True), False),
        (_make_block(hash=HASH32_AS_TEXT), False),
        (_make_block(hash=HASH31), False),
        (_make_block(parent_hash=HASH32_AS_TEXT), False),
        (_make_block(parent_hash=HASH31), False),
        (_make_block(nonce=-1), False),
        (_make_block(nonce=1.0), False),
        (_make_block(nonce=True), False),
        (_make_block(sha3_uncles=HASH32_AS_TEXT), False),
        (_make_block(logs_bloom=-1), False),
        (_make_block(logs_bloom=1.0), False),
        (_make_block(logs_bloom=True), False),
        (_make_block(transactions_root=HASH32_AS_TEXT), False),
        (_make_block(transactions_root=HASH31), False),
        (_make_block(receipts_root=HASH32_AS_TEXT), False),
        (_make_block(receipts_root=HASH31), False),
        (_make_block(state_root=HASH32_AS_TEXT), False),
        (_make_block(state_root=HASH31), False),
        (_make_block(coinbase=encode_hex(ADDRESS_A)), False),
        (_make_block(difficulty=-1), False),
        (_make_block(difficulty=1.0), False),
        (_make_block(difficulty=True), False),
        (_make_block(mix_hash=HASH32_AS_TEXT), False),
        (_make_block(mix_hash=HASH31), False),
        (_make_block(total_difficulty=-1), False),
        (_make_block(total_difficulty=1.0), False),
        (_make_block(total_difficulty=True), False),
        (_make_block(size=-1), False),
        (_make_block(size=1.0), False),
        (_make_block(size=True), False),
        (_make_block(extra_data=HASH32_AS_TEXT), False),
        (_make_block(extra_data=HASH31), False),
        (_make_block(gas_limit=-1), False),
        (_make_block(gas_limit=1.0), False),
        (_make_block(gas_limit=True), False),
        (_make_block(gas_used=-1), False),
        (_make_block(gas_used=1.0), False),
        (_make_block(gas_used=True), False),
        (_make_block(timestamp=-1), False),
        (_make_block(timestamp=1.0), False),
        (_make_block(timestamp=True), False),
        (_make_block(base_fee_per_gas=1000000000), True),
        (_make_block(base_fee_per_gas=-1000000000), False),
        (_make_block(base_fee_per_gas=1000000000.0), False),
        (_make_block(base_fee_per_gas="1000000000"), False),
        (_make_block(uncles=[ZERO_32BYTES]), True),
        (_make_block(uncles=[ZERO_32BYTES, HASH32_AS_TEXT]), False),
        (_make_block(transactions=[ZERO_32BYTES]), True),
        (_make_block(transactions=[_make_legacy_txn()]), True),
        (_make_block(transactions=[ZERO_32BYTES, _make_legacy_txn()]), False),
        (_make_block(transactions=[_make_access_list_txn()]), True),
        (_make_block(transactions=[ZERO_32BYTES, _make_access_list_txn()]), False),
        (_make_block(transactions=[_make_dynamic_fee_txn()]), True),
        (_make_block(transactions=[ZERO_32BYTES, _make_dynamic_fee_txn()]), False),
        (_make_block(transactions=[ZERO_32BYTES, HASH32_AS_TEXT]), False),
        (_make_block(withdrawals=[_make_withdrawal()]), True),
        (_make_block(withdrawals=[_make_withdrawal(address=ADDRESS_A)]), True),
        (_make_block(withdrawals=[_make_withdrawal(index=-1)]), False),
        (_make_block(withdrawals=[_make_withdrawal(index=2**64)]), False),
        (_make_block(withdrawals=[_make_withdrawal(validator_index=-1)]), False),
        (_make_block(withdrawals=[_make_withdrawal(validator_index=2**64)]), False),
        (_make_block(withdrawals=[_make_withdrawal(amount=-1)]), False),
        (_make_block(withdrawals=[_make_withdrawal(amount=2**64)]), False),
        (_make_block(withdrawals=[_make_withdrawal(address="1")]), False),
        (
            _make_block(
                withdrawals=[_make_withdrawal(address=encode_hex(ZERO_ADDRESS))]
            ),
            False,
        ),
    ),
)
def test_block_output_validation(validator, block, is_valid):
    if is_valid:
        validator.validate_outbound_block(block)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_block(block)


@pytest.mark.parametrize(
    "accounts,is_valid",
    (
        ([ADDRESS_A], True),
        ([ADDRESS_A, encode_hex(ADDRESS_A)], False),
    ),
)
def test_accounts_output_validation(validator, accounts, is_valid):
    if is_valid:
        validator.validate_outbound_accounts(accounts)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_accounts(accounts)
