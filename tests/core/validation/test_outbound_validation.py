from typing import (
    Any,
)

import pytest
from eth_utils import (
    encode_hex,
)
from toolz import (
    merge,
)

from eth_tester.exceptions import (
    ValidationError,
)
from eth_tester.validation import (
    DefaultValidator,
)
from tests.constants import (
    ADDRESS_A,
    HASH31,
    HASH32_AS_TEXT,
    TOPIC_A,
    TOPIC_B,
    ZERO_32BYTES,
    ZERO_ADDRESS,
)
from tests.utils import (
    make_access_list_txn,
    make_blob_txn,
    make_block,
    make_dynamic_fee_txn,
    make_legacy_txn,
    make_log,
    make_receipt,
    make_withdrawal,
)


@pytest.mark.parametrize(
    "block_hash,is_valid",
    (
        pytest.param(ZERO_32BYTES, True, id="valid_bytes_all_zero"),
        pytest.param(b"\xff" * 32, True, id="valid_bytes_all_ff"),
        pytest.param(b"\x00", False, id="invalid_bytes_short"),
        pytest.param("\x00" * 32, False, id="invalid_str"),
        pytest.param(encode_hex(ZERO_32BYTES), False, id="invalid_hex"),
        pytest.param(1, False, id="invalid_int"),
        pytest.param(True, False, id="invalid_bool"),
    ),
)
def test_block_hash_output_validation(
    validator: DefaultValidator, block_hash: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_outbound_block_hash(block_hash)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_block_hash(block_hash)


@pytest.mark.parametrize(
    "value,is_valid",
    [(ZERO_32BYTES, True), (ZERO_32BYTES + b"\x00", False), (b"0x", False), (1, False)],
    ids=["valid", "invalid_too_long", "invalid_hex", "invalid_int"],
)
def test_validate_outbound_transaction_hash(
    validator: DefaultValidator,
    value: Any,
    is_valid: bool,
) -> None:
    if is_valid:
        validator.validate_outbound_transaction_hash(value)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_transaction_hash(value)


@pytest.mark.parametrize(
    "transaction,is_valid",
    (
        pytest.param(make_legacy_txn(), True, id="valid_legacy_txn"),
        pytest.param(make_access_list_txn(), True, id="valid_access_list_txn"),
        pytest.param(make_dynamic_fee_txn(), True, id="valid_dynamic_fee_txn"),
        pytest.param(make_blob_txn(), True, id="valid_blob_txn"),
        pytest.param(
            make_legacy_txn(hash=HASH32_AS_TEXT), False, id="invalid_text_hash"
        ),
        pytest.param(make_legacy_txn(hash=HASH31), False, id="invalid_short_hash"),
        pytest.param(make_legacy_txn(nonce=-1), False, id="invalid_negative_nonce"),
        pytest.param(make_legacy_txn(nonce=1.0), False, id="invalid_float_nonce"),
        pytest.param(make_legacy_txn(nonce=True), False, id="invalid_bool_nonce"),
        pytest.param(make_legacy_txn(value=-1), False, id="invalid_negative_value"),
        pytest.param(make_legacy_txn(value=1.0), False, id="invalid_float_value"),
        pytest.param(make_legacy_txn(value=True), False, id="invalid_bool_value"),
        pytest.param(
            make_legacy_txn(block_number=-1),
            False,
            id="invalid_negative_block_number",
        ),
        pytest.param(
            make_legacy_txn(block_number=1.0),
            False,
            id="invalid_float_block_number",
        ),
        pytest.param(
            make_legacy_txn(block_number=True),
            False,
            id="invalid_bool_block_number",
        ),
        pytest.param(make_legacy_txn(gas=-1), False, id="invalid_negative_gas"),
        pytest.param(make_legacy_txn(gas=1.0), False, id="invalid_float_gas"),
        pytest.param(make_legacy_txn(gas=True), False, id="invalid_bool_gas"),
        pytest.param(
            make_legacy_txn(gas_price=-1),
            False,
            id="invalid_negative_gas_price",
        ),
        pytest.param(
            make_legacy_txn(gas_price=1.0), False, id="invalid_float_gas_price"
        ),
        pytest.param(
            make_legacy_txn(gas_price=True), False, id="invalid_bool_gas_price"
        ),
        pytest.param(make_legacy_txn(data=""), False, id="invalid_empty_string_data"),
        pytest.param(make_legacy_txn(data="0x"), False, id="invalid_0x_string_data"),
        pytest.param(
            make_legacy_txn(block_hash=HASH32_AS_TEXT),
            False,
            id="invalid_text_block_hash",
        ),
        pytest.param(
            make_legacy_txn(block_hash=HASH31),
            False,
            id="invalid_short_block_hash",
        ),
        pytest.param(
            make_legacy_txn(transaction_index=None, block_hash=None, block_number=None),
            True,
            id="valid_pending_legacy_txn",
        ),
        pytest.param(
            make_access_list_txn(
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            True,
            id="valid_pending_access_list_txn",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            True,
            id="valid_pending_dynamic_fee_txn",
        ),
        pytest.param(
            make_blob_txn(
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            True,
            id="valid_pending_blob_txn",
        ),
        pytest.param(
            make_access_list_txn(chain_id="1"),
            False,
            id="invalid_string_chain_id_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(chain_id="1"),
            False,
            id="invalid_string_chain_id_dynamic_fee",
        ),
        pytest.param(
            make_blob_txn(chain_id="1"),
            False,
            id="invalid_string_chain_id_blob",
        ),
        pytest.param(
            make_access_list_txn(chain_id=-1),
            False,
            id="invalid_negative_chain_id_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(chain_id=-1),
            False,
            id="invalid_negative_chain_id_dynamic_fee",
        ),
        pytest.param(
            make_blob_txn(chain_id=-1),
            False,
            id="invalid_negative_chain_id_blob",
        ),
        pytest.param(
            make_access_list_txn(chain_id=None),
            False,
            id="invalid_none_chain_id_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(chain_id=None),
            False,
            id="invalid_none_chain_id_dynamic_fee",
        ),
        pytest.param(
            make_blob_txn(chain_id=None), False, id="invalid_none_chain_id_blob"
        ),
        pytest.param(make_legacy_txn(v=0), True, id="valid_v_0_legacy"),
        pytest.param(make_dynamic_fee_txn(v=0), True, id="valid_v_0_dynamic_fee"),
        pytest.param(make_access_list_txn(v=0), True, id="valid_v_0_access_list"),
        pytest.param(make_blob_txn(v=0), True, id="valid_v_0_blob"),
        pytest.param(make_legacy_txn(v=1), True, id="valid_v_1_legacy"),
        pytest.param(make_dynamic_fee_txn(v=1), True, id="valid_v_1_dynamic_fee"),
        pytest.param(make_access_list_txn(v=1), True, id="valid_v_1_access_list"),
        pytest.param(make_blob_txn(v=1), True, id="valid_v_1_blob"),
        pytest.param(make_legacy_txn(v=27), True, id="valid_v_27_legacy"),
        pytest.param(make_access_list_txn(v=27), False, id="invalid_v_27_access_list"),
        pytest.param(make_dynamic_fee_txn(v=27), False, id="invalid_v_27_dynamic_fee"),
        pytest.param(make_blob_txn(v=27), False, id="invalid_v_27_blob"),
        pytest.param(
            make_dynamic_fee_txn(max_fee_per_gas=1.0),
            False,
            id="invalid_float_max_fee_per_gas",
        ),
        pytest.param(
            make_dynamic_fee_txn(max_priority_fee_per_gas=1.0),
            False,
            id="invalid_float_max_priority_fee",
        ),
        pytest.param(
            make_dynamic_fee_txn(max_fee_per_gas="1"),
            False,
            id="invalid_string_max_fee_per_gas",
        ),
        pytest.param(
            make_dynamic_fee_txn(max_priority_fee_per_gas="1"),
            False,
            id="invalid_string_max_priority_fee",
        ),
        pytest.param(
            make_blob_txn(max_fee_per_blob_gas=1.0),
            False,
            id="invalid_float_max_fee_per_blob_gas",
        ),
        pytest.param(
            make_blob_txn(max_fee_per_blob_gas="1"),
            False,
            id="invalid_string_max_fee_per_blob_gas",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=""),  # type: ignore[arg-type]
            True,
            id="valid_string_blob_hashes",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=()),
            True,
            id="valid_empty_blob_hashes",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=("",)),
            False,
            id="invalid_empty_string_in_blob_hashes",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=(ZERO_32BYTES,)),
            True,
            id="valid_bytes32_blob_hash",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=(b"\x00" * 31,)),
            False,
            id="invalid_bytes31_blob_hash",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=(b"\x00",)),
            False,
            id="invalid_bytes1_blob_hash",
        ),
        pytest.param(
            make_access_list_txn(
                access_list=((b"\xf0" * 20, (0, 2)),),
            ),
            True,
            id="valid_access_list_with_storage_keys",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                access_list=((b"\xef" * 20, (1, 2, 3, 4)),),
            ),
            True,
            id="valid_dynamic_fee_with_storage_keys",
        ),
        pytest.param(
            make_blob_txn(
                access_list=((b"\xef" * 20, (1, 2, 3, 4)),),
            ),
            True,
            id="valid_blob_with_storage_keys",
        ),
        pytest.param(
            make_access_list_txn(access_list=()),
            True,
            id="valid_empty_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(access_list=()),
            True,
            id="valid_empty_dynamic_fee_access_list",
        ),
        pytest.param(
            make_blob_txn(access_list=()),
            True,
            id="valid_empty_blob_access_list",
        ),
        pytest.param(
            make_access_list_txn(
                access_list=((b"\xf0" * 19, (0, 2)),),
            ),
            False,
            id="invalid_short_address_in_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                access_list=((b"\xf0" * 19, ()),),
            ),
            False,
            id="invalid_short_address_with_empty_storage_keys",
        ),
        pytest.param(
            make_blob_txn(
                access_list=((b"\xf0" * 19, ()),),
            ),
            False,
            id="invalid_short_address_in_blob_access_list",
        ),
        pytest.param(
            make_access_list_txn(
                access_list=((b"\xf0" * 20, ("0", 2)),),
            ),
            False,
            id="invalid_string_storage_key",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                access_list=((b"\xf0" * 20, (b"", 1)),),
            ),
            False,
            id="invalid_empty_bytes_storage_key",
        ),
        pytest.param(
            make_blob_txn(
                access_list=((b"\xf0" * 20, (b"", 1)),),
            ),
            False,
            id="invalid_empty_bytes_storage_key_in_blob",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                access_list=(("", (1, 2)),),
            ),
            False,
            id="invalid_empty_string_address_in_access_list",
        ),
        pytest.param(
            make_blob_txn(
                access_list=(("", (1, 2)),),
            ),
            False,
            id="invalid_empty_string_address_in_blob_access_list",
        ),
        pytest.param({}, False, id="invalid_empty_dict"),
        pytest.param(
            merge(make_legacy_txn(), {"invalid-key": 1}),
            False,
            id="invalid_extra_key",
        ),
    ),
)
def test_transaction_output_validation(
    validator: DefaultValidator, transaction: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_outbound_transaction(transaction)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_transaction(transaction)


@pytest.mark.parametrize(
    "log_entry,is_valid",
    (
        pytest.param(make_log(), True, id="valid_standard_log"),
        pytest.param(
            make_log(
                _type="pending",
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            True,
            id="valid_pending_log",
        ),
        pytest.param(
            make_log(
                _type="mined",
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            True,
            id="valid_mined_log_with_nulls",
        ),
        pytest.param(make_log(_type="invalid-type"), False, id="invalid_log_type"),
        pytest.param(
            make_log(transaction_index=-1),
            False,
            id="invalid_negative_transaction_index",
        ),
        pytest.param(
            make_log(block_number=-1), False, id="invalid_negative_block_number"
        ),
        pytest.param(
            make_log(transaction_hash=HASH31),
            False,
            id="invalid_short_transaction_hash",
        ),
        pytest.param(
            make_log(transaction_hash=HASH32_AS_TEXT),
            False,
            id="invalid_text_transaction_hash",
        ),
        pytest.param(make_log(block_hash=HASH31), False, id="invalid_short_block_hash"),
        pytest.param(
            make_log(block_hash=HASH32_AS_TEXT), False, id="invalid_text_block_hash"
        ),
        pytest.param(
            make_log(address=encode_hex(ADDRESS_A)), False, id="invalid_hex_address"
        ),
        pytest.param(make_log(data=""), False, id="invalid_empty_string_data"),
        pytest.param(make_log(data=None), False, id="invalid_none_data"),
        pytest.param(make_log(topics=[HASH32_AS_TEXT]), False, id="invalid_text_topic"),
        pytest.param(make_log(topics=[HASH31]), False, id="invalid_short_topic"),
        pytest.param(
            make_log(topics=[TOPIC_A, TOPIC_B]), True, id="valid_multiple_topics"
        ),
        pytest.param(
            make_log(topics="invalid-topics"),  # type: ignore[arg-type]
            False,
            id="invalid_string_topics",
        ),
        pytest.param(make_log(address=ADDRESS_A), True, id="valid_address"),
        pytest.param(
            merge(make_log(), {"invalid-key": 1}), False, id="invalid_extra_key"
        ),
    ),
)
def test_log_entry_output_validation(
    validator: DefaultValidator, log_entry: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_outbound_log_entry(log_entry)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_log_entry(log_entry)


@pytest.mark.parametrize(
    "receipt,is_valid",
    (
        pytest.param(make_receipt(), True, id="valid_standard_receipt"),
        pytest.param(
            make_receipt(transaction_hash=HASH32_AS_TEXT),
            False,
            id="invalid_text_transaction_hash",
        ),
        pytest.param(
            make_receipt(transaction_hash=HASH31),
            False,
            id="invalid_short_transaction_hash",
        ),
        pytest.param(
            make_receipt(block_hash=HASH32_AS_TEXT), False, id="invalid_text_block_hash"
        ),
        pytest.param(
            make_receipt(block_hash=HASH31), False, id="invalid_short_block_hash"
        ),
        pytest.param(
            make_receipt(transaction_index=-1),
            False,
            id="invalid_negative_transaction_index",
        ),
        pytest.param(
            make_receipt(transaction_index=1.0),
            False,
            id="invalid_float_transaction_index",
        ),
        pytest.param(
            make_receipt(transaction_index=True),
            False,
            id="invalid_bool_transaction_index",
        ),
        pytest.param(
            make_receipt(block_number=-1), False, id="invalid_negative_block_number"
        ),
        pytest.param(
            make_receipt(block_number=1.0), False, id="invalid_float_block_number"
        ),
        pytest.param(
            make_receipt(block_number=True), False, id="invalid_bool_block_number"
        ),
        pytest.param(make_receipt(gas_used=-1), False, id="invalid_negative_gas_used"),
        pytest.param(make_receipt(gas_used=1.0), False, id="invalid_float_gas_used"),
        pytest.param(make_receipt(gas_used=True), False, id="invalid_bool_gas_used"),
        pytest.param(
            make_receipt(cumulative_gas_used=-1),
            False,
            id="invalid_negative_cumulative_gas_used",
        ),
        pytest.param(
            make_receipt(cumulative_gas_used=1.0),
            False,
            id="invalid_float_cumulative_gas_used",
        ),
        pytest.param(
            make_receipt(cumulative_gas_used=True),
            False,
            id="invalid_bool_cumulative_gas_used",
        ),
        pytest.param(
            make_receipt(contract_address=ZERO_ADDRESS),
            True,
            id="valid_contract_address",
        ),
        pytest.param(
            make_receipt(contract_address=encode_hex(ZERO_ADDRESS)),
            False,
            id="invalid_hex_contract_address",
        ),
        pytest.param(make_receipt(logs=[make_log()]), True, id="valid_logs"),
        pytest.param(
            make_receipt(logs=[make_log(_type="invalid")]),
            False,
            id="invalid_log_type_in_logs",
        ),
        pytest.param(
            make_receipt(_from=ADDRESS_A, to=ADDRESS_A),
            True,
            id="valid_from_to_same_address",
        ),
        pytest.param(
            make_receipt(_from=ADDRESS_A, to=ZERO_ADDRESS),
            True,
            id="valid_from_to_different_address",
        ),
        pytest.param(
            make_receipt(_from=encode_hex(ZERO_ADDRESS), to=ADDRESS_A),
            False,
            id="invalid_hex_from_address",
        ),
        pytest.param(
            make_receipt(_from=ADDRESS_A, to=encode_hex(ZERO_ADDRESS)),
            False,
            id="invalid_hex_to_address",
        ),
        pytest.param(make_receipt(status=0), True, id="valid_status_0"),
        pytest.param(make_receipt(status=1), True, id="valid_status_1"),
        pytest.param(make_receipt(status=2), False, id="invalid_status_2"),
        pytest.param(make_receipt(status=-1), False, id="invalid_negative_status"),
        pytest.param(
            make_receipt(blob_gas_used=-1, blob_gas_price=-1),
            False,
            id="invalid_negative_blob_gas_used_and_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=-1, blob_gas_price=0),
            False,
            id="invalid_negative_blob_gas_used",
        ),
        pytest.param(
            make_receipt(blob_gas_used=0, blob_gas_price=-1),
            False,
            id="invalid_negative_blob_gas_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=0, blob_gas_price=0),
            True,
            id="valid_zero_blob_gas_used_and_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=0, blob_gas_price=1),
            True,
            id="valid_zero_blob_gas_used_nonzero_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=1, blob_gas_price=0),
            True,
            id="valid_nonzero_blob_gas_used_zero_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=1, blob_gas_price=1),
            True,
            id="valid_nonzero_blob_gas_used_and_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=2, blob_gas_price=1),
            True,
            id="valid_blob_gas_used_greater_than_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=1, blob_gas_price=2),
            True,
            id="valid_blob_gas_price_greater_than_used",
        ),
        pytest.param(
            make_receipt(blob_gas_used=2, blob_gas_price=2),
            True,
            id="valid_equal_blob_gas_used_and_price",
        ),
        pytest.param(
            merge(make_receipt(), {"invalid-key": 1}), False, id="invalid_extra_key"
        ),
    ),
)
def test_receipt_output_validation(
    validator: DefaultValidator, receipt: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_outbound_receipt(receipt)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_receipt(receipt)


@pytest.mark.parametrize(
    "block,is_valid",
    (
        pytest.param(make_block(), True, id="valid_block"),
        pytest.param(make_block(number=-1), False, id="invalid_negative_number"),
        pytest.param(make_block(number=1.0), False, id="invalid_float_number"),
        pytest.param(make_block(number=True), False, id="invalid_bool_number"),
        pytest.param(make_block(hash=HASH32_AS_TEXT), False, id="invalid_text_hash"),
        pytest.param(make_block(hash=HASH31), False, id="invalid_short_hash"),
        pytest.param(
            make_block(parent_hash=HASH32_AS_TEXT),
            False,
            id="invalid_text_parent_hash",
        ),
        pytest.param(
            make_block(parent_hash=HASH31), False, id="invalid_short_parent_hash"
        ),
        pytest.param(make_block(nonce=-1), False, id="invalid_negative_nonce"),
        pytest.param(make_block(nonce=1.0), False, id="invalid_float_nonce"),
        pytest.param(make_block(nonce=True), False, id="invalid_bool_nonce"),
        pytest.param(
            make_block(sha3_uncles=HASH32_AS_TEXT),
            False,
            id="invalid_text_sha3_uncles",
        ),
        pytest.param(
            make_block(logs_bloom=-1), False, id="invalid_negative_logs_bloom"
        ),
        pytest.param(make_block(logs_bloom=1.0), False, id="invalid_float_logs_bloom"),
        pytest.param(make_block(logs_bloom=True), False, id="invalid_bool_logs_bloom"),
        pytest.param(
            make_block(transactions_root=HASH32_AS_TEXT),
            False,
            id="invalid_text_transactions_root",
        ),
        pytest.param(
            make_block(transactions_root=HASH31),
            False,
            id="invalid_short_transactions_root",
        ),
        pytest.param(
            make_block(receipts_root=HASH32_AS_TEXT),
            False,
            id="invalid_text_receipts_root",
        ),
        pytest.param(
            make_block(receipts_root=HASH31), False, id="invalid_short_receipts_root"
        ),
        pytest.param(
            make_block(state_root=HASH32_AS_TEXT), False, id="invalid_text_state_root"
        ),
        pytest.param(
            make_block(state_root=HASH31), False, id="invalid_short_state_root"
        ),
        pytest.param(
            make_block(coinbase=encode_hex(ADDRESS_A)),
            False,
            id="invalid_hex_coinbase",
        ),
        pytest.param(
            make_block(difficulty=-1), False, id="invalid_negative_difficulty"
        ),
        pytest.param(make_block(difficulty=1.0), False, id="invalid_float_difficulty"),
        pytest.param(make_block(difficulty=True), False, id="invalid_bool_difficulty"),
        pytest.param(
            make_block(mix_hash=HASH32_AS_TEXT), False, id="invalid_text_mix_hash"
        ),
        pytest.param(make_block(mix_hash=HASH31), False, id="invalid_short_mix_hash"),
        pytest.param(
            make_block(total_difficulty=-1),
            False,
            id="invalid_negative_total_difficulty",
        ),
        pytest.param(
            make_block(total_difficulty=1.0),
            False,
            id="invalid_float_total_difficulty",
        ),
        pytest.param(
            make_block(total_difficulty=True),
            False,
            id="invalid_bool_total_difficulty",
        ),
        pytest.param(make_block(size=-1), False, id="invalid_negative_size"),
        pytest.param(make_block(size=1.0), False, id="invalid_float_size"),
        pytest.param(make_block(size=True), False, id="invalid_bool_size"),
        pytest.param(
            make_block(extra_data=HASH32_AS_TEXT), False, id="invalid_text_extra_data"
        ),
        pytest.param(
            make_block(extra_data=HASH31), False, id="invalid_short_extra_data"
        ),
        pytest.param(make_block(gas_limit=-1), False, id="invalid_negative_gas_limit"),
        pytest.param(make_block(gas_limit=1.0), False, id="invalid_float_gas_limit"),
        pytest.param(make_block(gas_limit=True), False, id="invalid_bool_gas_limit"),
        pytest.param(make_block(gas_used=-1), False, id="invalid_negative_gas_used"),
        pytest.param(make_block(gas_used=1.0), False, id="invalid_float_gas_used"),
        pytest.param(make_block(gas_used=True), False, id="invalid_bool_gas_used"),
        pytest.param(make_block(timestamp=-1), False, id="invalid_negative_timestamp"),
        pytest.param(make_block(timestamp=1.0), False, id="invalid_float_timestamp"),
        pytest.param(make_block(timestamp=True), False, id="invalid_bool_timestamp"),
        pytest.param(
            make_block(base_fee_per_gas=1000000000), True, id="valid_base_fee"
        ),
        pytest.param(
            make_block(base_fee_per_gas=-1000000000),
            False,
            id="invalid_negative_base_fee",
        ),
        pytest.param(
            make_block(base_fee_per_gas=1000000000.0),
            False,
            id="invalid_float_base_fee",
        ),
        pytest.param(
            make_block(base_fee_per_gas="1000000000"),
            False,
            id="invalid_string_base_fee",
        ),
        pytest.param(make_block(uncles=[ZERO_32BYTES]), True, id="valid_uncles"),
        pytest.param(
            make_block(uncles=[ZERO_32BYTES, HASH32_AS_TEXT]),
            False,
            id="invalid_uncles_with_text",
        ),
        pytest.param(
            make_block(transactions="invalid"),  # type: ignore[arg-type]
            False,
            id="valid_transactions_string",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES]), True, id="valid_transactions_hash"
        ),
        pytest.param(
            make_block(transactions=[make_legacy_txn()]),
            True,
            id="valid_transactions_legacy_txn",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, make_legacy_txn()]),
            False,
            id="invalid_mixed_transactions",
        ),
        pytest.param(
            make_block(transactions=[make_access_list_txn()]),
            True,
            id="valid_transactions_access_list",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, make_access_list_txn()]),
            False,
            id="invalid_mixed_with_access_list",
        ),
        pytest.param(
            make_block(transactions=[make_dynamic_fee_txn()]),
            True,
            id="valid_transactions_dynamic_fee",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, make_dynamic_fee_txn()]),
            False,
            id="invalid_mixed_with_dynamic_fee",
        ),
        pytest.param(
            make_block(transactions=[make_blob_txn()]),
            True,
            id="valid_transactions_blob",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, make_blob_txn()]),
            False,
            id="invalid_mixed_with_blob",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, HASH32_AS_TEXT]),
            False,
            id="invalid_transactions_with_text",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal()]), True, id="valid_withdrawals"
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(address=ADDRESS_A)]),
            True,
            id="valid_withdrawal_with_address",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(index=-1)]),
            False,
            id="invalid_withdrawal_negative_index",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(index=2**64)]),
            False,
            id="invalid_withdrawal_index_too_large",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(validator_index=-1)]),
            False,
            id="invalid_withdrawal_negative_validator_index",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(validator_index=2**64)]),
            False,
            id="invalid_withdrawal_validator_index_too_large",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(amount=-1)]),
            False,
            id="invalid_withdrawal_negative_amount",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(amount=2**64)]),
            False,
            id="invalid_withdrawal_amount_too_large",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(address="1")]),
            False,
            id="invalid_withdrawal_string_address",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(address=encode_hex(ZERO_ADDRESS))]),
            False,
            id="invalid_withdrawal_hex_address",
        ),
        pytest.param(
            merge(make_block(), {"invalid-key": 1}), False, id="invalid_extra_key"
        ),
    ),
)
def test_block_output_validation(
    validator: DefaultValidator, block: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_outbound_block(block)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_block(block)


@pytest.mark.parametrize(
    "accounts,is_valid",
    (
        pytest.param([ADDRESS_A], True, id="valid_address"),
        pytest.param([ADDRESS_A, encode_hex(ADDRESS_A)], False, id="invalid_hex"),
        pytest.param(ADDRESS_A, False, id="invalid_not_list"),
        pytest.param([b"0x"], False, id="invalid_bytes"),
        pytest.param([1], False, id="invalid_int"),
    ),
)
def test_accounts_output_validation(
    validator: DefaultValidator, accounts: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_outbound_accounts(accounts)
    else:
        with pytest.raises(ValidationError):
            validator.validate_outbound_accounts(accounts)


@pytest.mark.parametrize(
    "value,is_valid",
    [(b"", True), (b"0x", True), (1, False)],
    ids=["valid", "invalid_hex", "invalid_int"],
)
@pytest.mark.parametrize(
    "validator_name",
    [
        "validate_outbound_code",
        "validate_outbound_return_data",
    ],
)
def test_validate_outbound_value_bytes(
    validator: DefaultValidator,
    validator_name: str,
    value: Any,
    is_valid: bool,
) -> None:
    if is_valid:
        getattr(validator, validator_name)(value)
    else:
        with pytest.raises(ValidationError):
            getattr(validator, validator_name)(value)


@pytest.mark.parametrize(
    "value,is_valid",
    [
        pytest.param(0, True, id="valid_zero"),
        pytest.param(1, True, id="valid_one"),
        pytest.param(2**256 - 1, True, id="valid_max_uint256"),
        pytest.param(2**256, False, id="invalid_too_large"),
        pytest.param(2**256 + 1, False, id="invalid_too_large_plus_one"),
        pytest.param(2**256 - 2, True, id="valid_max_uint256_minus_two"),
        pytest.param(-1, False, id="invalid_negative"),
        pytest.param("abc", False, id="invalid_string"),
    ],
)
@pytest.mark.parametrize(
    "validator_name",
    [
        "validate_outbound_balance",
        "validate_outbound_gas_estimate",
        "validate_outbound_nonce",
        "validate_outbound_storage",
    ],
)
def test_validate_outbound_value_uint256(
    validator: DefaultValidator,
    validator_name: str,
    value: Any,
    is_valid: bool,
) -> None:
    if is_valid:
        getattr(validator, validator_name)(value)
    else:
        with pytest.raises(ValidationError):
            getattr(validator, validator_name)(value)
