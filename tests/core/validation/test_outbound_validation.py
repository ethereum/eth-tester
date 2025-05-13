import pytest
from typing import (
    Any,
)

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
    "block_hash",
    (
        pytest.param(ZERO_32BYTES, id="valid_bytes_all_zero"),
        pytest.param(b"\xff" * 32, id="valid_bytes_all_ff"),
    ),
)
def test_block_hash_output_validation(
    validator: DefaultValidator, block_hash: Any
) -> None:
    validator.validate_outbound_block_hash(block_hash)


@pytest.mark.parametrize(
    "block_hash,error_message",
    (
        pytest.param(
            b"\x00",
            "Must be of length 32.  Got: b'\\x00' of length 1",
            id="invalid_bytes_short",
        ),
        pytest.param(
            "\x00" * 32,
            "Value must be a byte string.  Got type: <class 'str'>",
            id="invalid_str",
        ),
        pytest.param(
            encode_hex(ZERO_32BYTES),
            "Value must be a byte string.  Got type: <class 'str'>",
            id="invalid_hex",
        ),
        pytest.param(
            1,
            "Value must be a byte string.  Got type: <class 'int'>",
            id="invalid_int",
        ),
        pytest.param(
            True,
            "Value must be a byte string.  Got type: <class 'bool'>",
            id="invalid_bool",
        ),
    ),
)
def test_block_hash_output_validation_invalid(
    validator: DefaultValidator, block_hash: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_outbound_block_hash(block_hash)
    assert e.value.args[0] == error_message


@pytest.mark.parametrize(
    "hash", (pytest.param(ZERO_32BYTES, id="valid_bytes_all_zero"),)
)
def test_validate_outbound_transaction_hash(
    validator: DefaultValidator,
    hash: Any,
) -> None:
    validator.validate_outbound_transaction_hash(hash)


@pytest.mark.parametrize(
    "hash,error_message",
    (
        pytest.param(
            b"\x00",
            "Must be of length 32.  Got: b'\\x00' of length 1",
            id="invalid_bytes_short",
        ),
        pytest.param(
            b"\xff" * 31,
            "Must be of length 32.  Got: b'\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff' of length 31",  # noqa: E501
            id="invalid_bytes_short_ff",
        ),
        pytest.param(
            f"0x{'00' * 32}",
            "Value must be a byte string.  Got type: <class 'str'>",
            id="invalid_hex_string",
        ),
        pytest.param(
            "0x0",
            "Value must be a byte string.  Got type: <class 'str'>",
            id="invalid_hex_string_short",
        ),
        pytest.param(
            1, "Value must be a byte string.  Got type: <class 'int'>", id="invalid_int"
        ),
        pytest.param(
            True,
            "Value must be a byte string.  Got type: <class 'bool'>",
            id="invalid_bool",
        ),
    ),
)
def test_validate_outbound_transaction_hash_invalid(
    validator: DefaultValidator,
    hash: Any,
    error_message: str,
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_outbound_transaction_hash(hash)
    assert e.value.args[0] == error_message


@pytest.mark.parametrize(
    "transaction",
    (
        pytest.param(make_legacy_txn(), id="valid_legacy_txn"),
        pytest.param(make_access_list_txn(), id="valid_access_list_txn"),
        pytest.param(make_dynamic_fee_txn(), id="valid_dynamic_fee_txn"),
        pytest.param(make_blob_txn(), id="valid_blob_txn"),
        pytest.param(
            make_legacy_txn(transaction_index=None, block_hash=None, block_number=None),
            id="valid_pending_legacy_txn",
        ),
        pytest.param(
            make_access_list_txn(
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            id="valid_pending_access_list_txn",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            id="valid_pending_dynamic_fee_txn",
        ),
        pytest.param(
            make_blob_txn(
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            id="valid_pending_blob_txn",
        ),
        pytest.param(make_legacy_txn(v=0), id="valid_v_0_legacy"),
        pytest.param(make_dynamic_fee_txn(v=0), id="valid_v_0_dynamic_fee"),
        pytest.param(make_access_list_txn(v=0), id="valid_v_0_access_list"),
        pytest.param(make_blob_txn(v=0), id="valid_v_0_blob"),
        pytest.param(make_legacy_txn(v=1), id="valid_v_1_legacy"),
        pytest.param(make_dynamic_fee_txn(v=1), id="valid_v_1_dynamic_fee"),
        pytest.param(make_access_list_txn(v=1), id="valid_v_1_access_list"),
        pytest.param(make_blob_txn(v=1), id="valid_v_1_blob"),
        pytest.param(make_legacy_txn(v=27), id="valid_v_27_legacy"),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=""),  # type: ignore[arg-type]
            id="valid_string_blob_hashes",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=()),
            id="valid_empty_blob_hashes",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=(ZERO_32BYTES,)),
            id="valid_bytes32_blob_hash",
        ),
        pytest.param(
            make_access_list_txn(
                access_list=((b"\xf0" * 20, (0, 2)),),
            ),
            id="valid_access_list_with_storage_keys",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                access_list=((b"\xef" * 20, (1, 2, 3, 4)),),
            ),
            id="valid_dynamic_fee_with_storage_keys",
        ),
        pytest.param(
            make_blob_txn(
                access_list=((b"\xef" * 20, (1, 2, 3, 4)),),
            ),
            id="valid_blob_with_storage_keys",
        ),
        pytest.param(
            make_access_list_txn(access_list=()),
            id="valid_empty_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(access_list=()),
            id="valid_empty_dynamic_fee_access_list",
        ),
        pytest.param(
            make_blob_txn(access_list=()),
            id="valid_empty_blob_access_list",
        ),
    ),
)
def test_transaction_output_validation(
    validator: DefaultValidator, transaction: Any
) -> None:
    validator.validate_outbound_transaction(transaction)


@pytest.mark.parametrize(
    "transaction",
    (
        pytest.param(make_legacy_txn(hash=HASH32_AS_TEXT), id="invalid_text_hash"),
        pytest.param(make_legacy_txn(hash=HASH31), id="invalid_short_hash"),
        pytest.param(make_legacy_txn(nonce=-1), id="invalid_negative_nonce"),
        pytest.param(make_legacy_txn(nonce=1.0), id="invalid_float_nonce"),
        pytest.param(make_legacy_txn(nonce=True), id="invalid_bool_nonce"),
        pytest.param(make_legacy_txn(value=-1), id="invalid_negative_value"),
        pytest.param(make_legacy_txn(value=1.0), id="invalid_float_value"),
        pytest.param(make_legacy_txn(value=True), id="invalid_bool_value"),
        pytest.param(
            make_legacy_txn(block_number=-1),
            id="invalid_negative_block_number",
        ),
        pytest.param(
            make_legacy_txn(block_number=1.0),
            id="invalid_float_block_number",
        ),
        pytest.param(
            make_legacy_txn(block_number=True),
            id="invalid_bool_block_number",
        ),
        pytest.param(make_legacy_txn(gas=-1), id="invalid_negative_gas"),
        pytest.param(make_legacy_txn(gas=1.0), id="invalid_float_gas"),
        pytest.param(make_legacy_txn(gas=True), id="invalid_bool_gas"),
        pytest.param(
            make_legacy_txn(gas_price=-1),
            id="invalid_negative_gas_price",
        ),
        pytest.param(make_legacy_txn(gas_price=1.0), id="invalid_float_gas_price"),
        pytest.param(make_legacy_txn(gas_price=True), id="invalid_bool_gas_price"),
        pytest.param(make_legacy_txn(data=""), id="invalid_empty_string_data"),
        pytest.param(make_legacy_txn(data="0x"), id="invalid_0x_string_data"),
        pytest.param(
            make_legacy_txn(block_hash=HASH32_AS_TEXT),
            id="invalid_text_block_hash",
        ),
        pytest.param(
            make_legacy_txn(block_hash=HASH31),
            id="invalid_short_block_hash",
        ),
        pytest.param(
            make_access_list_txn(chain_id="1"),
            id="invalid_string_chain_id_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(chain_id="1"),
            id="invalid_string_chain_id_dynamic_fee",
        ),
        pytest.param(
            make_blob_txn(chain_id="1"),
            id="invalid_string_chain_id_blob",
        ),
        pytest.param(
            make_access_list_txn(chain_id=-1),
            id="invalid_negative_chain_id_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(chain_id=-1),
            id="invalid_negative_chain_id_dynamic_fee",
        ),
        pytest.param(
            make_blob_txn(chain_id=-1),
            id="invalid_negative_chain_id_blob",
        ),
        pytest.param(
            make_access_list_txn(chain_id=None),
            id="invalid_none_chain_id_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(chain_id=None),
            id="invalid_none_chain_id_dynamic_fee",
        ),
        pytest.param(make_blob_txn(chain_id=None), id="invalid_none_chain_id_blob"),
        pytest.param(make_access_list_txn(v=27), id="invalid_v_27_access_list"),
        pytest.param(make_dynamic_fee_txn(v=27), id="invalid_v_27_dynamic_fee"),
        pytest.param(make_blob_txn(v=27), id="invalid_v_27_blob"),
        pytest.param(
            make_dynamic_fee_txn(max_fee_per_gas=1.0),
            id="invalid_float_max_fee_per_gas",
        ),
        pytest.param(
            make_dynamic_fee_txn(max_priority_fee_per_gas=1.0),
            id="invalid_float_max_priority_fee",
        ),
        pytest.param(
            make_dynamic_fee_txn(max_fee_per_gas="1"),
            id="invalid_string_max_fee_per_gas",
        ),
        pytest.param(
            make_dynamic_fee_txn(max_priority_fee_per_gas="1"),
            id="invalid_string_max_priority_fee",
        ),
        pytest.param(
            make_blob_txn(max_fee_per_blob_gas=1.0),
            id="invalid_float_max_fee_per_blob_gas",
        ),
        pytest.param(
            make_blob_txn(max_fee_per_blob_gas="1"),
            id="invalid_string_max_fee_per_blob_gas",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=("",)),
            id="invalid_empty_string_in_blob_hashes",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=(b"\x00" * 31,)),
            id="invalid_bytes31_blob_hash",
        ),
        pytest.param(
            make_blob_txn(blob_versioned_hashes=(b"\x00",)),
            id="invalid_bytes1_blob_hash",
        ),
        pytest.param(
            make_access_list_txn(
                access_list=((b"\xf0" * 19, (0, 2)),),
            ),
            id="invalid_short_address_in_access_list",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                access_list=((b"\xf0" * 19, ()),),
            ),
            id="invalid_short_address_with_empty_storage_keys",
        ),
        pytest.param(
            make_blob_txn(
                access_list=((b"\xf0" * 19, ()),),
            ),
            id="invalid_short_address_in_blob_access_list",
        ),
        pytest.param(
            make_access_list_txn(
                access_list=((b"\xf0" * 20, ("0", 2)),),
            ),
            id="invalid_string_storage_key",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                access_list=((b"\xf0" * 20, (b"", 1)),),
            ),
            id="invalid_empty_bytes_storage_key",
        ),
        pytest.param(
            make_blob_txn(
                access_list=((b"\xf0" * 20, (b"", 1)),),
            ),
            id="invalid_empty_bytes_storage_key_in_blob",
        ),
        pytest.param(
            make_dynamic_fee_txn(
                access_list=(("", (1, 2)),),
            ),
            id="invalid_empty_string_address_in_access_list",
        ),
        pytest.param(
            make_blob_txn(
                access_list=(("", (1, 2)),),
            ),
            id="invalid_empty_string_address_in_blob_access_list",
        ),
        pytest.param({}, id="invalid_empty_dict"),
        pytest.param(
            merge(make_legacy_txn(), {"invalid-key": 1}),
            id="invalid_extra_key",
        ),
    ),
)
def test_transaction_output_validation_invalid(
    validator: DefaultValidator,
    transaction: Any,
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_outbound_transaction(transaction)
    assert "Value did not pass any of the provided validators" in e.value.args[0]


@pytest.mark.parametrize(
    "log_entry",
    (
        pytest.param(make_log(), id="valid_standard_log"),
        pytest.param(
            make_log(
                _type="pending",
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            id="valid_pending_log",
        ),
        pytest.param(
            make_log(
                _type="mined",
                transaction_index=None,
                block_hash=None,
                block_number=None,
            ),
            id="valid_mined_log_with_nulls",
        ),
        pytest.param(make_log(topics=[TOPIC_A, TOPIC_B]), id="valid_multiple_topics"),
        pytest.param(make_log(address=ADDRESS_A), id="valid_address"),
    ),
)
def test_log_entry_output_validation(
    validator: DefaultValidator, log_entry: Any
) -> None:
    validator.validate_outbound_log_entry(log_entry)


@pytest.mark.parametrize(
    "log_entry,error_message",
    (
        pytest.param(
            make_log(_type="invalid-type"),
            "The following keys failed to validate\n- type: Log entry type must be one of 'pending' or 'mined'",  # noqa: E501
            id="invalid_log_type",
        ),
        pytest.param(
            make_log(transaction_index=-1),
            "The following keys failed to validate\n- transactionIndex: Value must be a positive integer.  Got: -1",  # noqa: E501
            id="invalid_negative_transaction_index",
        ),
        pytest.param(
            make_log(block_number=-1),
            "The following keys failed to validate\n- blockNumber: Value must be a positive integer.  Got: -1",  # noqa: E501
            id="invalid_negative_block_number",
        ),
        pytest.param(
            make_log(transaction_hash=HASH31),
            "The following keys failed to validate\n- transactionHash: Must be of length 32.  Got: b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00' of length 31",  # noqa: E501
            id="invalid_short_transaction_hash",
        ),
        pytest.param(
            make_log(transaction_hash=HASH32_AS_TEXT),
            "The following keys failed to validate\n- transactionHash: Value must be a byte string.  Got type: <class 'str'>",  # noqa: E501
            id="invalid_text_transaction_hash",
        ),
        pytest.param(
            make_log(block_hash=HASH31),
            "The following keys failed to validate\n- blockHash: Must be of length 32.  Got: b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00' of length 31",  # noqa: E501
            id="invalid_short_block_hash",
        ),
        pytest.param(
            make_log(block_hash=HASH32_AS_TEXT),
            "The following keys failed to validate\n- blockHash: Value must be a byte string.  Got type: <class 'str'>",  # noqa: E501
            id="invalid_text_block_hash",
        ),
        pytest.param(
            make_log(address=encode_hex(ADDRESS_A)),
            "The following keys failed to validate\n- address: Value must be a byte string.  Got type: <class 'str'>",  # noqa: E501
            id="invalid_hex_address",
        ),
        pytest.param(
            make_log(data=""),
            "The following keys failed to validate\n- data: Value must be a byte string.  Got type: <class 'str'>",  # noqa: E501
            id="invalid_empty_string_data",
        ),
        pytest.param(
            make_log(data=None),
            "The following keys failed to validate\n- data: Value must be a byte string.  Got type: <class 'NoneType'>",  # noqa: E501
            id="invalid_none_data",
        ),
        pytest.param(
            make_log(topics=[HASH32_AS_TEXT]),
            "The following keys failed to validate\n- topics: The following items failed to validate\n- [0]: Value must be a byte string.  Got type: <class 'str'>",  # noqa: E501
            id="invalid_text_topic",
        ),
        pytest.param(
            make_log(topics=[HASH31]),
            "The following keys failed to validate\n- topics: The following items failed to validate\n- [0]: Must be of length 32.  Got: b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00' of length 31",  # noqa: E501
            id="invalid_short_topic",
        ),
        pytest.param(
            make_log(topics="invalid-topics"),  # type: ignore[arg-type]
            "The following keys failed to validate\n- topics: Value must be a sequence type.  Got: <class 'str'>",  # noqa: E501
            id="invalid_string_topics",
        ),
        pytest.param(
            merge(make_log(), {"invalid-key": 1}),
            "Only the keys 'address/blockHash/blockNumber/data/logIndex/topics/transactionHash/transactionIndex/type' are allowed.  Got extra keys: 'invalid-key'",  # noqa: E501
            id="invalid_extra_key",
        ),
    ),
)
def test_log_entry_output_validation_invalid(
    validator: DefaultValidator, log_entry: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_outbound_log_entry(log_entry)
    assert e.value.args[0] == error_message


@pytest.mark.parametrize(
    "receipt",
    (
        pytest.param(make_receipt(), id="valid_standard_receipt"),
        pytest.param(
            make_receipt(contract_address=ZERO_ADDRESS),
            id="valid_contract_address",
        ),
        pytest.param(
            make_receipt(_from=ADDRESS_A, to=ADDRESS_A),
            id="valid_from_to_same_address",
        ),
        pytest.param(
            make_receipt(_from=ADDRESS_A, to=ZERO_ADDRESS),
            id="valid_from_to_different_address",
        ),
        pytest.param(make_receipt(status=0), id="valid_status_0"),
        pytest.param(make_receipt(status=1), id="valid_status_1"),
        pytest.param(make_receipt(logs=[make_log()]), id="valid_logs"),
        pytest.param(
            make_receipt(blob_gas_used=0, blob_gas_price=0),
            id="valid_zero_blob_gas_used_and_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=0, blob_gas_price=1),
            id="valid_zero_blob_gas_used_nonzero_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=1, blob_gas_price=0),
            id="valid_nonzero_blob_gas_used_zero_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=1, blob_gas_price=1),
            id="valid_nonzero_blob_gas_used_and_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=2, blob_gas_price=1),
            id="valid_blob_gas_used_greater_than_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=1, blob_gas_price=2),
            id="valid_blob_gas_price_greater_than_used",
        ),
        pytest.param(
            make_receipt(blob_gas_used=2, blob_gas_price=2),
            id="valid_equal_blob_gas_used_and_price",
        ),
    ),
)
def test_receipt_output_validation(validator: DefaultValidator, receipt: Any) -> None:
    validator.validate_outbound_receipt(receipt)


@pytest.mark.parametrize(
    "receipt",
    (
        pytest.param(
            make_receipt(transaction_hash=HASH32_AS_TEXT),
            id="invalid_text_transaction_hash",
        ),
        pytest.param(
            make_receipt(transaction_hash=HASH31),
            id="invalid_short_transaction_hash",
        ),
        pytest.param(
            make_receipt(block_hash=HASH32_AS_TEXT), id="invalid_text_block_hash"
        ),
        pytest.param(make_receipt(block_hash=HASH31), id="invalid_short_block_hash"),
        pytest.param(
            make_receipt(transaction_index=-1),
            id="invalid_negative_transaction_index",
        ),
        pytest.param(
            make_receipt(transaction_index=1.0),
            id="invalid_float_transaction_index",
        ),
        pytest.param(
            make_receipt(transaction_index=True),
            id="invalid_bool_transaction_index",
        ),
        pytest.param(make_receipt(block_number=-1), id="invalid_negative_block_number"),
        pytest.param(make_receipt(block_number=1.0), id="invalid_float_block_number"),
        pytest.param(make_receipt(block_number=True), id="invalid_bool_block_number"),
        pytest.param(make_receipt(gas_used=-1), id="invalid_negative_gas_used"),
        pytest.param(make_receipt(gas_used=1.0), id="invalid_float_gas_used"),
        pytest.param(make_receipt(gas_used=True), id="invalid_bool_gas_used"),
        pytest.param(
            make_receipt(cumulative_gas_used=-1),
            id="invalid_negative_cumulative_gas_used",
        ),
        pytest.param(
            make_receipt(cumulative_gas_used=1.0),
            id="invalid_float_cumulative_gas_used",
        ),
        pytest.param(
            make_receipt(cumulative_gas_used=True),
            id="invalid_bool_cumulative_gas_used",
        ),
        pytest.param(
            make_receipt(contract_address=encode_hex(ZERO_ADDRESS)),
            id="invalid_hex_contract_address",
        ),
        pytest.param(
            make_receipt(logs=[make_log(_type="invalid")]),
            id="invalid_log_type_in_logs",
        ),
        pytest.param(
            make_receipt(_from=encode_hex(ZERO_ADDRESS), to=ADDRESS_A),
            id="invalid_hex_from_address",
        ),
        pytest.param(
            make_receipt(_from=ADDRESS_A, to=encode_hex(ZERO_ADDRESS)),
            id="invalid_hex_to_address",
        ),
        pytest.param(make_receipt(status=2), id="invalid_status_2"),
        pytest.param(make_receipt(status=-1), id="invalid_negative_status"),
        pytest.param(
            make_receipt(blob_gas_used=-1, blob_gas_price=-1),
            id="invalid_negative_blob_gas_used_and_price",
        ),
        pytest.param(
            make_receipt(blob_gas_used=-1, blob_gas_price=0),
            id="invalid_negative_blob_gas_used",
        ),
        pytest.param(
            make_receipt(blob_gas_used=0, blob_gas_price=-1),
            id="invalid_negative_blob_gas_price",
        ),
        pytest.param(merge(make_receipt(), {"invalid-key": 1}), id="invalid_extra_key"),
    ),
)
def test_receipt_output_validation_invalid(
    validator: DefaultValidator, receipt: Any
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_outbound_receipt(receipt)
    assert "Value did not pass any of the provided validators" in e.value.args[0]


@pytest.mark.parametrize(
    "block",
    (
        pytest.param(make_block(), id="valid_block"),
        pytest.param(make_block(base_fee_per_gas=1000000000), id="valid_base_fee"),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES]), id="valid_transactions_hash"
        ),
        pytest.param(make_block(uncles=[ZERO_32BYTES]), id="valid_uncles"),
        pytest.param(
            make_block(transactions=[make_legacy_txn()]),
            id="valid_transactions_legacy_txn",
        ),
        pytest.param(
            make_block(transactions=[make_access_list_txn()]),
            id="valid_transactions_access_list",
        ),
        pytest.param(
            make_block(transactions=[make_dynamic_fee_txn()]),
            id="valid_transactions_dynamic_fee",
        ),
        pytest.param(
            make_block(transactions=[make_blob_txn()]),
            id="valid_transactions_blob",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal()]), id="valid_withdrawals"
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(address=ADDRESS_A)]),
            id="valid_withdrawal_with_address",
        ),
    ),
)
def test_block_output_validation(validator: DefaultValidator, block: Any) -> None:
    validator.validate_outbound_block(block)


@pytest.mark.parametrize(
    "block,error_message",
    (
        pytest.param(
            make_block(base_fee_per_gas=-1000000000),
            "Value must be a positive integer.",
            id="invalid_negative_base_fee",
        ),
        pytest.param(
            make_block(base_fee_per_gas=1000000000.0),
            "Value must be a positive integer.",
            id="invalid_float_base_fee",
        ),
        pytest.param(
            make_block(base_fee_per_gas="1000000000"),
            "Value must be a positive integer.",
            id="invalid_string_base_fee",
        ),
        pytest.param(
            make_block(uncles=[ZERO_32BYTES, HASH32_AS_TEXT]),
            "The following keys failed to validate",
            id="invalid_uncles_with_text",
        ),
        pytest.param(
            make_block(transactions="invalid"),  # type: ignore[arg-type]
            "The following keys failed to validate",
            id="invalid_transactions_string",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, make_legacy_txn()]),
            "The following keys failed to validate",
            id="invalid_mixed_transactions",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, make_access_list_txn()]),
            "The following keys failed to validate",
            id="invalid_mixed_with_access_list",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, make_dynamic_fee_txn()]),
            "The following keys failed to validate",
            id="invalid_mixed_with_dynamic_fee",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, make_blob_txn()]),
            "The following keys failed to validate",
            id="invalid_mixed_with_blob",
        ),
        pytest.param(
            make_block(transactions=[ZERO_32BYTES, HASH32_AS_TEXT]),
            "The following keys failed to validate",
            id="invalid_transactions_with_text",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(index=-1)]),
            "The following keys failed to validate",
            id="invalid_withdrawal_negative_index",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(index=2**64)]),
            "The following keys failed to validate",
            id="invalid_withdrawal_index_too_large",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(validator_index=-1)]),
            "Value must be a positive integer.  Got: -1",
            id="invalid_withdrawal_negative_validator_index",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(validator_index=2**64)]),
            "The following keys failed to validate",
            id="invalid_withdrawal_validator_index_too_large",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(amount=-1)]),
            "Value must be a positive integer.  Got: -1",
            id="invalid_withdrawal_negative_amount",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(amount=2**64)]),
            "The following keys failed to validate",
            id="invalid_withdrawal_amount_too_large",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(address="1")]),
            "The following keys failed to validate",
            id="invalid_withdrawal_string_address",
        ),
        pytest.param(
            make_block(withdrawals=[make_withdrawal(address=encode_hex(ZERO_ADDRESS))]),
            "The following keys failed to validate",
            id="invalid_withdrawal_hex_address",
        ),
        pytest.param(
            merge(make_block(), {"invalid-key": 1}),
            "Only the keys 'baseFeePerGas/blobGasUsed/coinbase/difficulty/excessBlobGas/extraData/gasLimit/gasUsed/hash/logsBloom/mixHash/nonce/number/parentBeaconBlockRoot/parentHash/receiptsRoot/sha3Uncles/size/stateRoot/timestamp/totalDifficulty/transactions/transactionsRoot/uncles/withdrawals/withdrawalsRoot' are allowed.  Got extra keys: 'invalid-key'",  # noqa: E501
            id="invalid_extra_key",
        ),
    ),
)
def test_block_output_validation_invalid(
    validator: DefaultValidator, block: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_outbound_block(block)
    assert error_message in e.value.args[0]


@pytest.mark.parametrize(
    "accounts",
    (pytest.param([ADDRESS_A], id="valid_address"),),
)
def test_accounts_output_validation(validator: DefaultValidator, accounts: Any) -> None:
    validator.validate_outbound_accounts(accounts)


@pytest.mark.parametrize(
    "accounts,error_message",
    (
        pytest.param(
            [ADDRESS_A, encode_hex(ADDRESS_A)],
            "The following items failed to validate\n- [1]: Value must be a byte string.  Got type: <class 'str'>",
            id="invalid_hex",
        ),
        pytest.param(
            ADDRESS_A,
            "Value must be a sequence type.  Got: <class 'bytes'>",
            id="invalid_not_list",
        ),
        pytest.param(
            [b"0x"],
            "The following items failed to validate\n- [0]: Value must be a 20 byte string",  # noqa: E501
            id="invalid_bytes",
        ),
        pytest.param(
            [1],
            "The following items failed to validate\n- [0]: Value must be a byte string.  Got type: <class 'int'>",  # noqa: E501
            id="invalid_int",
        ),
    ),
)
def test_accounts_output_validation_invalid(
    validator: DefaultValidator, accounts: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_outbound_accounts(accounts)
    assert e.value.args[0] == error_message


@pytest.mark.parametrize(
    "value",
    (
        pytest.param(b"", id="valid_empty_bytes"),
        pytest.param(b"0x", id="valid_empty_hex"),
    ),
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
) -> None:
    getattr(validator, validator_name)(value)


@pytest.mark.parametrize(
    "value,error_message",
    (
        pytest.param(
            1, "Value must be a byte string.  Got type: <class 'int'>", id="invalid_int"
        ),
    ),
)
@pytest.mark.parametrize(
    "validator_name",
    [
        "validate_outbound_code",
        "validate_outbound_return_data",
    ],
)
def test_validate_outbound_value_bytes_invalid(
    validator: DefaultValidator,
    validator_name: str,
    value: Any,
    error_message: str,
) -> None:
    with pytest.raises(ValidationError) as e:
        getattr(validator, validator_name)(value)
    assert e.value.args[0] == error_message


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(0, id="valid_zero"),
        pytest.param(1, id="valid_one"),
        pytest.param(2**256 - 1, id="valid_max_uint256"),
        pytest.param(2**256 - 2, id="valid_max_uint256_minus_two"),
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
) -> None:
    getattr(validator, validator_name)(value)


@pytest.mark.parametrize(
    "value,error_message",
    [
        pytest.param(
            2**256,
            "Value exceeds maximum 256 bit integer size:  115792089237316195423570985008687907853269984665640564039457584007913129639936",  # noqa: E501
            id="invalid_too_large",
        ),
        pytest.param(
            2**256 + 1,
            "Value exceeds maximum 256 bit integer size:  115792089237316195423570985008687907853269984665640564039457584007913129639937",  # noqa: E501
            id="invalid_too_large_plus_one",
        ),
        pytest.param(
            -1, "Value must be a positive integer.  Got: -1", id="invalid_negative"
        ),
        pytest.param(
            "abc", "Value must be a positive integer.  Got: abc", id="invalid_string"
        ),
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
def test_validate_outbound_value_uint256_invalid(
    validator: DefaultValidator,
    validator_name: str,
    value: Any,
    error_message: str,
) -> None:
    with pytest.raises(ValidationError) as e:
        getattr(validator, validator_name)(value)
    assert e.value.args[0] == error_message
