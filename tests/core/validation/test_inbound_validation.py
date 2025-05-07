import pytest
from typing import (
    Any,
    Dict,
)

from eth_utils import (
    decode_hex,
)

from eth_tester.exceptions import (
    ValidationError,
)
from eth_tester.validation import (
    DefaultValidator,
)
from eth_tester.validation.inbound import (
    validate_inbound_withdrawals,
)
from tests.constants import (
    ADDRESS_A_HEX,
    ADDRESS_B_HEX,
    TOPIC_A_HEX,
    TOPIC_B_HEX,
    TOPIC_C_HEX,
    TOPIC_D_HEX,
)
from tests.utils import (
    make_filter_params,
    make_transaction,
)


@pytest.mark.parametrize(
    "account",
    (
        pytest.param(f"0x{'01' * 20}", id="valid_20_byte_hex_address"),
        pytest.param(f"{'01' * 20}", id="valid_string_address"),
    ),
)
def test_inbound_account_valid(validator: DefaultValidator, account: Any) -> None:
    validator.validate_inbound_account(account)


@pytest.mark.parametrize(
    "account",
    (
        pytest.param(f"0x{'01' * 32}", id="invalid_32_byte_hex_address"),
        pytest.param(b"\x01" * 20, id="invalid_bytes_address"),
        pytest.param(None, id="invalid_none_address"),
    ),
)
def test_inbound_account_invalid(validator: DefaultValidator, account: Any) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_account(account)


@pytest.mark.parametrize(
    "block_hash",
    (
        pytest.param("0" * 64, id="valid_hash_string"),
        pytest.param("0x" + "0" * 64, id="valid_hash_hex_string"),
    ),
)
def test_block_hash_input_validation(
    validator: DefaultValidator, block_hash: Any
) -> None:
    validator.validate_inbound_block_hash(block_hash)


@pytest.mark.parametrize(
    "block_hash",
    (
        pytest.param(0, id="invalid_int_zero"),
        pytest.param(1, id="invalid_int_one"),
        pytest.param(-1, id="invalid_negative_int"),
        pytest.param(False, id="invalid_bool_false"),
        pytest.param(True, id="invalid_bool_true"),
        pytest.param(b"", id="invalid_empty_bytes"),
        pytest.param("", id="invalid_empty_string"),
        pytest.param("0" * 32, id="invalid_hash_string"),
        pytest.param("0x" + "0" * 32, id="invalid_hash_hex_string"),
        pytest.param("\x00" * 32, id="invalid_32_bytes_string"),
        pytest.param(b"\x00" * 32, id="invalid_32_bytes"),
        pytest.param(b"0x" + b"0" * 64, id="invalid_bytes_hex_string"),
    ),
)
def test_block_hash_input_validation_invalid(
    validator: DefaultValidator, block_hash: Any
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_block_hash(block_hash)


@pytest.mark.parametrize(
    "block_number",
    (
        pytest.param(0, id="valid_zero"),
        pytest.param(1, id="valid_positive_int"),
        pytest.param("latest", id="valid_latest_string"),
        pytest.param("pending", id="valid_pending_string"),
        pytest.param("earliest", id="valid_earliest_string"),
        pytest.param("safe", id="valid_safe_string"),
        pytest.param("finalized", id="valid_finalized_string"),
        pytest.param(2**256, id="valid_large_int"),
    ),
)
def test_block_number_input_validation(
    validator: DefaultValidator, block_number: Any
) -> None:
    validator.validate_inbound_block_number(block_number)


@pytest.mark.parametrize(
    "block_number",
    (
        pytest.param(-1, id="invalid_negative_int"),
        pytest.param(False, id="invalid_bool_false"),
        pytest.param(True, id="invalid_bool_true"),
        pytest.param(b"latest", id="invalid_latest_bytes"),
        pytest.param(b"pending", id="invalid_pending_bytes"),
        pytest.param(b"earliest", id="invalid_earliest_bytes"),
        pytest.param(b"safe", id="invalid_safe_bytes"),
        pytest.param(b"finalized", id="invalid_finalized_bytes"),
    ),
)
def test_block_number_input_validation_invalid(
    validator: DefaultValidator, block_number: Any
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_block_number(block_number)


@pytest.mark.parametrize(
    "filter_id",
    (
        pytest.param(0, id="valid_zero"),
        pytest.param(1, id="valid_positive_int"),
    ),
)
def test_filter_id_input_validation(
    validator: DefaultValidator, filter_id: Any
) -> None:
    validator.validate_inbound_filter_id(filter_id)


@pytest.mark.parametrize(
    "filter_id",
    (
        pytest.param(-1, id="invalid_negative_int"),
        pytest.param("0x0", id="invalid_hex_string_0x0"),
        pytest.param("0x00", id="invalid_hex_string_0x00"),
        pytest.param("0x1", id="invalid_hex_string_0x1"),
        pytest.param("0x01", id="invalid_hex_string_0x01"),
        pytest.param("0", id="invalid_string_0"),
        pytest.param("1", id="invalid_string_1"),
    ),
)
def test_filter_id_input_validation_invalid(
    validator: DefaultValidator, filter_id: Any
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_filter_id(filter_id)


@pytest.mark.parametrize(
    "filter_params",
    (
        pytest.param(make_filter_params(), id="empty_filter"),
        pytest.param(make_filter_params(from_block=0), id="valid_from_block_zero"),
        pytest.param(make_filter_params(to_block=0), id="valid_to_block_zero"),
        pytest.param(
            make_filter_params(address=ADDRESS_A_HEX), id="valid_single_address"
        ),
        pytest.param(
            make_filter_params(address=[ADDRESS_A_HEX, ADDRESS_B_HEX]),
            id="valid_multiple_addresses",
        ),
        pytest.param(make_filter_params(topics=[TOPIC_A_HEX]), id="valid_single_topic"),
        pytest.param(
            make_filter_params(topics=[TOPIC_A_HEX, TOPIC_B_HEX]),
            id="valid_multiple_topics",
        ),
        pytest.param(
            make_filter_params(topics=[TOPIC_A_HEX, None]),
            id="valid_topic_with_none",
        ),
        pytest.param(
            make_filter_params(topics=[[TOPIC_A_HEX], [TOPIC_B_HEX]]),
            id="valid_nested_topics",
        ),
        pytest.param(
            make_filter_params(topics=[TOPIC_A_HEX, [TOPIC_B_HEX, TOPIC_A_HEX]]),
            id="valid_mixed_topic_structure",
        ),
        pytest.param(
            make_filter_params(topics=[[TOPIC_A_HEX], [TOPIC_B_HEX, None]]),
            id="valid_nested_topics_with_none",
        ),
        pytest.param(
            make_filter_params(topics=[decode_hex(TOPIC_A_HEX)]),
            id="valid_TOPIC_B_HEXytes",
        ),
        pytest.param(
            make_filter_params(
                topics=[decode_hex(TOPIC_A_HEX), decode_hex(TOPIC_B_HEX)]
            ),
            id="valid_multiple_TOPIC_B_HEXytes",
        ),
        pytest.param(
            make_filter_params(topics=[decode_hex(TOPIC_A_HEX), None]),
            id="valid_TOPIC_B_HEXytes_with_none",
        ),
        pytest.param(
            make_filter_params(
                topics=[[decode_hex(TOPIC_A_HEX)], [decode_hex(TOPIC_B_HEX)]]
            ),
            id="valid_nested_TOPIC_B_HEXytes",
        ),
        pytest.param(
            make_filter_params(
                topics=[
                    decode_hex(TOPIC_A_HEX),
                    [decode_hex(TOPIC_B_HEX), decode_hex(TOPIC_A_HEX)],
                ]
            ),
            id="valid_mixed_TOPIC_B_HEXytes",
        ),
        pytest.param(
            make_filter_params(
                topics=[
                    [decode_hex(TOPIC_A_HEX)],
                    [decode_hex(TOPIC_B_HEX), None],
                ]
            ),
            id="valid_nested_TOPIC_B_HEXytes_with_none",
        ),
    ),
)
def test_filter_params_input_validation(
    validator: DefaultValidator, filter_params: Dict[str, Any]
) -> None:
    validator.validate_inbound_filter_params(**filter_params)


@pytest.mark.parametrize(
    "filter_params",
    (
        pytest.param(
            make_filter_params(from_block=-1), id="invalid_from_block_negative"
        ),
        pytest.param(make_filter_params(to_block=-1), id="invalid_to_block_negative"),
        pytest.param(make_filter_params(from_block=True), id="invalid_from_block_bool"),
        pytest.param(make_filter_params(to_block=False), id="invalid_to_block_bool"),
        pytest.param(
            make_filter_params(from_block="0x0"),
            id="invalid_from_block_hex_string",
        ),
        pytest.param(
            make_filter_params(to_block="0x0"), id="invalid_to_block_hex_string"
        ),
        pytest.param(
            make_filter_params(from_block="0x1"),
            id="invalid_from_block_hex_one",
        ),
        pytest.param(make_filter_params(to_block="0x1"), id="invalid_to_block_hex_one"),
        pytest.param(
            make_filter_params(address=decode_hex(ADDRESS_A_HEX)),
            id="invalid_ADDRESS_B_HEXytes",
        ),
        pytest.param(
            make_filter_params(address=TOPIC_A_HEX), id="invalid_address_topic"
        ),
        pytest.param(
            make_filter_params(address=decode_hex(TOPIC_A_HEX)),
            id="invalid_address_TOPIC_B_HEXytes",
        ),
        pytest.param(
            make_filter_params(address=[TOPIC_A_HEX, ADDRESS_B_HEX]),
            id="invalid_mixed_address_topic",
        ),
        pytest.param(
            make_filter_params(topics=[decode_hex(TOPIC_C_HEX)]),
            id="invalid_topic_length_short",
        ),
        pytest.param(
            make_filter_params(topics=[decode_hex(TOPIC_D_HEX)]),
            id="invalid_topic_length_long",
        ),
        pytest.param(
            make_filter_params(topics=[ADDRESS_A_HEX]),
            id="invalid_topic_is_address",
        ),
        pytest.param(
            make_filter_params(topics=[ADDRESS_A_HEX, TOPIC_B_HEX]),
            id="invalid_topic_mix_address",
        ),
        pytest.param(
            make_filter_params(topics=[[ADDRESS_A_HEX], [TOPIC_B_HEX]]),
            id="invalid_nested_topic_with_address",
        ),
    ),
)
def test_filter_params_input_validation_invalid(
    validator: DefaultValidator, filter_params: Dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_filter_params(**filter_params)


@pytest.mark.parametrize(
    "private_key",
    (
        pytest.param(f"0x{'01' * 32}", id="valid_hex_private_key"),
        pytest.param(f"{'01' * 32}", id="valid_string_private_key"),
    ),
)
def test_private_key_input_validation(private_key: Any) -> None:
    DefaultValidator.validate_inbound_private_key(private_key)


@pytest.mark.parametrize(
    "private_key",
    (
        pytest.param(f"0x{'01' * 20}", id="invalid_20_byte_hex_private_key"),
        pytest.param(b"\x01" * 32, id="invalid_32_byte_private_key"),
        pytest.param(None, id="none_private_key"),
    ),
)
def test_private_key_input_validation_invalid(
    validator: DefaultValidator, private_key: Any
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_private_key(private_key)


@pytest.mark.parametrize(
    "raw_transaction",
    (
        pytest.param(f"0x{'01' * 32}", id="valid_raw_transaction"),
        pytest.param("0x", id="valid_empty_raw_transaction"),
        pytest.param("12345", id="valid_raw_transaction"),
    ),
)
def test_inbound_raw_transaction(
    validator: DefaultValidator, raw_transaction: Any
) -> None:
    validator.validate_inbound_raw_transaction(raw_transaction)


@pytest.mark.parametrize(
    "raw_transaction",
    (
        pytest.param("", id="invalid_empty_raw_transaction_string"),
        pytest.param(b"\x01" * 32, id="invalid_raw_transaction_bytes"),
        pytest.param(False, id="invalid_raw_transaction_bool_false"),
        pytest.param(1, id="invalid_raw_transaction_int"),
    ),
)
def test_inbound_raw_transaction_invalid(
    validator: DefaultValidator, raw_transaction: Any
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_raw_transaction(raw_transaction)


@pytest.mark.parametrize(
    "txn_internal_type,transaction",
    (
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, gas=21000),
            id="valid_from_and_gas",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to=ADDRESS_B_HEX, gas=21000),
            id="valid_complete_transaction",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000),
            id="empty_to_string",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="0x0"),
            id="valid_type_0x0",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="0x1"),
            id="valid_type_0x1",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="0x01"),
            id="valid_type_0x01",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="0x2"),
            id="valid_type_0x2",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="0x02"),
            id="valid_type_0x02",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type=1),
            id="valid_type_int_1",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, value=0),
            id="valid_zero_value",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, data=""),
            id="valid_empty_data",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, data="0x"),
            id="valid_0x_data",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=0),
            id="valid_zero_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=1),
            id="valid_positive_nonce",
        ),
        pytest.param(
            "send_signed",
            make_transaction(_from=ADDRESS_A_HEX, gas=21000, r=1, s=1, v=1),
            id="valid_signed_transaction",
        ),
        pytest.param(
            "send_signed",
            make_transaction(
                _from=ADDRESS_A_HEX,
                gas=21000,
                max_fee_per_gas=1000000000,
                max_priority_fee_per_gas=1000000000,
                r=1,
                s=1,
                v=1,
            ),
            id="valid_signed_eip1559_transaction",
        ),
        pytest.param(  # access list txn
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX,
                to="",
                gas=21000,
                gas_price=10000,
                # properly formatted access list
                access_list=(
                    {
                        "address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                        "storageKeys": (
                            "0x0000000000000000000000000000000000000000000000000000000000000003",  # noqa: E501
                            "0x0000000000000000000000000000000000000000000000000000000000000007",  # noqa: E501
                        ),
                    },
                    {
                        "address": "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
                        "storageKeys": (),
                    },
                ),
            ),
            id="valid_access_list_transaction",
        ),
        pytest.param(  # dynamic fee txn
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX,
                to="",
                gas=21000,
                max_fee_per_gas=1000000000,
                max_priority_fee_per_gas=1000000000,
                # properly formatted access list
                access_list=(
                    {
                        "address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                        "storageKeys": (
                            "0x0000000000000000000000000000000000000000000000000000000000000003",  # noqa: E501
                            "0x0000000000000000000000000000000000000000000000000000000000000007",  # noqa: E501
                        ),
                    },
                    {
                        "address": "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
                        "storageKeys": (),
                    },
                ),
            ),
            id="valid_dynamic_fee_transaction",
        ),
    ),
)
def test_transaction_input_validation(
    validator: DefaultValidator,
    txn_internal_type: str,
    transaction: Dict[str, Any],
) -> None:
    validator.validate_inbound_transaction(transaction, txn_internal_type)


@pytest.mark.parametrize(
    "txn_internal_type,transaction",
    (
        pytest.param("send", {}, id="empty_transaction"),
        pytest.param(
            "send", make_transaction(to=ADDRESS_B_HEX, gas=21000), id="missing_from"
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to=ADDRESS_B_HEX),
            id="missing_gas",
        ),
        pytest.param(
            "send",
            make_transaction(_from="", to=ADDRESS_B_HEX, gas=21000),
            id="empty_from",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to=b"", gas=21000),
            id="empty_to_bytes",
        ),
        pytest.param(
            "send",
            make_transaction(
                _from=decode_hex(ADDRESS_A_HEX), to=ADDRESS_B_HEX, gas=21000
            ),
            id="from_as_bytes",
        ),
        pytest.param(
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX, to=decode_hex(ADDRESS_B_HEX), gas=21000
            ),
            id="to_as_bytes",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="0x4"),
            id="invalid_type_0x4",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="1"),
            id="invalid_type_string_1",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="x1"),
            id="invalid_type_x1",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, value=-1),
            id="invalid_negative_value",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, data="0x0"),
            id="invalid_odd_length_data",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=-1),
            id="invalid_negative_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce="0x1"),
            id="invalid_hex_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce="arst"),
            id="invalid_string_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=True),
            id="invalid_bool_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=1.0),
            id="invalid_float_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=-1),
            id="invalid_negative_nonce_2",
        ),
        pytest.param(
            "send_signed",
            make_transaction(_from=ADDRESS_A_HEX, gas=21000),
            id="signed_missing_signature",
        ),
        pytest.param(
            "send_signed",
            make_transaction(_from=ADDRESS_A_HEX, gas=21000, r=1, s=1, v=256),
            id="invalid_v_value",
        ),
        pytest.param(
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX,
                to="",
                gas=21000,
                gas_price=10000,
                # improperly formatted access list storage key
                access_list=(
                    {
                        "address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                        "storage_keys": (
                            "3",
                            "0x0000000000000000000000000000000000000000000000000000000000000007",  # noqa: E501
                        ),
                    },
                    {
                        "address": "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
                        "storage_keys": (),
                    },
                ),
            ),
            id="invalid_access_list_storage_key",
        ),
        pytest.param(
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX,
                to="",
                gas=21000,
                # improperly formatted access list address
                access_list=(
                    {
                        "address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                        "storage_keys": (
                            "0x0000000000000000000000000000000000000000000000000000000000000003",  # noqa: E501
                            "0x0000000000000000000000000000000000000000000000000000000000000007",  # noqa: E501
                        ),
                    },
                    {"address": b"", "storage_keys": ()},
                ),
            ),
            id="invalid_access_list_address",
        ),
        # Cancun
        # `eth_sendTransaction` does not support blob transactions:
        pytest.param(
            "send",
            make_transaction(blob_versioned_hashes=[]),
            id="invalid_empty_blob_hashes",
        ),
        pytest.param(
            "send",
            make_transaction(blob_versioned_hashes=[b""]),
            id="invalid_empty_bytes_blob_hash",
        ),
        pytest.param(
            "send",
            make_transaction(blob_versioned_hashes=[b"0x"]),
            id="invalid_0x_bytes_blob_hash",
        ),
        pytest.param(
            "send",
            make_transaction(max_fee_per_blob_gas=0),
            id="invalid_zero_max_fee_per_blob_gas",
        ),
        pytest.param(
            "send",
            make_transaction(max_fee_per_blob_gas=1),
            id="invalid_positive_max_fee_per_blob_gas",
        ),
        pytest.param(
            "send",
            make_transaction(max_fee_per_blob_gas="0x0"),
            id="invalid_hex_max_fee_per_blob_gas",
        ),
    ),
)
def test_transaction_input_validation_invalid(
    validator: DefaultValidator,
    txn_internal_type: str,
    transaction: Dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_transaction(transaction, txn_internal_type)


@pytest.mark.parametrize(
    "transaction",
    (
        pytest.param(make_transaction(_from=ADDRESS_A_HEX), id="only_from"),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, nonce=1), id="from_and_nonce"
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, gas=21000), id="from_and_gas"
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to=ADDRESS_B_HEX), id="from_and_to"
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to=ADDRESS_B_HEX, gas=21000),
            id="complete_transaction",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000),
            id="empty_to_with_gas",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to=""), id="empty_to_string"
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", value=0), id="zero_value"
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", data=""),
            id="empty_data_string",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", data="0x"),
            id="0x_data_string",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, value=0),
            id="valid_with_zero_value",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, data=""),
            id="valid_with_empty_data",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, data="0x"),
            id="valid_with_0x_data",
        ),
    ),
)
def test_transaction_call_and_estimate_gas_input_validation(
    validator: DefaultValidator,
    transaction: Dict[str, Any],
) -> None:
    validator.validate_inbound_transaction(transaction, txn_internal_type="call")
    validator.validate_inbound_transaction(transaction, txn_internal_type="estimate")


@pytest.mark.parametrize(
    "transaction",
    (
        pytest.param({}, id="empty_transaction"),
        pytest.param(make_transaction(to=ADDRESS_B_HEX), id="missing_from"),
        pytest.param(make_transaction(gas=21000), id="only_gas"),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, gas=True), id="invalid_gas_type"
        ),
        pytest.param(make_transaction(_from=""), id="empty_from_string"),
        pytest.param(
            make_transaction(_from="", to=ADDRESS_B_HEX), id="empty_from_with_to"
        ),
        pytest.param(make_transaction(_from="", gas=21000), id="empty_from_with_gas"),
        pytest.param(
            make_transaction(_from="", to=ADDRESS_B_HEX, gas=21000),
            id="empty_from_complete",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to=b""), id="empty_to_bytes"
        ),
        pytest.param(
            make_transaction(
                _from=decode_hex(ADDRESS_A_HEX), to=ADDRESS_B_HEX, gas=21000
            ),
            id="from_as_bytes_with_gas",
        ),
        pytest.param(
            make_transaction(_from=decode_hex(ADDRESS_A_HEX), to=ADDRESS_B_HEX),
            id="from_as_bytes",
        ),
        pytest.param(
            make_transaction(
                _from=ADDRESS_A_HEX, to=decode_hex(ADDRESS_B_HEX), gas=21000
            ),
            id="to_as_bytes_with_gas",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to=decode_hex(ADDRESS_B_HEX)),
            id="to_as_bytes",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", value=-1),
            id="negative_value",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", data=b""),
            id="empty_data_bytes",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", data=b"0x"),
            id="0x_data_bytes",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", data="0x0"),
            id="invalid_odd_length_data",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, value=-1),
            id="invalid_with_negative_value",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, data="0x0"),
            id="invalid_with_odd_length_data",
        ),
    ),
)
def test_transaction_call_and_estimate_gas_input_validation_invalid(
    validator: DefaultValidator,
    transaction: Dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_transaction(transaction, txn_internal_type="call")
        validator.validate_inbound_transaction(
            transaction, txn_internal_type="estimate"
        )


@pytest.mark.parametrize(
    "withdrawals",
    (
        pytest.param(
            [
                {
                    "index": 0,
                    "validatorIndex": 0,
                    "address": b"\x00" * 20,  # bytes address
                    "amount": 0,
                }
            ],
            id="valid_single_withdrawal",
        ),
        pytest.param(
            [
                {
                    # limit case for uint64 fields
                    "index": 2**64 - 1,
                    "validatorIndex": 2**64 - 1,
                    "address": b"\x22" * 20,
                    "amount": 2**64 - 1,
                },
                {
                    "index": 0,
                    "validatorIndex": 0,
                    "address": f"0x{'22' * 20}",  # hexstr address
                    "amount": 0,
                },
            ],
            id="valid_multiple_withdrawals",
        ),
    ),
)
def test_apply_withdrawals_inbound_dict_validation(withdrawals: Any) -> None:
    validate_inbound_withdrawals(withdrawals)


@pytest.mark.parametrize(
    "withdrawals",
    (
        pytest.param({}, id="invalid_dict_instead_of_list"),
        pytest.param(
            {"index": 0, "validator_index": 0, "address": b"\x00" * 20, "amount": 0},
            id="invalid_single_dict",
        ),
        pytest.param([{}], id="invalid_empty_dict_in_list"),
        pytest.param(
            [  # mixed valid and invalid cases
                {  # valid case
                    "index": 0,
                    "validator_index": 0,
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
                {  # invalid case
                    "index": -1,  # negative index
                    "validator_index": 0,
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
            ],
            id="invalid_negative_index",
        ),
        pytest.param(
            [
                {
                    "index": 2**64,  # out of range
                    "validator_index": 0,
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
            ],
            id="invalid_index_overflow",
        ),
        pytest.param(
            [
                {
                    "index": 0,
                    "validator_index": 2**64,  # out of range
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
            ],
            id="invalid_validator_index_overflow",
        ),
        pytest.param(
            [
                {
                    "index": 0,
                    "validator_index": 0,
                    "address": b"\x00" * 20,
                    "amount": 2**64,  # out of range
                },
            ],
            id="invalid_amount_overflow",
        ),
        pytest.param(
            [
                {
                    "index": 0,
                    "validator_index": 0,
                    "address": b"\x00" * 21,  # not 20 bytes
                    "amount": 0,
                },
            ],
            id="invalid_ADDRESS_B_HEXytes_too_long",
        ),
        pytest.param(
            [
                {
                    "index": 0,
                    "validator_index": 0,
                    "address": f"0x{'22' * 19}",  # not 20 bytes
                    "amount": 0,
                },
            ],
            id="invalid_hex_address_too_short",
        ),
    ),
)
def test_apply_withdrawals_inbound_dict_validation_invalid(
    withdrawals: Any,
) -> None:
    with pytest.raises(ValidationError):
        validate_inbound_withdrawals(withdrawals)


@pytest.mark.parametrize(
    "slot",
    (
        pytest.param("0x0", id="valid_0x0"),
        pytest.param("0x1", id="valid_0x1"),
        pytest.param("0x22", id="valid_0x22"),
        pytest.param("0x4d2", id="valid_0x4d2"),
    ),
)
def test_validate_inbound_storage_slot(slot: Any) -> None:
    DefaultValidator.validate_inbound_storage_slot(slot)


@pytest.mark.parametrize(
    "slot",
    (
        pytest.param(0, id="invalid_int_zero"),
        pytest.param(1, id="invalid_int_one"),
        pytest.param(-1, id="invalid_negative_int"),
        pytest.param("1", id="invalid_string_1"),
        pytest.param("-0x1", id="invalid_negative_hex"),
        pytest.param("test", id="invalid_string"),
        pytest.param(b"test", id="invalid_bytes"),
    ),
)
def test_validate_inbound_storage_slot_invalid(slot: Any) -> None:
    with pytest.raises(
        ValidationError,
        match=(
            "Storage slot must be a hex string representation of a positive "
            f"integer - slot: {slot}"
        ),
    ):
        DefaultValidator.validate_inbound_storage_slot(slot)


@pytest.mark.parametrize(
    "slot",
    (pytest.param(hex(2**256 - 1), id="valid_at_max_limit"),),
)
def test_validate_inbound_storage_slot_integer_value_at_limit(slot: Any) -> None:
    DefaultValidator.validate_inbound_storage_slot(slot)


@pytest.mark.parametrize(
    "slot",
    (pytest.param(hex(2**256), id="invalid_exceeds_max_limit"),),
)
def test_validate_inbound_storage_slot_integer_value_at_limit_invalid(
    slot: Any,
) -> None:
    with pytest.raises(
        ValidationError,
        match="Value exceeds maximum 256 bit integer size",
    ):
        DefaultValidator.validate_inbound_storage_slot(slot)


@pytest.mark.parametrize(
    "timestamp",
    (
        pytest.param(4000001, id="valid_integer_timestamp"),
        pytest.param(4000010, id="valid_another_integer_timestamp"),
    ),
)
def test_time_travel_input_timestamp_validation(
    validator: DefaultValidator, timestamp: Any
) -> None:
    validator.validate_inbound_timestamp(timestamp)


@pytest.mark.parametrize(
    "timestamp",
    (
        pytest.param("4000001", id="invalid_string_timestamp"),
        pytest.param("4000010", id="invalid_another_string_timestamp"),
        pytest.param(4000001.0, id="invalid_float_timestamp"),
        pytest.param(4000010.0, id="invalid_another_float_timestamp"),
        pytest.param(True, id="invalid_true_boolean_timestamp"),
        pytest.param(False, id="invalid_false_boolean_timestamp"),
    ),
)
def test_time_travel_input_timestamp_validation_invalid(
    validator: DefaultValidator, timestamp: Any
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_timestamp(timestamp)


@pytest.mark.parametrize(
    "txn_hash",
    (
        pytest.param(f"0x{'01' * 32}", id="valid_hex_txn_hash"),
        pytest.param(f"{'01' * 32}", id="valid_string_txn_hash"),
    ),
)
def test_inbound_txn_hash_validation(
    validator: DefaultValidator, txn_hash: Any
) -> None:
    validator.validate_inbound_transaction_hash(txn_hash)


@pytest.mark.parametrize(
    "txn_hash",
    (
        pytest.param(f"0x{'01' * 20}", id="invalid_20_byte_hex_txn_hash"),
        pytest.param(b"\x01" * 32, id="invalid_32_byte_txn_hash"),
        pytest.param(None, id="none_txn_hash"),
    ),
)
def test_inbound_txn_hash_validation_invalid(
    validator: DefaultValidator, txn_hash: Any
) -> None:
    with pytest.raises(ValidationError):
        validator.validate_inbound_transaction_hash(txn_hash)
