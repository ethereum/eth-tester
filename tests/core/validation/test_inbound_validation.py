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

VALIDATION_ERROR_MESSAGE_REQUIRED_KEYS = (
    "Transaction is missing the required keys: '{}'"
)
VALIDATION_ERROR_MESSAGE_BLOB_TRANSACTIONS = "Transaction contains blob-specific parameters. Blob transactions are only supported via `eth_sendRawTransaction`, rlp encoding the blob sidecar data along with the transaction as per the EIP-4844 `PooledTransaction` model."  # noqa: E501
VALIDATION_ERROR_MESSAGE_EXTRA_KEYS = (
    "Only the keys '{}' are allowed.  Got extra keys: '{}'"
)
VALIDATION_ERROR_MESSAGE_ADDRESS_HEX = (
    "Address must be 20 bytes encoded as hexadecimal - address: {}"
)
VALIDATION_ERROR_MESSAGE_VALUE_POSITIVE_INTEGER = (
    "Value must be a positive integer.  Got: {}"
)
VALIDATION_ERROR_MESSAGE_DATA_HEX = (
    "Transaction 'data' must be a hexadecimal encoded string.  Got: {}"
)
VALIDATION_ERROR_MESSAGE_WITHDRAWAL_LIST = "Invalid withdrawal list - withdrawals: {}"


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
    "account,error_message",
    (
        pytest.param(
            f"0x{'01' * 32}",
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(f"0x{'01' * 32}"),
            id="invalid_32_byte_hex_address",
        ),
        pytest.param(
            b"\x01" * 20,
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(b"\x01" * 20),
            id="invalid_bytes_address",
        ),
        pytest.param(
            None,
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(None),
            id="invalid_none_address",
        ),
    ),
)
def test_inbound_account_invalid(
    validator: DefaultValidator, account: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_account(account)
    assert e.value.args[0] == error_message


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
    "block_hash,error_message",
    (
        pytest.param(
            0,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: 0",
            id="invalid_int_zero",
        ),
        pytest.param(
            1,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: 1",
            id="invalid_int_one",
        ),
        pytest.param(
            -1,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: -1",
            id="invalid_negative_int",
        ),
        pytest.param(
            False,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: False",
            id="invalid_bool_false",
        ),
        pytest.param(
            True,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: True",
            id="invalid_bool_true",
        ),
        pytest.param(
            b"",
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: b''",
            id="invalid_empty_bytes",
        ),
        pytest.param(
            "",
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: ",
            id="invalid_empty_string",
        ),
        pytest.param(
            "0" * 32,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: 00000000000000000000000000000000",  # noqa: E501
            id="invalid_hash_string",
        ),
        pytest.param(
            "0x" + "0" * 32,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: 0x00000000000000000000000000000000",  # noqa: E501
            id="invalid_hash_hex_string",
        ),
        pytest.param(
            "\x00" * 32,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # noqa: E501
            id="invalid_32_bytes_string",
        ),
        pytest.param(
            b"\x00" * 32,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'",  # noqa: E501
            id="invalid_32_bytes",
        ),
        pytest.param(
            b"0x" + b"0" * 64,
            "Block hash must be a hexadecimal encoded 32 byte string.  Got: b'0x0000000000000000000000000000000000000000000000000000000000000000'",  # noqa: E501
            id="invalid_bytes_hex_string",
        ),
    ),
)
def test_block_hash_input_validation_invalid(
    validator: DefaultValidator, block_hash: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_block_hash(block_hash)
    assert e.value.args[0] == error_message


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
    "block_number,error_message",
    (
        pytest.param(
            -1,
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: -1",  # noqa: E501
            id="invalid_negative_int",
        ),
        pytest.param(
            False,
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: False",  # noqa: E501
            id="invalid_bool_false",
        ),
        pytest.param(
            True,
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: True",  # noqa: E501
            id="invalid_bool_true",
        ),
        pytest.param(
            b"latest",
            "Value must be a text string.  Got type: <class 'bytes'>",
            id="invalid_latest_bytes",
        ),
        pytest.param(
            b"pending",
            "Value must be a text string.  Got type: <class 'bytes'>",
            id="invalid_pending_bytes",
        ),
        pytest.param(
            b"earliest",
            "Value must be a text string.  Got type: <class 'bytes'>",
            id="invalid_earliest_bytes",
        ),
        pytest.param(
            b"safe",
            "Value must be a text string.  Got type: <class 'bytes'>",
            id="invalid_safe_bytes",
        ),
        pytest.param(
            b"finalized",
            "Value must be a text string.  Got type: <class 'bytes'>",
            id="invalid_finalized_bytes",
        ),
    ),
)
def test_block_number_input_validation_invalid(
    validator: DefaultValidator, block_number: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_block_number(block_number)
    assert e.value.args[0] == error_message


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
    "filter_id,error_message",
    (
        pytest.param(
            -1,
            "Value must be a positive integer.  Got: -1",
            id="invalid_negative_int",
        ),
        pytest.param(
            "0x0",
            "Value must be a positive integer.  Got: 0x0",
            id="invalid_hex_string_0x0",
        ),
        pytest.param(
            "0x00",
            "Value must be a positive integer.  Got: 0x00",
            id="invalid_hex_string_0x00",
        ),
        pytest.param(
            "0x1",
            "Value must be a positive integer.  Got: 0x1",
            id="invalid_hex_string_0x1",
        ),
        pytest.param(
            "0x01",
            "Value must be a positive integer.  Got: 0x01",
            id="invalid_hex_string_0x01",
        ),
        pytest.param(
            "0", "Value must be a positive integer.  Got: 0", id="invalid_string_0"
        ),
        pytest.param(
            "1", "Value must be a positive integer.  Got: 1", id="invalid_string_1"
        ),
    ),
)
def test_filter_id_input_validation_invalid(
    validator: DefaultValidator, filter_id: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_filter_id(filter_id)
    assert e.value.args[0] == error_message


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
    "filter_params,error_message",
    (
        pytest.param(
            make_filter_params(from_block=-1),
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: -1",  # noqa: E501
            id="invalid_from_block_negative",
        ),
        pytest.param(
            make_filter_params(to_block=-1),
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: -1",  # noqa: E501
            id="invalid_to_block_negative",
        ),
        pytest.param(
            make_filter_params(from_block=True),
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: True",  # noqa: E501
            id="invalid_from_block_bool",
        ),
        pytest.param(
            make_filter_params(to_block=False),
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: False",  # noqa: E501
            id="invalid_to_block_bool",
        ),
        pytest.param(
            make_filter_params(from_block="0x0"),
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: 0x0",  # noqa: E501
            id="invalid_from_block_hex_string",
        ),
        pytest.param(
            make_filter_params(to_block="0x0"),
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: 0x0",  # noqa: E501
            id="invalid_to_block_hex_string",
        ),
        pytest.param(
            make_filter_params(from_block="0x1"),
            "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: 0x1",  # noqa: E501
            id="invalid_from_block_hex_one",
        ),
        pytest.param(
            make_filter_params(address=decode_hex(ADDRESS_A_HEX)),
            "Address must be 20 bytes encoded as hexadecimal - address: b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01'",  # noqa: E501
            id="invalid_address_decode_hex",
        ),
        pytest.param(
            make_filter_params(address=TOPIC_A_HEX),
            "Address must be 20 bytes encoded as hexadecimal - address: 0x0000000000000000000000000000000000000000000000000000000000000001",  # noqa: E501
            id="invalid_address_topic",
        ),
        pytest.param(
            make_filter_params(address=decode_hex(TOPIC_A_HEX)),
            "Address must be 20 bytes encoded as hexadecimal - address: b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01'",  # noqa: E501
            id="invalid_address_decode_hex_topic",
        ),
        pytest.param(
            make_filter_params(address=[TOPIC_A_HEX, ADDRESS_B_HEX]),
            "Address must be 20 bytes encoded as hexadecimal - address: 0x0000000000000000000000000000000000000000000000000000000000000001",  # noqa: E501
            id="invalid_mixed_address_topic",
        ),
        pytest.param(
            make_filter_params(topics=[decode_hex(TOPIC_C_HEX)]),
            'Topics must be one of `None` or an array of topics. Each topic must be 32 bytes, represented as a bytestring or its hex string equivalent. A filter query of topics using "OR" can be achieved using a sub-array of topics. See https://eth.wiki/json-rpc/API#eth_newfilter for more details.',  # noqa: E501
            id="invalid_topic_length_short",
        ),
        pytest.param(
            make_filter_params(topics=[decode_hex(TOPIC_D_HEX)]),
            'Topics must be one of `None` or an array of topics. Each topic must be 32 bytes, represented as a bytestring or its hex string equivalent. A filter query of topics using "OR" can be achieved using a sub-array of topics. See https://eth.wiki/json-rpc/API#eth_newfilter for more details.',  # noqa: E501
            id="invalid_topic_length_long",
        ),
        pytest.param(
            make_filter_params(topics=[ADDRESS_A_HEX]),
            'Topics must be one of `None` or an array of topics. Each topic must be 32 bytes, represented as a bytestring or its hex string equivalent. A filter query of topics using "OR" can be achieved using a sub-array of topics. See https://eth.wiki/json-rpc/API#eth_newfilter for more details.',  # noqa: E501
            id="invalid_topic_is_address",
        ),
        pytest.param(
            make_filter_params(topics=[ADDRESS_A_HEX, TOPIC_B_HEX]),
            'Topics must be one of `None` or an array of topics. Each topic must be 32 bytes, represented as a bytestring or its hex string equivalent. A filter query of topics using "OR" can be achieved using a sub-array of topics. See https://eth.wiki/json-rpc/API#eth_newfilter for more details.',  # noqa: E501
            id="invalid_topic_mix_address",
        ),
        pytest.param(
            make_filter_params(topics=[[ADDRESS_A_HEX], [TOPIC_B_HEX]]),
            'Topics must be one of `None` or an array of topics. Each topic must be 32 bytes, represented as a bytestring or its hex string equivalent. A filter query of topics using "OR" can be achieved using a sub-array of topics. See https://eth.wiki/json-rpc/API#eth_newfilter for more details.',  # noqa: E501
            id="invalid_nested_topic_with_address",
        ),
    ),
)
def test_filter_params_input_validation_invalid(
    validator: DefaultValidator, filter_params: Dict[str, Any], error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_filter_params(**filter_params)
    assert e.value.args[0] == error_message


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
    "private_key,error_message",
    (
        pytest.param(
            f"0x{'01' * 20}",
            "Private keys must be 32 bytes encoded as hexadecimal",
            id="invalid_20_byte_hex_private_key",
        ),  # noqa: E501
        pytest.param(
            b"\x01" * 32,
            "Private keys must be 32 bytes encoded as hexadecimal",
            id="invalid_32_byte_private_key",
        ),  # noqa: E501
        pytest.param(
            None,
            "Private keys must be 32 bytes encoded as hexadecimal",
            id="none_private_key",
        ),  # noqa: E501
    ),
)
def test_private_key_input_validation_invalid(
    validator: DefaultValidator, private_key: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_private_key(private_key)
    assert e.value.args[0] == error_message


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
    "raw_transaction,error_message",
    (
        pytest.param(
            "",
            "Raw Transaction must be a hexadecimal encoded string.  Got: ",
            id="invalid_empty_raw_transaction_string",
        ),
        pytest.param(
            b"\x01" * 32,
            "Raw Transaction must be a hexadecimal encoded string.  Got: b'\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01'",  # noqa: E501
            id="invalid_raw_transaction_bytes",
        ),
        pytest.param(
            False,
            "Raw Transaction must be a hexadecimal encoded string.  Got: False",
            id="invalid_raw_transaction_bool_false",
        ),  # noqa: E501
        pytest.param(
            1,
            "Raw Transaction must be a hexadecimal encoded string.  Got: 1",
            id="invalid_raw_transaction_int",
        ),  # noqa: E501
    ),
)
def test_inbound_raw_transaction_invalid(
    validator: DefaultValidator, raw_transaction: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_raw_transaction(raw_transaction)
    assert e.value.args[0] == error_message


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
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX, to="", gas=21000, gas_price=1000000000000000000
            ),
            id="valid_large_gas_price",
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
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, gas=1, data="0x1234567890"),
            id="valid_data_transaction",
        ),
        pytest.param(
            "send",
            make_transaction(chain_id=1, _from=ADDRESS_A_HEX, gas=1),
            id="valid_chain_id_transaction",
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
    "txn_internal_type,transaction,validation_error_message",
    (
        pytest.param(
            "send",
            {},
            VALIDATION_ERROR_MESSAGE_REQUIRED_KEYS.format("from/gas"),
            id="empty_transaction",
        ),
        pytest.param(
            "send",
            make_transaction(to=ADDRESS_B_HEX, gas=21000),
            VALIDATION_ERROR_MESSAGE_REQUIRED_KEYS.format("from"),
            id="missing_from",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to=ADDRESS_B_HEX),
            VALIDATION_ERROR_MESSAGE_REQUIRED_KEYS.format("gas"),
            id="missing_gas",
        ),
        pytest.param(
            "send",
            make_transaction(_from="", to=ADDRESS_B_HEX, gas=21000),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(""),
            id="empty_from",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to=b"", gas=21000),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(b""),
            id="empty_to_bytes",
        ),
        pytest.param(
            "send",
            make_transaction(
                _from=decode_hex(ADDRESS_A_HEX), to=ADDRESS_B_HEX, gas=21000
            ),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"  # noqa: E501
            ),  # noqa: E501
            id="from_as_bytes",
        ),
        pytest.param(
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX, to=decode_hex(ADDRESS_B_HEX), gas=21000
            ),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"  # noqa: E501
            ),  # noqa: E501
            id="to_as_bytes",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="0x4"),
            "Transaction type '0x4' not recognized.",
            id="invalid_type_0x4",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="1"),
            "Transaction type string must be hex string. Got: 1",
            id="invalid_type_string_1",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, _type="x1"),
            "Transaction type must be hexadecimal or integer. Got x1",
            id="invalid_type_x1",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, value=-1),
            "Value must be a positive integer.  Got: -1",
            id="invalid_negative_value",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, data="0x0"),
            "Transaction 'data' must be a hexadecimal encoded string.  Got: 0x0",
            id="invalid_odd_length_data",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=-1),
            "Value must be a positive integer.  Got: -1",
            id="invalid_negative_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce="0x1"),
            "Value must be a positive integer.  Got: 0x1",
            id="invalid_hex_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce="arst"),
            "Value must be a positive integer.  Got: arst",
            id="invalid_string_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=True),
            "Value must be a positive integer.  Got: True",
            id="invalid_bool_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=1.0),
            "Value must be a positive integer.  Got: 1.0",
            id="invalid_float_nonce",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, nonce=-1),
            "Value must be a positive integer.  Got: -1",
            id="invalid_negative_nonce_2",
        ),
        pytest.param(
            "send_signed",
            make_transaction(_from=ADDRESS_A_HEX, gas=21000),
            VALIDATION_ERROR_MESSAGE_REQUIRED_KEYS.format("r/s/v"),
            id="signed_missing_signature",
        ),
        pytest.param(
            "send_signed",
            make_transaction(_from=ADDRESS_A_HEX, gas=21000, r=1, s=1, v=256),
            "Value exceeds maximum 7 bit integer size:  256",
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
            "accessList storage keys are not list-like: None",
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
            "accessList storage keys are not list-like: None",
            id="invalid_access_list_address",
        ),
        pytest.param(
            "send",
            make_transaction(blob_versioned_hashes=[]),
            VALIDATION_ERROR_MESSAGE_BLOB_TRANSACTIONS,
            id="invalid_empty_blob_hashes",
        ),
        pytest.param(
            "send",
            make_transaction(blob_versioned_hashes=[b""]),
            VALIDATION_ERROR_MESSAGE_BLOB_TRANSACTIONS,
            id="invalid_empty_bytes_blob_hash",
        ),
        pytest.param(
            "send",
            make_transaction(blob_versioned_hashes=[b"0x"]),
            VALIDATION_ERROR_MESSAGE_BLOB_TRANSACTIONS,
            id="invalid_0x_bytes_blob_hash",
        ),
        pytest.param(
            "send",
            make_transaction(max_fee_per_blob_gas=0),
            VALIDATION_ERROR_MESSAGE_BLOB_TRANSACTIONS,
            id="invalid_zero_max_fee_per_blob_gas",
        ),
        pytest.param(
            "send",
            make_transaction(max_fee_per_blob_gas=1),
            VALIDATION_ERROR_MESSAGE_BLOB_TRANSACTIONS,
            id="invalid_positive_max_fee_per_blob_gas",
        ),
        pytest.param(
            "send",
            make_transaction(max_fee_per_blob_gas="0x0"),
            VALIDATION_ERROR_MESSAGE_BLOB_TRANSACTIONS,
            id="invalid_hex_max_fee_per_blob_gas",
        ),
        pytest.param(
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX, gas=1, gas_price=1, max_fee_per_gas=1
            ),
            "Mixed legacy and dynamic fee transaction values",
            id="invalid_mixed_legacy_and_max_fee_per_gas",
        ),
        pytest.param(
            "send",
            make_transaction(
                _from=ADDRESS_A_HEX, gas=1, gas_price=1, max_priority_fee_per_gas=1
            ),
            "Mixed legacy and dynamic fee transaction values",
            id="invalid_mixed_legacy_and_max_priority_fee_per_gas",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, gas=1, data="0x0"),
            "Transaction 'data' must be a hexadecimal encoded string.  Got: 0x0",
            id="invalid_0x_data_string",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, gas=1, data=False),
            "Transaction 'data' must be a hexadecimal encoded string.  Got: False",
            id="invalid_data_boolean",
        ),
        pytest.param(
            "send",
            make_transaction(_from=ADDRESS_A_HEX, gas=1, data="0x12345"),
            "Transaction 'data' must be a hexadecimal encoded string.  Got: 0x12345",
            id="invalid_data_string",
        ),
        pytest.param(
            "send",
            make_transaction(chain_id="abc", _from=ADDRESS_A_HEX, gas=1),
            "Value must be a positive integer.  Got: abc",
            id="invalid_chain_id_transaction",
        ),
    ),
)
def test_transaction_input_validation_invalid(
    validator: DefaultValidator,
    txn_internal_type: str,
    transaction: Dict[str, Any],
    validation_error_message: str,
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_transaction(transaction, txn_internal_type)
    assert e.value.args[0] == validation_error_message  # noqa: E501


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
    "txn_internal_type",
    ("call", "estimate"),
)
@pytest.mark.parametrize(
    "transaction,error_message",
    (
        pytest.param(
            {},
            VALIDATION_ERROR_MESSAGE_REQUIRED_KEYS.format("from"),
            id="empty_transaction",
        ),
        pytest.param(
            make_transaction(to=ADDRESS_B_HEX),
            VALIDATION_ERROR_MESSAGE_REQUIRED_KEYS.format("from"),
            id="missing_from",
        ),
        pytest.param(
            make_transaction(gas=21000),
            VALIDATION_ERROR_MESSAGE_REQUIRED_KEYS.format("from"),
            id="only_gas",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, gas=True),
            "Value must be a positive integer.  Got: True",
            id="invalid_gas_type",
        ),
        pytest.param(
            make_transaction(_from=""),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(""),
            id="empty_from_string",
        ),
        pytest.param(
            make_transaction(_from="", to=ADDRESS_B_HEX),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(""),
            id="empty_from_with_to",
        ),
        pytest.param(
            make_transaction(_from="", gas=21000),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(""),
            id="empty_from_with_gas",
        ),
        pytest.param(
            make_transaction(_from="", to=ADDRESS_B_HEX, gas=21000),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(""),
            id="empty_from_complete",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to=b""),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(b""),
            id="empty_to_bytes",
        ),
        pytest.param(
            make_transaction(
                _from=decode_hex(ADDRESS_A_HEX), to=ADDRESS_B_HEX, gas=21000
            ),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(b"\x00" * 19 + b"\x01"),
            id="from_as_bytes_with_gas",
        ),
        pytest.param(
            make_transaction(_from=decode_hex(ADDRESS_A_HEX), to=ADDRESS_B_HEX),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(b"\x00" * 19 + b"\x01"),
            id="from_as_bytes",
        ),
        pytest.param(
            make_transaction(
                _from=ADDRESS_A_HEX, to=decode_hex(ADDRESS_B_HEX), gas=21000
            ),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(b"\x00" * 19 + b"\x02"),
            id="to_as_bytes_with_gas",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to=decode_hex(ADDRESS_B_HEX)),
            VALIDATION_ERROR_MESSAGE_ADDRESS_HEX.format(b"\x00" * 19 + b"\x02"),
            id="to_as_bytes",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", value=-1),
            VALIDATION_ERROR_MESSAGE_VALUE_POSITIVE_INTEGER.format(-1),
            id="negative_value",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", data=b""),
            VALIDATION_ERROR_MESSAGE_DATA_HEX.format(b""),
            id="empty_data_bytes",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", data=b"0x"),
            VALIDATION_ERROR_MESSAGE_DATA_HEX.format(b"0x"),
            id="0x_data_bytes",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", data="0x0"),
            VALIDATION_ERROR_MESSAGE_DATA_HEX.format("0x0"),
            id="invalid_odd_length_data",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, value=-1),
            VALIDATION_ERROR_MESSAGE_VALUE_POSITIVE_INTEGER.format(-1),
            id="invalid_with_negative_value",
        ),
        pytest.param(
            make_transaction(_from=ADDRESS_A_HEX, to="", gas=21000, data="0x0"),
            VALIDATION_ERROR_MESSAGE_DATA_HEX.format("0x0"),
            id="invalid_with_odd_length_data",
        ),
    ),
)
def test_transaction_call_and_estimate_gas_input_validation_invalid(
    validator: DefaultValidator,
    txn_internal_type: str,
    transaction: Dict[str, Any],
    error_message: str,
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_transaction(
            transaction, txn_internal_type=txn_internal_type
        )
    assert e.value.args[0] == error_message


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
    "withdrawals,error_message",
    (
        pytest.param(
            {}, "Withdrawals list must not be empty.", id="invalid_dict_instead_of_list"
        ),
        pytest.param(
            {"index": 0, "validatorIndex": 0, "address": b"\x00" * 20, "amount": 0},
            "Value must be a dictionary.  Got: <class 'str'>",
            id="invalid_single_dict",
        ),
        pytest.param(
            [{}],
            "dict must contain all of the keys 'address/amount/index/validatorIndex'.  Missing the keys: 'address/amount/index/validatorIndex'",  # noqa: E501
            id="invalid_empty_dict_in_list",
        ),
        pytest.param(
            [  # mixed valid and invalid cases
                {  # valid case
                    "index": 0,
                    "validatorIndex": 0,
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
                {  # invalid case
                    "index": -1,  # negative index
                    "validatorIndex": 0,
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
            ],
            "The following keys failed to validate\n- index: Value must be a positive integer.  Got: -1",  # noqa: E501
            id="invalid_negative_index",
        ),
        pytest.param(
            [
                {
                    "index": 2**64,  # out of range
                    "validatorIndex": 0,
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
            ],
            "The following keys failed to validate\n- index: Value exceeds maximum 64 bit integer size:  18446744073709551616",  # noqa: E501
            id="invalid_index_overflow",
        ),
        pytest.param(
            [
                {
                    "index": 0,
                    "validatorIndex": 2**64,  # out of range
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
            ],
            "The following keys failed to validate\n- validatorIndex: Value exceeds maximum 64 bit integer size:  18446744073709551616",  # noqa: E501
            id="invalid_validator_index_overflow",
        ),
        pytest.param(
            [
                {
                    "index": 0,
                    "validatorIndex": 0,
                    "address": b"\x00" * 20,
                    "amount": 2**64,  # out of range
                },
            ],
            "The following keys failed to validate\n- amount: Value exceeds maximum 64 bit integer size:  18446744073709551616",  # noqa: E501
            id="invalid_amount_overflow",
        ),
        pytest.param(
            [
                {
                    "index": 0,
                    "validatorIndex": 0,
                    "address": b"\x00" * 21,  # not 20 bytes
                    "amount": 0,
                },
            ],
            "The following keys failed to validate\n- address: Value must be a valid address. Got: b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'",  # noqa: E501
            id="invalid_address_too_long",
        ),
        pytest.param(
            [
                {
                    "index": 0,
                    "validatorIndex": 0,
                    "address": f"0x{'22' * 19}",  # not 20 bytes
                    "amount": 0,
                },
            ],
            "The following keys failed to validate\n- address: Value must be a valid address. Got: 0x22222222222222222222222222222222222222",  # noqa: E501
            id="invalid_hex_address_too_short",
        ),
    ),
)
def test_apply_withdrawals_inbound_dict_validation_invalid(
    withdrawals: Any,
    error_message: str,
) -> None:
    with pytest.raises(ValidationError) as e:
        validate_inbound_withdrawals(withdrawals)
    assert e.value.args[0] == error_message


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
    "slot,error_message",
    (
        pytest.param(
            0,
            "Storage slot must be a hex string representation of a positive integer - slot: 0",  # noqa: E501
            id="invalid_int_zero",
        ),
        pytest.param(
            1,
            "Storage slot must be a hex string representation of a positive integer - slot: 1",  # noqa: E501
            id="invalid_int_one",
        ),
        pytest.param(
            -1,
            "Storage slot must be a hex string representation of a positive integer - slot: -1",  # noqa: E501
            id="invalid_negative_int",
        ),
        pytest.param(
            "1",
            "Storage slot must be a hex string representation of a positive integer - slot: 1",  # noqa: E501
            id="invalid_string_1",
        ),
        pytest.param(
            "-0x1",
            "Storage slot must be a hex string representation of a positive integer - slot: -0x1",  # noqa: E501
            id="invalid_negative_hex",
        ),
        pytest.param(
            "test",
            "Storage slot must be a hex string representation of a positive integer - slot: test",  # noqa: E501
            id="invalid_string",
        ),
        pytest.param(
            b"test",
            "Storage slot must be a hex string representation of a positive integer - slot: b'test'",  # noqa: E501
            id="invalid_bytes",
        ),
    ),
)
def test_validate_inbound_storage_slot_invalid(slot: Any, error_message: str) -> None:
    with pytest.raises(
        ValidationError,
        match=(
            "Storage slot must be a hex string representation of a positive "
            f"integer - slot: {slot}"
        ),
    ) as e:
        DefaultValidator.validate_inbound_storage_slot(slot)
    assert e.value.args[0] == error_message


@pytest.mark.parametrize(
    "slot",
    (pytest.param(hex(2**256 - 1), id="valid_at_max_limit"),),
)
def test_validate_inbound_storage_slot_integer_value_at_limit(slot: Any) -> None:
    DefaultValidator.validate_inbound_storage_slot(slot)


@pytest.mark.parametrize(
    "slot,error_message",
    (
        pytest.param(
            hex(2**256),
            "Value exceeds maximum 256 bit integer size:  115792089237316195423570985008687907853269984665640564039457584007913129639936",  # noqa: E501
            id="invalid_exceeds_max_limit",
        ),
    ),
)
def test_validate_inbound_storage_slot_integer_value_at_limit_invalid(
    slot: Any,
    error_message: str,
) -> None:
    with pytest.raises(
        ValidationError,
        match="Value exceeds maximum 256 bit integer size",
    ) as e:
        DefaultValidator.validate_inbound_storage_slot(slot)
    assert e.value.args[0] == error_message


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
    "timestamp,error_message",
    (
        pytest.param(
            "4000001",
            "Value must be a positive integer.  Got: 4000001",
            id="invalid_string_timestamp",
        ),
        pytest.param(
            "4000010",
            "Value must be a positive integer.  Got: 4000010",
            id="invalid_another_string_timestamp",
        ),
        pytest.param(
            4000001.0,
            "Value must be a positive integer.  Got: 4000001.0",
            id="invalid_float_timestamp",
        ),
        pytest.param(
            4000010.0,
            "Value must be a positive integer.  Got: 4000010.0",
            id="invalid_another_float_timestamp",
        ),
        pytest.param(
            True,
            "Value must be a positive integer.  Got: True",
            id="invalid_true_boolean_timestamp",
        ),
        pytest.param(
            False,
            "Value must be a positive integer.  Got: False",
            id="invalid_false_boolean_timestamp",
        ),
    ),
)
def test_time_travel_input_timestamp_validation_invalid(
    validator: DefaultValidator, timestamp: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_timestamp(timestamp)
    assert e.value.args[0] == error_message


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
    "txn_hash,error_message",
    (
        pytest.param(
            f"0x{'01' * 20}",
            "Transaction hash must be a hexadecimal encoded 32 byte string.  Got: 0x0101010101010101010101010101010101010101",  # noqa: E501
            id="invalid_20_byte_hex_txn_hash",
        ),
        pytest.param(
            b"\x01" * 32,
            "Transaction hash must be a hexadecimal encoded 32 byte string.  Got: b'\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01\\x01'",  # noqa: E501
            id="invalid_32_byte_txn_hash",
        ),
        pytest.param(
            None,
            "Transaction hash must be a hexadecimal encoded 32 byte string.  Got: None",
            id="none_txn_hash",
        ),
    ),
)
def test_inbound_txn_hash_validation_invalid(
    validator: DefaultValidator, txn_hash: Any, error_message: str
) -> None:
    with pytest.raises(ValidationError) as e:
        validator.validate_inbound_transaction_hash(txn_hash)
    assert e.value.args[0] == error_message
