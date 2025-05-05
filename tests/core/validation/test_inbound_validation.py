from typing import (
    Any,
    Dict,
    Generator,
    Tuple,
)

import pytest

from eth_utils import (
    decode_hex,
    encode_hex,
    to_dict,
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
from tests.utils import (
    yield_key_value_if_value_not_none,
)


@pytest.mark.parametrize(
    "account,is_valid",
    (
        pytest.param(f"0x{'01' * 20}", True, id="valid_20_byte_hex_address"),
        pytest.param(f"{'01' * 20}", True, id="valid_string_address"),
        pytest.param(f"0x{'01' * 32}", False, id="invalid_32_byte_hex_address"),
        pytest.param(b"\x01" * 20, False, id="invalid_bytes_address"),
        pytest.param(None, False, id="invalid_none_address"),
    ),
)
def test_inbound_account(account: Any, is_valid: bool) -> None:
    if is_valid:
        DefaultValidator.validate_inbound_account(account)
    else:
        with pytest.raises(ValidationError):
            DefaultValidator.validate_inbound_account(account)


@pytest.mark.parametrize(
    "block_hash,is_valid",
    (
        pytest.param(0, False, id="invalid_int_zero"),
        pytest.param(1, False, id="invalid_int_one"),
        pytest.param(-1, False, id="invalid_negative_int"),
        pytest.param(False, False, id="invalid_bool_false"),
        pytest.param(True, False, id="invalid_bool_true"),
        pytest.param(b"", False, id="invalid_empty_bytes"),
        pytest.param("", False, id="invalid_empty_string"),
        pytest.param("0" * 32, False, id="invalid_hash_string"),
        pytest.param("0x" + "0" * 32, False, id="invalid_hash_hex_string"),
        pytest.param("\x00" * 32, False, id="invalid_32_bytes_string"),
        pytest.param(b"\x00" * 32, False, id="invalid_32_bytes"),
        pytest.param("0" * 64, True, id="valid_hash_string"),
        pytest.param("0x" + "0" * 64, True, id="valid_hash_hex_string"),
        pytest.param(b"0x" + b"0" * 64, False, id="invalid_bytes_hex_string"),
    ),
)
def test_block_hash_input_validation(
    validator: DefaultValidator, block_hash: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_inbound_block_hash(block_hash)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_block_hash(block_hash)


@pytest.mark.parametrize(
    "block_number,is_valid",
    (
        pytest.param(0, True, id="valid_zero"),
        pytest.param(1, True, id="valid_positive_int"),
        pytest.param(-1, False, id="invalid_negative_int"),
        pytest.param(False, False, id="invalid_bool_false"),
        pytest.param(True, False, id="invalid_bool_true"),
        pytest.param("latest", True, id="valid_latest_string"),
        pytest.param("pending", True, id="valid_pending_string"),
        pytest.param("earliest", True, id="valid_earliest_string"),
        pytest.param("safe", True, id="valid_safe_string"),
        pytest.param("finalized", True, id="valid_finalized_string"),
        pytest.param(2**256, True, id="valid_large_int"),
        pytest.param(b"latest", False, id="invalid_latest_bytes"),
        pytest.param(b"pending", False, id="invalid_pending_bytes"),
        pytest.param(b"earliest", False, id="invalid_earliest_bytes"),
        pytest.param(b"safe", False, id="invalid_safe_bytes"),
        pytest.param(b"finalized", False, id="invalid_finalized_bytes"),
    ),
)
def test_block_number_input_validation(
    validator: DefaultValidator, block_number: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_inbound_block_number(block_number)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_block_number(block_number)


@pytest.mark.parametrize(
    "filter_id,is_valid",
    (
        pytest.param(-1, False, id="invalid_negative_int"),
        pytest.param(0, True, id="valid_zero"),
        pytest.param(1, True, id="valid_positive_int"),
        pytest.param("0x0", False, id="invalid_hex_string_0x0"),
        pytest.param("0x00", False, id="invalid_hex_string_0x00"),
        pytest.param("0x1", False, id="invalid_hex_string_0x1"),
        pytest.param("0x01", False, id="invalid_hex_string_0x01"),
        pytest.param("0", False, id="invalid_string_0"),
        pytest.param("1", False, id="invalid_string_1"),
    ),
)
def test_filter_id_input_validation(
    validator: DefaultValidator, filter_id: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_inbound_filter_id(filter_id)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_filter_id(filter_id)


def _make_filter_params(
    from_block: Any = None,
    to_block: Any = None,
    address: Any = None,
    topics: Any = None,
) -> Dict[str, Any]:
    return {
        "from_block": from_block,
        "to_block": to_block,
        "address": address,
        "topics": topics,
    }


ADDRESS_A = encode_hex(b"\x00" * 19 + b"\x01")
ADDRESS_B = encode_hex(b"\x00" * 19 + b"\x02")
TOPIC_A = encode_hex(b"\x00" * 31 + b"\x01")
TOPIC_B = encode_hex(b"\x00" * 31 + b"\x02")
TOPIC_C = encode_hex(b"\x00" * 30 + b"\x01")
TOPIC_D = encode_hex(b"\x00" * 32 + b"\x01")


@pytest.mark.parametrize(
    "filter_params,is_valid",
    (
        pytest.param(_make_filter_params(), True, id="empty_filter"),
        pytest.param(
            _make_filter_params(from_block=0), True, id="valid_from_block_zero"
        ),
        pytest.param(_make_filter_params(to_block=0), True, id="valid_to_block_zero"),
        pytest.param(
            _make_filter_params(from_block=-1), False, id="invalid_from_block_negative"
        ),
        pytest.param(
            _make_filter_params(to_block=-1), False, id="invalid_to_block_negative"
        ),
        pytest.param(
            _make_filter_params(from_block=True), False, id="invalid_from_block_bool"
        ),
        pytest.param(
            _make_filter_params(to_block=False), False, id="invalid_to_block_bool"
        ),
        pytest.param(
            _make_filter_params(from_block="0x0"),
            False,
            id="invalid_from_block_hex_string",
        ),
        pytest.param(
            _make_filter_params(to_block="0x0"), False, id="invalid_to_block_hex_string"
        ),
        pytest.param(
            _make_filter_params(from_block="0x1"),
            False,
            id="invalid_from_block_hex_one",
        ),
        pytest.param(
            _make_filter_params(to_block="0x1"), False, id="invalid_to_block_hex_one"
        ),
        pytest.param(
            _make_filter_params(address=ADDRESS_A), True, id="valid_single_address"
        ),
        pytest.param(
            _make_filter_params(address=decode_hex(ADDRESS_A)),
            False,
            id="invalid_address_bytes",
        ),
        pytest.param(
            _make_filter_params(address=[ADDRESS_A, ADDRESS_B]),
            True,
            id="valid_multiple_addresses",
        ),
        pytest.param(
            _make_filter_params(address=TOPIC_A), False, id="invalid_address_topic"
        ),
        pytest.param(
            _make_filter_params(address=decode_hex(TOPIC_A)),
            False,
            id="invalid_address_topic_bytes",
        ),
        pytest.param(
            _make_filter_params(address=[TOPIC_A, ADDRESS_B]),
            False,
            id="invalid_mixed_address_topic",
        ),
        pytest.param(
            _make_filter_params(topics=[TOPIC_A]), True, id="valid_single_topic"
        ),
        pytest.param(
            _make_filter_params(topics=[TOPIC_A, TOPIC_B]),
            True,
            id="valid_multiple_topics",
        ),
        pytest.param(
            _make_filter_params(topics=[TOPIC_A, None]),
            True,
            id="valid_topic_with_none",
        ),
        pytest.param(
            _make_filter_params(topics=[[TOPIC_A], [TOPIC_B]]),
            True,
            id="valid_nested_topics",
        ),
        pytest.param(
            _make_filter_params(topics=[TOPIC_A, [TOPIC_B, TOPIC_A]]),
            True,
            id="valid_mixed_topic_structure",
        ),
        pytest.param(
            _make_filter_params(topics=[[TOPIC_A], [TOPIC_B, None]]),
            True,
            id="valid_nested_topics_with_none",
        ),
        pytest.param(
            _make_filter_params(topics=[decode_hex(TOPIC_A)]),
            True,
            id="valid_topic_bytes",
        ),
        pytest.param(
            _make_filter_params(topics=[decode_hex(TOPIC_A), decode_hex(TOPIC_B)]),
            True,
            id="valid_multiple_topic_bytes",
        ),
        pytest.param(
            _make_filter_params(topics=[decode_hex(TOPIC_A), None]),
            True,
            id="valid_topic_bytes_with_none",
        ),
        pytest.param(
            _make_filter_params(topics=[[decode_hex(TOPIC_A)], [decode_hex(TOPIC_B)]]),
            True,
            id="valid_nested_topic_bytes",
        ),
        pytest.param(
            _make_filter_params(
                topics=[decode_hex(TOPIC_A), [decode_hex(TOPIC_B), decode_hex(TOPIC_A)]]
            ),
            True,
            id="valid_mixed_topic_bytes",
        ),
        pytest.param(
            _make_filter_params(
                topics=[[decode_hex(TOPIC_A)], [decode_hex(TOPIC_B), None]]
            ),
            True,
            id="valid_nested_topic_bytes_with_none",
        ),
        pytest.param(
            _make_filter_params(topics=[decode_hex(TOPIC_C)]),
            False,
            id="invalid_topic_length_short",
        ),
        pytest.param(
            _make_filter_params(topics=[decode_hex(TOPIC_D)]),
            False,
            id="invalid_topic_length_long",
        ),
        pytest.param(
            _make_filter_params(topics=[ADDRESS_A]),
            False,
            id="invalid_topic_is_address",
        ),
        pytest.param(
            _make_filter_params(topics=[ADDRESS_A, TOPIC_B]),
            False,
            id="invalid_topic_mix_address",
        ),
        pytest.param(
            _make_filter_params(topics=[[ADDRESS_A], [TOPIC_B]]),
            False,
            id="invalid_nested_topic_with_address",
        ),
    ),
)
def test_filter_params_input_validation(
    validator: DefaultValidator, filter_params: Dict[str, Any], is_valid: bool
) -> None:
    if is_valid:
        validator.validate_inbound_filter_params(**filter_params)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_filter_params(**filter_params)


@pytest.mark.parametrize(
    "private_key,is_valid",
    (
        pytest.param(f"0x{'01' * 32}", True, id="valid_hex_private_key"),
        pytest.param(f"{'01' * 32}", True, id="valid_string_private_key"),
        pytest.param(f"0x{'01' * 20}", False, id="invalid_20_byte_hex_private_key"),
        pytest.param(b"\x01" * 32, False, id="invalid_32_byte_private_key"),
        pytest.param(None, False, id="none_private_key"),
    ),
)
def test_private_key_input_validation(private_key: Any, is_valid: bool) -> None:
    if is_valid:
        DefaultValidator.validate_inbound_private_key(private_key)
    else:
        with pytest.raises(ValidationError):
            DefaultValidator.validate_inbound_private_key(private_key)


@to_dict
def _make_transaction(
    blob_versioned_hashes: Any = None,
    chain_id: Any = None,
    _type: Any = None,
    _from: Any = None,
    to: Any = None,
    gas: Any = None,
    gas_price: Any = None,
    max_fee_per_blob_gas: Any = None,
    max_fee_per_gas: Any = None,
    max_priority_fee_per_gas: Any = None,
    value: Any = None,
    data: Any = None,
    nonce: Any = None,
    access_list: Any = None,
    r: Any = None,
    s: Any = None,
    v: Any = None,
) -> Generator[Tuple[str, Any], None, None]:
    yield from yield_key_value_if_value_not_none("type", _type)
    yield from yield_key_value_if_value_not_none("chain_id", chain_id)
    yield from yield_key_value_if_value_not_none("from", _from)
    yield from yield_key_value_if_value_not_none("to", to)
    yield from yield_key_value_if_value_not_none("gas", gas)
    yield from yield_key_value_if_value_not_none("gas_price", gas_price)
    yield from yield_key_value_if_value_not_none("max_fee_per_gas", max_fee_per_gas)
    yield from yield_key_value_if_value_not_none(
        "max_priority_fee_per_gas", max_priority_fee_per_gas
    )
    yield from yield_key_value_if_value_not_none("value", value)
    yield from yield_key_value_if_value_not_none("data", data)
    yield from yield_key_value_if_value_not_none("nonce", nonce)
    yield from yield_key_value_if_value_not_none("access_list", access_list)
    yield from yield_key_value_if_value_not_none("r", r)
    yield from yield_key_value_if_value_not_none("s", s)
    yield from yield_key_value_if_value_not_none("v", v)
    yield from yield_key_value_if_value_not_none(
        "blob_versioned_hashes", blob_versioned_hashes
    )
    yield from yield_key_value_if_value_not_none(
        "max_fee_per_blob_gas", max_fee_per_blob_gas
    )


@pytest.mark.parametrize(
    "raw_transaction,is_valid",
    (
        pytest.param(f"0x{'01' * 32}", True, id="valid_raw_transaction"),
        pytest.param("0x", True, id="valid_empty_raw_transaction"),
        pytest.param("12345", True, id="valid_raw_transaction"),
        pytest.param("", False, id="invalid_empty_raw_transaction_string"),
        pytest.param(b"\x01" * 32, False, id="invalid_raw_transaction_bytes"),
        pytest.param(False, False, id="invalid_raw_transaction_bool_false"),
        pytest.param(1, False, id="invalid_raw_transaction_int"),
    ),
)
def test_inbound_raw_transaction(
    validator: DefaultValidator, raw_transaction: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_inbound_raw_transaction(raw_transaction)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_raw_transaction(raw_transaction)


@pytest.mark.parametrize(
    "txn_internal_type, transaction, is_valid",
    (
        pytest.param("send", {}, False, id="empty_transaction"),
        pytest.param(
            "send", _make_transaction(to=ADDRESS_B, gas=21000), False, id="missing_from"
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, gas=21000),
            True,
            id="valid_from_and_gas",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to=ADDRESS_B),
            False,
            id="missing_gas",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to=ADDRESS_B, gas=21000),
            True,
            id="valid_complete_transaction",
        ),
        pytest.param(
            "send",
            _make_transaction(_from="", to=ADDRESS_B, gas=21000),
            False,
            id="empty_from",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000),
            True,
            id="empty_to_string",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to=b"", gas=21000),
            False,
            id="empty_to_bytes",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=decode_hex(ADDRESS_A), to=ADDRESS_B, gas=21000),
            False,
            id="from_as_bytes",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to=decode_hex(ADDRESS_B), gas=21000),
            False,
            id="to_as_bytes",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x0"),
            True,
            id="valid_type_0x0",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x1"),
            True,
            id="valid_type_0x1",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x01"),
            True,
            id="valid_type_0x01",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x2"),
            True,
            id="valid_type_0x2",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x02"),
            True,
            id="valid_type_0x02",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type=1),
            True,
            id="valid_type_int_1",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x4"),
            False,
            id="invalid_type_0x4",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="1"),
            False,
            id="invalid_type_string_1",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="x1"),
            False,
            id="invalid_type_x1",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, value=0),
            True,
            id="valid_zero_value",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, value=-1),
            False,
            id="invalid_negative_value",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, data=""),
            True,
            id="valid_empty_data",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, data="0x"),
            True,
            id="valid_0x_data",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, data="0x0"),
            False,
            id="invalid_odd_length_data",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=0),
            True,
            id="valid_zero_nonce",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=1),
            True,
            id="valid_positive_nonce",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=-1),
            False,
            id="invalid_negative_nonce",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce="0x1"),
            False,
            id="invalid_hex_nonce",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce="arst"),
            False,
            id="invalid_string_nonce",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=True),
            False,
            id="invalid_bool_nonce",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=1.0),
            False,
            id="invalid_float_nonce",
        ),
        pytest.param(
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=-1),
            False,
            id="invalid_negative_nonce_2",
        ),
        pytest.param(
            "send_signed",
            _make_transaction(_from=ADDRESS_A, gas=21000),
            False,
            id="signed_missing_signature",
        ),
        pytest.param(
            "send_signed",
            _make_transaction(_from=ADDRESS_A, gas=21000, r=1, s=1, v=1),
            True,
            id="valid_signed_transaction",
        ),
        pytest.param(
            "send_signed",
            _make_transaction(_from=ADDRESS_A, gas=21000, r=1, s=1, v=256),
            False,
            id="invalid_v_value",
        ),
        pytest.param(
            "send_signed",
            _make_transaction(
                _from=ADDRESS_A,
                gas=21000,
                max_fee_per_gas=1000000000,
                max_priority_fee_per_gas=1000000000,
                r=1,
                s=1,
                v=1,
            ),
            True,
            id="valid_signed_eip1559_transaction",
        ),
        pytest.param(  # access list txn
            "send",
            _make_transaction(
                _from=ADDRESS_A,
                to="",
                gas=21000,
                gas_price=10000,
                # properly formatted access list
                access_list=(
                    {
                        "address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                        "storage_keys": (
                            "0x0000000000000000000000000000000000000000000000000000000000000003",  # noqa: E501
                            "0x0000000000000000000000000000000000000000000000000000000000000007",  # noqa: E501
                        ),
                    },
                    {
                        "address": "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
                        "storage_keys": (),
                    },
                ),
            ),
            True,
            id="valid_access_list_transaction",
        ),
        pytest.param(
            "send",
            _make_transaction(
                _from=ADDRESS_A,
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
            False,
            id="invalid_access_list_storage_key",
        ),
        pytest.param(
            "send",
            _make_transaction(
                _from=ADDRESS_A,
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
            False,
            id="invalid_access_list_address",
        ),
        pytest.param(  # dynamic fee txn
            "send",
            _make_transaction(
                _from=ADDRESS_A,
                to="",
                gas=21000,
                max_fee_per_gas=1000000000,
                max_priority_fee_per_gas=1000000000,
                # properly formatted access list
                access_list=(
                    {
                        "address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                        "storage_keys": (
                            "0x0000000000000000000000000000000000000000000000000000000000000003",  # noqa: E501
                            "0x0000000000000000000000000000000000000000000000000000000000000007",  # noqa: E501
                        ),
                    },
                    {
                        "address": "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
                        "storage_keys": (),
                    },
                ),
            ),
            True,
            id="valid_dynamic_fee_transaction",
        ),
        # Cancun
        # `eth_sendTransaction` does not support blob transactions:
        pytest.param(
            "send",
            _make_transaction(blob_versioned_hashes=[]),
            False,
            id="invalid_empty_blob_hashes",
        ),
        pytest.param(
            "send",
            _make_transaction(blob_versioned_hashes=[b""]),
            False,
            id="invalid_empty_bytes_blob_hash",
        ),
        pytest.param(
            "send",
            _make_transaction(blob_versioned_hashes=[b"0x"]),
            False,
            id="invalid_0x_bytes_blob_hash",
        ),
        pytest.param(
            "send",
            _make_transaction(max_fee_per_blob_gas=0),
            False,
            id="invalid_zero_max_fee_per_blob_gas",
        ),
        pytest.param(
            "send",
            _make_transaction(max_fee_per_blob_gas=1),
            False,
            id="invalid_positive_max_fee_per_blob_gas",
        ),
        pytest.param(
            "send",
            _make_transaction(max_fee_per_blob_gas="0x0"),
            False,
            id="invalid_hex_max_fee_per_blob_gas",
        ),
    ),
)
def test_transaction_input_validation(
    validator: DefaultValidator,
    txn_internal_type: str,
    transaction: Dict[str, Any],
    is_valid: bool,
) -> None:
    if is_valid:
        validator.validate_inbound_transaction(transaction, txn_internal_type)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_transaction(transaction, txn_internal_type)


@pytest.mark.parametrize(
    "transaction,is_valid",
    (
        pytest.param({}, False, id="empty_transaction"),
        pytest.param(_make_transaction(to=ADDRESS_B), False, id="missing_from"),
        pytest.param(_make_transaction(gas=21000), False, id="only_gas"),
        pytest.param(_make_transaction(_from=ADDRESS_A), True, id="only_from"),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, nonce=1), True, id="from_and_nonce"
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, gas=21000), True, id="from_and_gas"
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, gas=True), False, id="invalid_gas_type"
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to=ADDRESS_B), True, id="from_and_to"
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to=ADDRESS_B, gas=21000),
            True,
            id="complete_transaction",
        ),
        pytest.param(_make_transaction(_from=""), False, id="empty_from_string"),
        pytest.param(
            _make_transaction(_from="", to=ADDRESS_B), False, id="empty_from_with_to"
        ),
        pytest.param(
            _make_transaction(_from="", gas=21000), False, id="empty_from_with_gas"
        ),
        pytest.param(
            _make_transaction(_from="", to=ADDRESS_B, gas=21000),
            False,
            id="empty_from_complete",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", gas=21000),
            True,
            id="empty_to_with_gas",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to=""), True, id="empty_to_string"
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to=b""), False, id="empty_to_bytes"
        ),
        pytest.param(
            _make_transaction(_from=decode_hex(ADDRESS_A), to=ADDRESS_B, gas=21000),
            False,
            id="from_as_bytes_with_gas",
        ),
        pytest.param(
            _make_transaction(_from=decode_hex(ADDRESS_A), to=ADDRESS_B),
            False,
            id="from_as_bytes",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to=decode_hex(ADDRESS_B), gas=21000),
            False,
            id="to_as_bytes_with_gas",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to=decode_hex(ADDRESS_B)),
            False,
            id="to_as_bytes",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", value=0), True, id="zero_value"
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", value=-1),
            False,
            id="negative_value",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", data=""),
            True,
            id="empty_data_string",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", data=b""),
            False,
            id="empty_data_bytes",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", data="0x"),
            True,
            id="0x_data_string",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", data=b"0x"),
            False,
            id="0x_data_bytes",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", data="0x0"),
            False,
            id="invalid_odd_length_data",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, value=0),
            True,
            id="valid_with_zero_value",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, value=-1),
            False,
            id="invalid_with_negative_value",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, data=""),
            True,
            id="valid_with_empty_data",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, data="0x"),
            True,
            id="valid_with_0x_data",
        ),
        pytest.param(
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, data="0x0"),
            False,
            id="invalid_with_odd_length_data",
        ),
    ),
)
def test_transaction_call_and_estimate_gas_input_validation(
    validator: DefaultValidator,
    transaction: Dict[str, Any],
    is_valid: bool,
) -> None:
    if is_valid:
        validator.validate_inbound_transaction(transaction, txn_internal_type="call")
        validator.validate_inbound_transaction(
            transaction, txn_internal_type="estimate"
        )
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_transaction(
                transaction, txn_internal_type="call"
            )
            validator.validate_inbound_transaction(
                transaction, txn_internal_type="estimate"
            )


@pytest.mark.parametrize(
    "withdrawals,is_valid",
    (
        pytest.param(
            # valid cases all together
            [
                {
                    "index": 0,
                    "validator_index": 0,
                    "address": b"\x00" * 20,  # bytes address
                    "amount": 0,
                },
                {
                    # limit case for uint64 fields
                    "index": 2**64 - 1,
                    "validator_index": 2**64 - 1,
                    "address": b"\x22" * 20,
                    "amount": 2**64 - 1,
                },
                {
                    "index": 0,
                    "validator_index": 0,
                    "address": f"0x{'22' * 20}",  # hexstr address
                    "amount": 0,
                },
            ],
            True,
            id="valid_mixed_withdrawals",
        ),
        pytest.param({}, False, id="invalid_dict_instead_of_list"),
        pytest.param(
            {"index": 0, "validator_index": 0, "address": b"\x00" * 20, "amount": 0},
            False,
            id="invalid_single_dict",
        ),
        pytest.param([{}], False, id="invalid_empty_dict_in_list"),
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
            False,
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
            False,
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
            False,
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
            False,
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
            False,
            id="invalid_address_bytes_too_long",
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
            False,
            id="invalid_hex_address_too_short",
        ),
    ),
)
def test_apply_withdrawals_inbound_dict_validation(
    withdrawals: Any, is_valid: bool
) -> None:
    if not is_valid:
        with pytest.raises(ValidationError):
            validate_inbound_withdrawals(withdrawals)

    else:
        validate_inbound_withdrawals(withdrawals)


@pytest.mark.parametrize(
    "value,is_valid",
    (
        pytest.param("0x0", True, id="valid_0x0"),
        pytest.param("0x1", True, id="valid_0x1"),
        pytest.param("0x22", True, id="valid_0x22"),
        pytest.param("0x4d2", True, id="valid_0x4d2"),
        pytest.param(0, False, id="invalid_int_zero"),
        pytest.param(1, False, id="invalid_int_one"),
        pytest.param(-1, False, id="invalid_negative_int"),
        pytest.param("1", False, id="invalid_string_1"),
        pytest.param("-0x1", False, id="invalid_negative_hex"),
        pytest.param("test", False, id="invalid_string"),
        pytest.param(b"test", False, id="invalid_bytes"),
    ),
)
def test_validate_inbound_storage_slot(value: Any, is_valid: bool) -> None:
    if not is_valid:
        with pytest.raises(
            ValidationError,
            match=(
                "Storage slot must be a hex string representation of a positive "
                f"integer - slot: {value}"
            ),
        ):
            DefaultValidator.validate_inbound_storage_slot(value)
    else:
        DefaultValidator.validate_inbound_storage_slot(value)


@pytest.mark.parametrize(
    "value,is_valid",
    (
        pytest.param(hex(2**256 - 1), True, id="valid_at_max_limit"),
        pytest.param(hex(2**256), False, id="invalid_exceeds_max_limit"),
    ),
)
def test_validate_inbound_storage_slot_integer_value_at_limit(
    value: Any, is_valid: bool
) -> None:
    if not is_valid:
        with pytest.raises(
            ValidationError,
            match="Value exceeds maximum 256 bit integer size",
        ):
            DefaultValidator.validate_inbound_storage_slot(value)
    else:
        DefaultValidator.validate_inbound_storage_slot(value)


@pytest.mark.parametrize(
    "timestamp,is_valid",
    (
        (4000001, True),
        (4000010, True),
        ("4000001", False),
        ("4000010", False),
        (4000001.0, False),
        (4000010.0, False),
        (True, False),
        (False, False),
    ),
)
def test_time_travel_input_timestamp_validation(
    validator: DefaultValidator, timestamp: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_inbound_timestamp(timestamp)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_timestamp(timestamp)


@pytest.mark.parametrize(
    "txn_hash,is_valid",
    (
        pytest.param(f"0x{'01' * 32}", True, id="valid_hex_txn_hash"),
        pytest.param(f"{'01' * 32}", True, id="valid_string_txn_hash"),
        pytest.param(f"0x{'01' * 20}", False, id="invalid_20_byte_hex_txn_hash"),
        pytest.param(b"\x01" * 32, False, id="invalid_32_byte_txn_hash"),
        pytest.param(None, False, id="none_txn_hash"),
    ),
)
def test_inbound_txn_hash_validation(
    validator: DefaultValidator, txn_hash: Any, is_valid: bool
) -> None:
    if is_valid:
        validator.validate_inbound_transaction_hash(txn_hash)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_transaction_hash(txn_hash)
