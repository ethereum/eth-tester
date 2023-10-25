from __future__ import (
    unicode_literals,
)

import pytest

from eth_tester.validation.inbound import (
    validate_inbound_withdrawals,
)

try:
    pass
except ImportError:
    pass

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


@pytest.fixture
def validator():
    _validator = DefaultValidator()
    return _validator


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
def test_time_travel_input_timestamp_validation(validator, timestamp, is_valid):
    if is_valid:
        validator.validate_inbound_timestamp(timestamp)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_timestamp(timestamp)


@pytest.mark.parametrize(
    "block_number,is_valid",
    (
        (0, True),
        (1, True),
        (-1, False),
        (False, False),
        (True, False),
        ("latest", True),
        ("pending", True),
        ("earliest", True),
        ("safe", True),
        ("finalized", True),
        (2**256, True),
        (b"latest", False),
        (b"pending", False),
        (b"earliest", False),
        (b"safe", False),
        (b"finalized", False),
    ),
)
def test_block_number_input_validation(validator, block_number, is_valid):
    if is_valid:
        validator.validate_inbound_block_number(block_number)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_block_number(block_number)


@pytest.mark.parametrize(
    "block_hash,is_valid",
    (
        (0, False),
        (1, False),
        (-1, False),
        (False, False),
        (True, False),
        (b"", False),
        ("", False),
        ("0" * 32, False),
        ("0x" + "0" * 32, False),
        ("\x00" * 32, False),
        (b"\x00" * 32, False),
        ("0" * 64, True),
        ("0x" + "0" * 64, True),
        (b"0x" + b"0" * 64, False),
    ),
)
def test_block_hash_input_validation(validator, block_hash, is_valid):
    if is_valid:
        validator.validate_inbound_block_hash(block_hash)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_block_hash(block_hash)


def _make_filter_params(from_block=None, to_block=None, address=None, topics=None):
    return {
        "from_block": from_block,
        "to_block": to_block,
        "address": address,
        "topics": topics,
    }


@pytest.mark.parametrize(
    "filter_id,is_valid",
    (
        (-1, False),
        (0, True),
        (1, True),
        ("0x0", False),
        ("0x00", False),
        ("0x1", False),
        ("0x01", False),
        ("0", False),
        ("1", False),
    ),
)
def test_filter_id_input_validation(validator, filter_id, is_valid):
    if is_valid:
        validator.validate_inbound_filter_id(filter_id)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_filter_id(filter_id)


ADDRESS_A = encode_hex(b"\x00" * 19 + b"\x01")
ADDRESS_B = encode_hex(b"\x00" * 19 + b"\x02")
TOPIC_A = encode_hex(b"\x00" * 31 + b"\x01")
TOPIC_B = encode_hex(b"\x00" * 31 + b"\x02")
TOPIC_C = encode_hex(b"\x00" * 30 + b"\x01")
TOPIC_D = encode_hex(b"\x00" * 32 + b"\x01")


def _yield_key_value_if_value_not_none(key, value):
    if value is not None:
        yield key, value


@pytest.mark.parametrize(
    "filter_params,is_valid",
    (
        (_make_filter_params(), True),
        (_make_filter_params(from_block=0), True),
        (_make_filter_params(to_block=0), True),
        (_make_filter_params(from_block=-1), False),
        (_make_filter_params(to_block=-1), False),
        (_make_filter_params(from_block=True), False),
        (_make_filter_params(to_block=False), False),
        (_make_filter_params(from_block="0x0"), False),
        (_make_filter_params(to_block="0x0"), False),
        (_make_filter_params(from_block="0x1"), False),
        (_make_filter_params(to_block="0x1"), False),
        (_make_filter_params(address=ADDRESS_A), True),
        (_make_filter_params(address=decode_hex(ADDRESS_A)), False),
        (_make_filter_params(address=[ADDRESS_A, ADDRESS_B]), True),
        (_make_filter_params(address=TOPIC_A), False),
        (_make_filter_params(address=decode_hex(TOPIC_A)), False),
        (_make_filter_params(address=[TOPIC_A, ADDRESS_B]), False),
        (_make_filter_params(topics=[TOPIC_A]), True),
        (_make_filter_params(topics=[TOPIC_A, TOPIC_B]), True),
        (_make_filter_params(topics=[TOPIC_A, None]), True),
        (_make_filter_params(topics=[[TOPIC_A], [TOPIC_B]]), True),
        (_make_filter_params(topics=[TOPIC_A, [TOPIC_B, TOPIC_A]]), True),
        (_make_filter_params(topics=[[TOPIC_A], [TOPIC_B, None]]), True),
        (_make_filter_params(topics=[decode_hex(TOPIC_A)]), True),
        (_make_filter_params(topics=[decode_hex(TOPIC_A), decode_hex(TOPIC_B)]), True),
        (_make_filter_params(topics=[decode_hex(TOPIC_A), None]), True),
        (
            _make_filter_params(topics=[[decode_hex(TOPIC_A)], [decode_hex(TOPIC_B)]]),
            True,
        ),
        (
            _make_filter_params(
                topics=[decode_hex(TOPIC_A), [decode_hex(TOPIC_B), decode_hex(TOPIC_A)]]
            ),
            True,
        ),
        (
            _make_filter_params(
                topics=[[decode_hex(TOPIC_A)], [decode_hex(TOPIC_B), None]]
            ),
            True,
        ),
        (_make_filter_params(topics=[decode_hex(TOPIC_C)]), False),
        (_make_filter_params(topics=[decode_hex(TOPIC_D)]), False),
        (_make_filter_params(topics=[ADDRESS_A]), False),
        (_make_filter_params(topics=[ADDRESS_A, TOPIC_B]), False),
        (_make_filter_params(topics=[[ADDRESS_A], [TOPIC_B]]), False),
    ),
)
def test_filter_params_input_validation(validator, filter_params, is_valid):
    if is_valid:
        validator.validate_inbound_filter_params(**filter_params)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_filter_params(**filter_params)


@to_dict
def _make_transaction(
    chain_id=None,
    _type=None,
    _from=None,
    to=None,
    gas=None,
    gas_price=None,
    max_fee_per_gas=None,
    max_priority_fee_per_gas=None,
    value=None,
    data=None,
    nonce=None,
    access_list=None,
    r=None,
    s=None,
    v=None,
):
    yield from _yield_key_value_if_value_not_none("type", _type)
    yield from _yield_key_value_if_value_not_none("chain_id", chain_id)
    yield from _yield_key_value_if_value_not_none("from", _from)
    yield from _yield_key_value_if_value_not_none("to", to)
    yield from _yield_key_value_if_value_not_none("gas", gas)
    yield from _yield_key_value_if_value_not_none("gas_price", gas_price)
    yield from _yield_key_value_if_value_not_none("max_fee_per_gas", max_fee_per_gas)
    yield from _yield_key_value_if_value_not_none(
        "max_priority_fee_per_gas", max_priority_fee_per_gas
    )
    yield from _yield_key_value_if_value_not_none("value", value)
    yield from _yield_key_value_if_value_not_none("data", data)
    yield from _yield_key_value_if_value_not_none("nonce", nonce)
    yield from _yield_key_value_if_value_not_none("access_list", access_list)
    yield from _yield_key_value_if_value_not_none("r", r)
    yield from _yield_key_value_if_value_not_none("s", s)
    yield from _yield_key_value_if_value_not_none("v", v)


@pytest.mark.parametrize(
    "txn_internal_type, transaction, is_valid",
    (
        ("send", {}, False),
        ("send", _make_transaction(to=ADDRESS_B, gas=21000), False),
        ("send", _make_transaction(_from=ADDRESS_A, gas=21000), True),
        ("send", _make_transaction(_from=ADDRESS_A, to=ADDRESS_B), False),
        ("send", _make_transaction(_from=ADDRESS_A, to=ADDRESS_B, gas=21000), True),
        ("send", _make_transaction(_from="", to=ADDRESS_B, gas=21000), False),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000), True),
        ("send", _make_transaction(_from=ADDRESS_A, to=b"", gas=21000), False),
        (
            "send",
            _make_transaction(_from=decode_hex(ADDRESS_A), to=ADDRESS_B, gas=21000),
            False,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to=decode_hex(ADDRESS_B), gas=21000),
            False,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x0"),
            True,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x1"),
            True,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x01"),
            True,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x2"),
            True,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x02"),
            True,
        ),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type=1), True),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="0x3"),
            False,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="1"),
            False,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, _type="x1"),
            False,
        ),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, value=0), True),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, value=-1), False),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, data=""), True),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, data="0x"), True),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, data="0x0"),
            False,
        ),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=0), True),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=1), True),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=-1), False),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce="0x1"),
            False,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce="arst"),
            False,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=True),
            False,
        ),
        (
            "send",
            _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=1.0),
            False,
        ),
        ("send", _make_transaction(_from=ADDRESS_A, to="", gas=21000, nonce=-1), False),
        ("send_signed", _make_transaction(_from=ADDRESS_A, gas=21000), False),
        (
            "send_signed",
            _make_transaction(_from=ADDRESS_A, gas=21000, r=1, s=1, v=1),
            True,
        ),
        (
            "send_signed",
            _make_transaction(_from=ADDRESS_A, gas=21000, r=1, s=1, v=256),
            False,
        ),
        (
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
        ),
        (  # access list txn
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
        ),
        (
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
        ),
        (
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
        ),
        (  # dynamic fee txn
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
        ),
    ),
)
def test_transaction_input_validation(
    validator, txn_internal_type, transaction, is_valid
):
    if is_valid:
        validator.validate_inbound_transaction(transaction, txn_internal_type)
    else:
        with pytest.raises(ValidationError):
            validator.validate_inbound_transaction(transaction, txn_internal_type)


@pytest.mark.parametrize(
    "transaction,is_valid",
    (
        ({}, False),
        (_make_transaction(to=ADDRESS_B), False),
        (_make_transaction(gas=21000), False),
        (_make_transaction(_from=ADDRESS_A), True),
        (_make_transaction(_from=ADDRESS_A, nonce=1), True),
        (_make_transaction(_from=ADDRESS_A, gas=21000), True),
        (_make_transaction(_from=ADDRESS_A, gas=True), False),
        (_make_transaction(_from=ADDRESS_A, to=ADDRESS_B), True),
        (_make_transaction(_from=ADDRESS_A, to=ADDRESS_B, gas=21000), True),
        (_make_transaction(_from=""), False),
        (_make_transaction(_from="", to=ADDRESS_B), False),
        (_make_transaction(_from="", gas=21000), False),
        (_make_transaction(_from="", to=ADDRESS_B, gas=21000), False),
        (_make_transaction(_from=ADDRESS_A, to="", gas=21000), True),
        (_make_transaction(_from=ADDRESS_A, to=""), True),
        (_make_transaction(_from=ADDRESS_A, to=b""), False),
        (
            _make_transaction(_from=decode_hex(ADDRESS_A), to=ADDRESS_B, gas=21000),
            False,
        ),
        (_make_transaction(_from=decode_hex(ADDRESS_A), to=ADDRESS_B), False),
        (
            _make_transaction(_from=ADDRESS_A, to=decode_hex(ADDRESS_B), gas=21000),
            False,
        ),
        (_make_transaction(_from=ADDRESS_A, to=decode_hex(ADDRESS_B)), False),
        (_make_transaction(_from=ADDRESS_A, to="", value=0), True),
        (_make_transaction(_from=ADDRESS_A, to="", value=-1), False),
        (_make_transaction(_from=ADDRESS_A, to="", data=""), True),
        (_make_transaction(_from=ADDRESS_A, to="", data=b""), False),
        (_make_transaction(_from=ADDRESS_A, to="", data="0x"), True),
        (_make_transaction(_from=ADDRESS_A, to="", data=b"0x"), False),
        (_make_transaction(_from=ADDRESS_A, to="", data="0x0"), False),
        (_make_transaction(_from=ADDRESS_A, to="", gas=21000, value=0), True),
        (_make_transaction(_from=ADDRESS_A, to="", gas=21000, value=-1), False),
        (_make_transaction(_from=ADDRESS_A, to="", gas=21000, data=""), True),
        (_make_transaction(_from=ADDRESS_A, to="", gas=21000, data="0x"), True),
        (_make_transaction(_from=ADDRESS_A, to="", gas=21000, data="0x0"), False),
    ),
)
def test_transaction_call_and_estimate_gas_input_validation(
    validator, transaction, is_valid
):
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
        (
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
        ),
        ({}, False),
        (
            {"index": 0, "validator_index": 0, "address": b"\x00" * 20, "amount": 0},
            False,
        ),
        ([{}], False),
        (
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
        ),
        (
            [
                {
                    "index": 2**64,  # out of range
                    "validator_index": 0,
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
            ],
            False,
        ),
        (
            [
                {
                    "index": 0,
                    "validator_index": 2**64,  # out of range
                    "address": b"\x00" * 20,
                    "amount": 0,
                },
            ],
            False,
        ),
        (
            [
                {
                    "index": 0,
                    "validator_index": 0,
                    "address": b"\x00" * 20,
                    "amount": 2**64,  # out of range
                },
            ],
            False,
        ),
        (
            [
                {
                    "index": 0,
                    "validator_index": 0,
                    "address": b"\x00" * 21,  # not 20 bytes
                    "amount": 0,
                },
            ],
            False,
        ),
        (
            [
                {
                    "index": 0,
                    "validator_index": 0,
                    "address": f"0x{'22' * 19}",  # not 20 bytes
                    "amount": 0,
                },
            ],
            False,
        ),
    ),
)
def test_apply_withdrawals_inbound_dict_validation(withdrawals, is_valid):
    if not is_valid:
        with pytest.raises(ValidationError):
            validate_inbound_withdrawals(withdrawals)

    else:
        validate_inbound_withdrawals(withdrawals)


@pytest.mark.parametrize(
    "value,is_valid",
    (
        ("0x0", True),
        ("0x1", True),
        ("0x22", True),
        ("0x4d2", True),
        (0, False),
        (1, False),
        (-1, False),
        ("1", False),
        ("-0x1", False),
        ("test", False),
        (b"test", False),
    ),
)
def test_validate_inbound_storage_slot(value, is_valid):
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
        (hex(2**256 - 1), True),
        (hex(2**256), False),
    ),
)
def test_validate_inbound_storage_slot_integer_value_at_limit(value, is_valid):
    if not is_valid:
        with pytest.raises(
            ValidationError,
            match="Value exceeds maximum 256 bit integer size",
        ):
            DefaultValidator.validate_inbound_storage_slot(value)
    else:
        DefaultValidator.validate_inbound_storage_slot(value)
