import binascii
from typing import (
    Dict,
    List,
    Union,
)

from eth_typing import (
    HexStr,
)
from eth_utils import (
    decode_hex,
    is_boolean,
    is_bytes,
    is_checksum_address,
    is_checksum_formatted_address,
    is_dict,
    is_hex,
    is_hex_address,
    is_hexstr,
    is_integer,
    is_list_like,
    is_string,
    is_text,
    remove_0x_prefix,
)
from eth_utils.toolz import (
    partial,
)

from eth_tester.constants import (
    BLOB_TRANSACTION_PARAMS,
    BLOCK_NUMBER_META_VALUES,
)
from eth_tester.exceptions import (
    ValidationError,
)

from .common import (
    validate_address,
    validate_dict,
    validate_positive_integer,
    validate_text,
    validate_transaction_type,
    validate_uint8,
    validate_uint64,
    validate_uint256,
)


def is_32_bytes(value):
    return is_bytes(value) and len(value) == 32


def is_32byte_hex_string(value):
    return is_text(value) and is_hex(value) and len(remove_0x_prefix(value)) == 64


def is_topic(value):
    return value is None or is_32byte_hex_string(value) or is_32_bytes(value)


def validate_32_byte_hex_value(value, name):
    error_message = (
        "{} must be a hexadecimal encoded 32 byte string.  Got: "
        "{}".format(name, value)
    )
    if not is_32byte_hex_string(value):
        raise ValidationError(error_message)


MAX_TIMESTAMP = 33040162800  # January 1st 3017 is appropriately far in the future.


def validate_timestamp(value):
    validate_positive_integer(value)

    if value >= MAX_TIMESTAMP:
        raise ValidationError(
            "Timestamp values must be less than {}.  Got {}".format(
                MAX_TIMESTAMP,
                value,
            )
        )


def validate_block_number(value):
    error_message = (
        "Block number must be a positive integer or one of the strings "
        "'latest', 'earliest', or 'pending'.  Got: {}".format(value)
    )
    if is_string(value):
        validate_text(value)
        if value not in BLOCK_NUMBER_META_VALUES:
            raise ValidationError(error_message)
    elif not is_integer(value) or is_boolean(value):
        raise ValidationError(error_message)
    elif value < 0:
        raise ValidationError(error_message)


validate_block_hash = partial(validate_32_byte_hex_value, name="Block hash")
validate_transaction_hash = partial(validate_32_byte_hex_value, name="Transaction hash")
validate_filter_id = partial(validate_positive_integer)


def validate_account(value):
    if not is_text(value) or not is_hex_address(value):
        raise ValidationError(
            f"Address must be 20 bytes encoded as hexadecimal - address: {value}"
        )
    elif is_checksum_formatted_address(value) and not is_checksum_address(value):
        raise ValidationError("Address does not validate EIP55 checksum")


def validate_inbound_storage_slot(value):
    error_msg = (
        "Storage slot must be a hex string representation of a positive integer - "
        f"slot: {value}"
    )
    if not (is_hexstr(value) and value.startswith("0x")):
        raise ValidationError(error_msg)

    try:
        int_val = int(value, 16)
    except ValueError:
        raise ValidationError(error_msg)

    validate_uint256(int_val)


def is_valid_topic_array(value):
    if not is_list_like(value):
        return False
    return all(
        is_valid_topic_array(item) if is_list_like(item) else is_topic(item)
        for item in value
    )


def validate_filter_params(from_block, to_block, address, topics):
    # blocks
    if from_block is not None:
        validate_block_number(from_block)
    if to_block is not None:
        validate_block_number(to_block)

    # address
    if address is None:
        pass
    elif is_list_like(address):
        if not address:
            raise ValidationError(
                "Address must be either a single hexadecimal encoded address or "
                "a non-empty list of hexadecimal encoded addresses"
            )
        for sub_address in address:
            validate_account(sub_address)
    elif not is_hex_address(address):
        validate_account(address)

    invalid_topics_message = (
        "Topics must be one of `None` or an array of topics. Each topic must be 32 "
        "bytes, represented as a bytestring or its hex string equivalent. A "
        'filter query of topics using "OR" can be achieved using a sub-array of '
        "topics. See https://eth.wiki/json-rpc/API#eth_newfilter for more details."
    )
    # topics
    if topics is None:
        pass
    elif not is_list_like(topics):
        raise ValidationError(invalid_topics_message)
    elif is_valid_topic_array(topics):
        return True
    else:
        raise ValidationError(invalid_topics_message)


def validate_private_key(value):
    if (
        not is_text(value)
        or not is_hex(value)
        or not len(remove_0x_prefix(value)) == 64
    ):
        raise ValidationError("Private keys must be 32 bytes encoded as hexadecimal")


TRANSACTION_KEYS = {
    "type",
    "chain_id",
    "from",
    "to",
    "gas",
    "gas_price",
    "max_fee_per_gas",
    "max_priority_fee_per_gas",
    "value",
    "data",
    "access_list",
    "nonce",
}

SIGNED_TRANSACTION_KEYS = {
    "r",
    "s",
    "v",
}

TRANSACTION_INTERNAL_TYPE_INFO = {
    "send": TRANSACTION_KEYS,
    "send_signed": TRANSACTION_KEYS.union(SIGNED_TRANSACTION_KEYS),
    "call": TRANSACTION_KEYS,
    "estimate": TRANSACTION_KEYS,
}

ALLOWED_TRANSACTION_INTERNAL_TYPES = set(TRANSACTION_INTERNAL_TYPE_INFO.keys())


def validate_transaction(value, txn_internal_type):
    if txn_internal_type not in ALLOWED_TRANSACTION_INTERNAL_TYPES:
        raise TypeError(
            "the `txn_internal_type` parameter must be one of send/call/estimate"
        )
    if not is_dict(value):
        raise ValidationError(f"Transaction must be a dictionary. Got: {type(value)}")

    unknown_keys = tuple(
        sorted(
            set(value.keys()).difference(
                TRANSACTION_INTERNAL_TYPE_INFO[txn_internal_type],
            )
        )
    )
    if unknown_keys:
        if any(k in value for k in BLOB_TRANSACTION_PARAMS):
            raise ValidationError(
                "Transaction contains blob-specific parameters. Blob transactions are "
                "only supported via `eth_sendRawTransaction`, rlp encoding the blob "
                "sidecar data along with the transaction as per the EIP-4844 "
                "`PooledTransaction` model."
            )
        raise ValidationError(
            "Only the keys '{}' are allowed.  Got extra keys: '{}'".format(
                "/".join(
                    tuple(sorted(TRANSACTION_INTERNAL_TYPE_INFO[txn_internal_type]))
                ),
                "/".join(unknown_keys),
            )
        )

    if txn_internal_type == "send":
        required_keys = {"from", "gas"}
    elif txn_internal_type == "send_signed":
        required_keys = {"from", "gas"} | SIGNED_TRANSACTION_KEYS
    elif txn_internal_type in {"estimate", "call"}:
        required_keys = {"from"}
    else:
        raise Exception("Invariant: code path should be unreachable")

    missing_required_keys = tuple(sorted(required_keys.difference(value.keys())))
    if missing_required_keys:
        raise ValidationError(
            "Transaction is missing the required keys: '{}'".format(
                "/".join(missing_required_keys),
            )
        )

    if "type" in value:
        # type is validated but not required. If this value exists, it will be popped
        # out of the dict and the type will instead be inferred from the
        # transaction params.
        validate_transaction_type(value["type"])

    if "from" in value:
        validate_account(value["from"])

    if "to" in value and value["to"] != "":
        validate_account(value["to"])
    elif "to" in value and value["to"] == "":
        validate_text(value["to"])

    if "gas" in value:
        validate_uint256(value["gas"])

    if "gas_price" in value:
        validate_uint256(value["gas_price"])

    if "max_fee_per_gas" in value:
        validate_uint256(value["max_fee_per_gas"])
        if "gas_price" in value:
            raise ValidationError("Mixed legacy and dynamic fee transaction values")

    if "max_priority_fee_per_gas" in value:
        validate_uint256(value["max_priority_fee_per_gas"])
        if "gas_price" in value:
            raise ValidationError("Mixed legacy and dynamic fee transaction values")

    if "value" in value:
        validate_uint256(value["value"])

    if "nonce" in value:
        validate_uint256(value["nonce"])

    if "data" in value:
        bad_data_message = (
            "Transaction 'data' must be a hexadecimal encoded string.  Got: "
            "{}".format(value["data"])
        )
        if not is_text(value["data"]):
            raise ValidationError(bad_data_message)
        elif not remove_0x_prefix(value["data"]):
            pass
        elif not is_hex(value["data"]):
            raise ValidationError(bad_data_message)
        try:
            decode_hex(value["data"])
        except (binascii.Error, TypeError):
            # TypeError is for python2
            # binascii.Error is for python3
            raise ValidationError(bad_data_message)

    if "access_list" in value:
        _validate_inbound_access_list(value["access_list"])

    if txn_internal_type == "send_signed":
        validate_uint256(value["r"])
        validate_uint256(value["s"])
        validate_uint8(value["v"])


def _validate_inbound_access_list(access_list):
    """
    Validates the structure of an inbound access list. This is similar to the JSON-RPC
    structure for an access list only with `under_score` keys rather than `camelCase`.

    >>> _access_list = (
    ...     {
    ...         'address': '0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae',
    ...         'storage_keys': (
    ...             '0x0000000000000000000000000000000000000000000000000000000000000003',  # noqa: E501
    ...             '0x0000000000000000000000000000000000000000000000000000000000000007',  # noqa: E501
    ...         )
    ...     },
    ...     {
    ...         'address': '0xbb9bc244d798123fde783fcc1c72d3bb8c189413',
    ...         'storage_keys': ()
    ...     },
    ... )
    """
    if not is_list_like(access_list):
        raise ValidationError("access_list is not list-like")
    for entry in access_list:
        if not is_dict(entry) and len(entry) != 2:
            raise ValidationError(f"access_list entry not properly formatted: {entry}")
        address = entry.get("address")
        storage_keys = entry.get("storage_keys")
        if not is_hex_address(address):
            raise ValidationError(
                f"access_list address must be a hexadecimal address: {address}"
            )
        if not is_list_like(storage_keys):
            raise ValidationError(
                f"access_list storage keys are not list-like: {storage_keys}"
            )
        if len(storage_keys) > 0 and not all(
            is_32byte_hex_string(k) for k in storage_keys
        ):
            raise ValidationError(
                "one or more access list storage keys not formatted "
                f"properly: {storage_keys}"
            )


def validate_raw_transaction(raw_transaction):
    if not is_text(raw_transaction) or not is_hex(raw_transaction):
        raise ValidationError(
            "Raw Transaction must be a hexadecimal encoded string.  Got: "
            "{}".format(raw_transaction)
        )


INBOUND_WITHDRAWAL_VALIDATORS = {
    "index": validate_uint64,
    "validator_index": validate_uint64,
    "address": validate_address,
    "amount": validate_uint64,
}


def validate_inbound_withdrawals(
    withdrawals_list: List[Dict[str, Union[int, str, HexStr, bytes]]],
):
    if len(withdrawals_list) == 0:
        raise ValidationError("Withdrawals list must not be empty.")

    for withdrawal_dict in withdrawals_list:
        validate_dict(withdrawal_dict, key_validators=INBOUND_WITHDRAWAL_VALIDATORS)
