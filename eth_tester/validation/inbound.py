from __future__ import unicode_literals

import binascii

from eth_utils import (
    is_boolean,
    is_checksum_address,
    is_checksum_formatted_address,
    is_dict,
    is_hex,
    is_hex_address,
    is_integer,
    is_list_like,
    is_string,
    is_text,
    remove_0x_prefix,
    decode_hex,
)

from eth_utils.toolz import (
    partial,
)

from eth_tester.constants import (
    BLOCK_NUMBER_META_VALUES,
)
from eth_tester.exceptions import (
    ValidationError,
)

from .common import (
    validate_positive_integer,
    validate_uint256,
    validate_uint8,
    validate_text,
)


def is_32byte_hex_string(value):
    return is_text(value) and is_hex(value) and len(remove_0x_prefix(value)) == 64


def is_topic(value):
    return value is None or is_32byte_hex_string(value)


def validate_32_byte_hex_value(value, name):
    error_message = (
        "{} must be a hexidecimal encoded 32 byte string.  Got: "
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
    if not is_text(value):
        raise ValidationError("Address must be 20 bytes encoded as hexidecimal")
    elif not is_hex_address(value):
        raise ValidationError("Address must be 20 bytes encoded as hexidecimal")
    elif is_checksum_formatted_address(value) and not is_checksum_address(value):
        raise ValidationError("Address does not validate EIP55 checksum")


def is_valid_topic_array(value):
    if not is_list_like(value):
        return False
    return all(
        is_valid_topic_array(item) if is_list_like(item) else is_topic(item)
        for item in value)


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
                "Address must be either a single hexidecimal encoded address or "
                "a non-empty list of hexidecimal encoded addresses"
            )
        for sub_address in address:
            validate_account(sub_address)
    elif not is_hex_address(address):
        validate_account(address)

    invalid_topics_message = (
        "Topics must be one of `None`, an array of 32 byte hexidecimal encoded "
        "strings, or an array of arrays of 32 byte hexidecimal strings"
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
    if not is_text(value) or not is_hex(value) or not len(remove_0x_prefix(value)) == 64:
        raise ValidationError("Private keys must be 32 bytes encoded as hexidecimal")


TRANSACTION_KEYS = {
    'from',
    'to',
    'gas',
    'gas_price',
    'value',
    'data',
    'nonce',
}

SIGNED_TRANSACTION_KEYS = {
    'r',
    's',
    'v',
}

TRANSACTION_TYPE_INFO = {
    'send': TRANSACTION_KEYS,
    'send_signed': TRANSACTION_KEYS.union(SIGNED_TRANSACTION_KEYS),
    'call': TRANSACTION_KEYS.difference({'nonce'}),
    'estimate': TRANSACTION_KEYS.difference({'nonce'}),
}

ALLOWED_TRANSACTION_TYPES = set(TRANSACTION_TYPE_INFO.keys())


def validate_transaction(value, txn_type):
    if txn_type not in ALLOWED_TRANSACTION_TYPES:
        raise TypeError("the `txn_type` parameter must be one of send/call/estimate")
    if not is_dict(value):
        raise ValidationError("Transaction must be a dictionary.  Got: {}".format(type(value)))

    unknown_keys = tuple(sorted(set(value.keys()).difference(
        TRANSACTION_TYPE_INFO[txn_type],
    )))
    if unknown_keys:
        raise ValidationError(
            "Only the keys '{}' are allowed.  Got extra keys: '{}'".format(
                "/".join(tuple(sorted(TRANSACTION_TYPE_INFO[txn_type]))),
                "/".join(unknown_keys),
            )
        )

    if txn_type == 'send':
        required_keys = {'from', 'gas'}
    elif txn_type == 'send_signed':
        required_keys = {'from', 'gas'} | SIGNED_TRANSACTION_KEYS
    elif txn_type in {'estimate', 'call'}:
        required_keys = {'from'}
    else:
        raise Exception("Invariant: code path should be unreachable")

    missing_required_keys = tuple(sorted(required_keys.difference(value.keys())))
    if missing_required_keys:
        raise ValidationError(
            "Transaction is missing the required keys: '{}'".format(
                "/".join(missing_required_keys),
            )
        )

    if 'from' in value:
        validate_account(value['from'])

    if 'to' in value and value['to'] != '':
        validate_account(value['to'])
    elif 'to' in value and value['to'] == '':
        validate_text(value['to'])

    if 'gas' in value:
        validate_uint256(value['gas'])

    if 'gas_price' in value:
        validate_uint256(value['gas_price'])

    if 'value' in value:
        validate_uint256(value['value'])

    if 'nonce' in value:
        validate_uint256(value['nonce'])

    if 'data' in value:
        bad_data_message = (
            "Transaction data must be a hexidecimal encoded string.  Got: "
            "{}".format(value['data'])
        )
        if not is_text(value['data']):
            raise ValidationError(bad_data_message)
        elif not remove_0x_prefix(value['data']):
            pass
        elif not is_hex(value['data']):
            raise ValidationError(bad_data_message)
        try:
            decode_hex(value['data'])
        except (binascii.Error, TypeError):
            # TypeError is for python2
            # binascii.Error is for python3
            raise ValidationError(bad_data_message)

    if txn_type == 'send_signed':
        validate_uint256(value['r'])
        validate_uint256(value['s'])
        validate_uint8(value['v'])


def validate_raw_transaction(raw_transaction):
    if not is_text(raw_transaction) or not is_hex(raw_transaction):
        raise ValidationError(
            "Raw Transaction must be a hexidecimal encoded string.  Got: "
            "{}".format(raw_transaction)
        )
