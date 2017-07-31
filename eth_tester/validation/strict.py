from __future__ import unicode_literals

from eth_utils import (
    is_boolean,
    is_integer,
    is_string,
    is_hex,
    is_text,
    remove_0x_prefix,
)

from eth_tester.constants import (
    BLOCK_NUMBER_META_VALUES,
)
from eth_tester.exceptions import (
    ValidationError,
)

from .base import BaseValidationBackend


MAX_TIMESTAMP = 33040162800  # January 1st 3017 is appropriately far in the future.


def validate_timestamp(value):
    if not is_integer(value) or is_boolean(value):
        raise ValidationError(
            "Timestamp values must be integers.  Got: {0}".format(type(value))
        )
    if value < 0:
        raise ValidationError(
            "Timestamp values must be positive integers.  Got: {0}".format(value)
        )
    elif value >= MAX_TIMESTAMP:
        raise ValidationError(
            "Timestamp values must be less than {0}.  Got {1}".format(
                MAX_TIMESTAMP,
                value,
            )
        )


def validate_block_number(value):
    error_message = (
        "Block number must be a positive integer or one of the strings "
        "'latest', 'earliest', or 'pending'.  Got: {0}".format(value)
    )
    if is_string(value):
        if value not in BLOCK_NUMBER_META_VALUES:
            raise ValidationError(error_message)
    elif not is_integer(value) or is_boolean(value):
        raise ValidationError(error_message)
    elif value < 0:
        raise ValidationError(error_message)


def validate_32_byte_hex_value(value):
    error_message = (
        "Block hash must be a hexidecimal encoded 32 byte string.  Got: "
        "{0}".format(value)
    )
    if not is_text(value):
        raise ValidationError(error_message)
    elif not is_hex(value):
        raise ValidationError(error_message)
    elif len(remove_0x_prefix(value)) != 64:
        raise ValidationError(error_message)


validate_block_hash = validate_32_byte_hex_value
validate_transaction_hash = validate_32_byte_hex_value


class StrictValidationBackend(BaseValidationBackend):
    validate_timestamp = staticmethod(validate_timestamp)
    validate_block_number = staticmethod(validate_block_number)
    validate_block_hash = staticmethod(validate_32_byte_hex_value)
    validate_transaction_hash = staticmethod(validate_32_byte_hex_value)
