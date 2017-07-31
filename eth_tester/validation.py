from eth_utils import (
    is_boolean,
    is_integer,
    is_hex,
)

from eth_tester.exceptions import (
    ValidationError,
)


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
    raise NotImplementedError("not implemented")
