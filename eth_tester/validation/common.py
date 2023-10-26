from __future__ import (
    unicode_literals,
)

import functools
import math
from typing import (
    Union,
)

from eth_typing import (
    HexStr,
)
from eth_utils import (
    is_address,
    is_bytes,
    is_dict,
    is_hexstr,
    is_integer,
    is_list_like,
    is_text,
    to_dict,
    to_tuple,
)
from eth_utils.toolz import (
    curry,
)

from eth_tester.constants import (
    UINT8_MAX,
    UINT64_MAX,
    UINT256_MAX,
)
from eth_tester.exceptions import (
    ValidationError,
)


def validate_positive_integer(value):
    error_message = "Value must be a positive integer.  Got: {}".format(
        value,
    )
    if not is_integer(value):
        raise ValidationError(error_message)
    elif value < 0:
        raise ValidationError(error_message)


@curry
def validate_uint(max_val, value):
    validate_positive_integer(value)
    if value > max_val:
        bitsize = int(math.log2(max_val))
        raise ValidationError(
            f"Value exceeds maximum {bitsize:d} bit integer size:  {value}"
        )


validate_uint256 = validate_uint(UINT256_MAX)
validate_uint64 = validate_uint(UINT64_MAX)
validate_uint8 = validate_uint(UINT8_MAX)


def validate_bytes(value):
    if not is_bytes(value):
        raise ValidationError(
            "Value must be a byte string.  Got type: {}".format(type(value))
        )


def validate_text(value):
    if not is_text(value):
        raise ValidationError(
            "Value must be a text string.  Got type: {}".format(type(value))
        )


def validate_is_dict(value):
    if not is_dict(value):
        raise ValidationError(
            "Value must be a dictionary.  Got: {}".format(type(value))
        )


def validate_is_list_like(value):
    if not is_list_like(value):
        raise ValidationError(
            "Value must be a sequence type.  Got: {}".format(type(value))
        )


@to_tuple
def _accumulate_errors(value, validators):
    for idx, validator in enumerate(validators):
        try:
            validator(value)
        except ValidationError as err:
            yield idx, err


def validate_any(value, validators):
    errors = _accumulate_errors(value, validators)
    if len(errors) == len(validators):
        item_error_messages = tuple(
            " - [{}]: {}".format(idx, str(err)) for idx, err in errors
        )
        error_message = (
            "Value did not pass any of the provided validators:\n"
            "{}".format("\n".join(item_error_messages))
        )
        raise ValidationError(error_message)


def validate_no_extra_keys(value, allowed_keys):
    extra_keys = tuple(sorted(set(value.keys()).difference(allowed_keys)))
    if extra_keys:
        raise ValidationError(
            "Only the keys '{}' are allowed.  Got extra keys: '{}'".format(
                "/".join(tuple(sorted(allowed_keys))),
                "/".join(extra_keys),
            )
        )


def validate_has_required_keys(value, required_keys):
    missing_keys = tuple(sorted(set(required_keys).difference(value.keys())))
    if missing_keys:
        raise ValidationError(
            "dict must contain all of the keys '{}'.  Missing the keys: '{}'".format(
                "/".join(tuple(sorted(required_keys))),
                "/".join(missing_keys),
            )
        )


@to_dict
def _accumulate_dict_errors(value, validators):
    for key, validator_fn in validators.items():
        item = value[key]
        try:
            validator_fn(item)
        except ValidationError as err:
            yield key, err


def validate_dict(value, key_validators):
    validate_is_dict(value)
    validate_no_extra_keys(value, key_validators.keys())
    validate_has_required_keys(value, key_validators.keys())

    key_errors = _accumulate_dict_errors(value, key_validators)
    if key_errors:
        key_messages = tuple(
            "{}: {}".format(key, str(err)) for key, err in sorted(key_errors.items())
        )
        error_message = "The following keys failed to validate\n" "- {}".format(
            "\n - ".join(key_messages)
        )
        raise ValidationError(error_message)


@to_tuple
def _accumulate_array_errors(value, validator):
    for index, item in enumerate(value):
        try:
            validator(item)
        except ValidationError as err:
            yield index, err


def validate_array(value, validator):
    validate_is_list_like(value)

    item_errors = _accumulate_array_errors(value, validator)
    if item_errors:
        item_messages = tuple(
            "[{}]: {}".format(index, str(err)) for index, err in sorted(item_errors)
        )
        error_message = "The following items failed to validate\n" "- {}".format(
            "\n - ".join(item_messages)
        )
        raise ValidationError(error_message)


def validate_transaction_type(value):
    if not (is_hexstr(value) or is_integer(value)):
        raise ValidationError(
            f"Transaction type must be hexadecimal or integer. Got {value}"
        )
    if is_hexstr(value) and "0x" not in value:
        raise ValidationError(
            f"Transaction type string must be hex string. Got: {value}"
        )
    type_int = int(value, 16) if is_hexstr(value) else int(value)
    if type_int not in (0, 1, 2):
        raise ValidationError(f"Transaction type '{value}' not recognized.")


def if_not_null(validator_fn):
    @functools.wraps(validator_fn)
    def inner(value):
        if value is not None:
            validator_fn(value)

    return inner


def if_not_create_address(validator_fn):
    @functools.wraps(validator_fn)
    def inner(value):
        if value != b"":
            validator_fn(value)

    return inner


def validate_address(value: Union[str, HexStr, bytes]):
    if not is_address(value):
        raise ValidationError(f"Value must be a valid address. Got: {value}")
