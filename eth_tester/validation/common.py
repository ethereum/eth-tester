from __future__ import unicode_literals

import functools

from eth_utils import (
    is_boolean,
    is_bytes,
    is_text,
    is_dict,
    is_integer,
    is_list_like,
    to_dict,
    to_tuple,
)

from eth_tester.constants import (
    UINT256_MAX,
)
from eth_tester.exceptions import (
    ValidationError,
)


def validate_positive_integer(value):
    error_message = "Value must be positive integers.  Got: {0}".format(
        value,
    )
    if not is_integer(value) or is_boolean(value):
        raise ValidationError(error_message)
    elif value < 0:
        raise ValidationError(error_message)


def validate_uint256(value):
    validate_positive_integer(value)
    if value > UINT256_MAX:
        raise ValidationError("Value exceeds maximum 256 bit integer size:  {0}".format(value))


def validate_bytes(value):
    if not is_bytes(value):
        raise ValidationError("Value must be a byte string.  Got type: {0}".format(type(value)))


def validate_text(value):
    if not is_text(value):
        raise ValidationError("Value must be a text string.  Got type: {0}".format(type(value)))


def validate_is_dict(value):
    if not is_dict(value):
        raise ValidationError("Value must be a dictionary.  Got: {0}".format(type(value)))


def validate_is_list_like(value):
    if not is_list_like(value):
        raise ValidationError("Value must be a sequence type.  Got: {0}".format(type(value)))


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
            " - [{0}]: {1}".format(idx, str(err))
            for idx, err
            in errors
        )
        error_message = (
            "Value did not pass any of the provided validators:\n"
            "{0}".format(
                "\n".join(item_error_messages)
            )
        )
        raise ValidationError(error_message)


def validate_no_extra_keys(value, allowed_keys):
    extra_keys = tuple(sorted(set(value.keys()).difference(allowed_keys)))
    if extra_keys:
        raise ValidationError(
            "Only the keys '{0}' are allowed.  Got extra keys: '{1}'".format(
                "/".join(tuple(sorted(allowed_keys))),
                "/".join(extra_keys),
            )
        )


def validate_has_required_keys(value, required_keys):
    missing_keys = tuple(sorted(set(required_keys).difference(value.keys())))
    if missing_keys:
        raise ValidationError(
            "Blocks must contain all of the keys '{0}'.  Missing the keys: '{1}'".format(
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
            "{0}: {1}".format(key, str(err))
            for key, err
            in sorted(key_errors.items())
        )
        error_message = (
            "The following keys failed to validate\n"
            "- {0}".format(
                "\n - ".join(key_messages)
            )
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
            "[{0}]: {1}".format(index, str(err))
            for index, err
            in sorted(item_errors)
        )
        error_message = (
            "The following items failed to validate\n"
            "- {0}".format(
                "\n - ".join(item_messages)
            )
        )
        raise ValidationError(error_message)


def if_not_null(validator_fn):
    @functools.wraps(validator_fn)
    def inner(value):
        if value is not None:
            validator_fn(value)
    return inner


def if_not_create_address(validator_fn):
    @functools.wraps(validator_fn)
    def inner(value):
        if value != b'':
            validator_fn(value)
    return inner
