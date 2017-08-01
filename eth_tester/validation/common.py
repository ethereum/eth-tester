from __future__ import unicode_literals

import functools

from eth_utils import (
    is_boolean,
    is_bytes,
    is_dict,
    is_integer,
    to_dict,
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


def validate_is_dict(value):
    if not is_dict(value):
        raise ValidationError("Value must be a dictionary.  Got: {0}".format(type(value)))


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
def _accumulate_errors(value, validators):
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

    key_errors = _accumulate_errors(value, key_validators)
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


def if_not_null(validator_fn):
    @functools.wraps(validator_fn)
    def inner(value):
        if value is not None:
            validator_fn(value)
    return inner
