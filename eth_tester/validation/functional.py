from eth_utils import (
    is_bytes,
    is_hex,
)

from eth_tester.exceptions import (
    ValidationError,
)

from .utils import (
    collect_validation_errors,
)


def validate_any(value, validators):
    errors = collect_validation_errors(value, validators)
    if len(errors) == len(validators):
        raise ValidationError(
            "Value {0} was not valid under any of the provided validation "
            "rules:\n- {1}".format(
                value,
                '- '.join((str(error) for error in errors)),
            )
        )


def validate_all(value, validators):
    errors = collect_validation_errors(value, validators)
    if errors:
        raise ValidationError(
            "Value {0} was not valid under all of the provided validation "
            "rules:\n- {1}".format(
                value,
                '- '.join((str(error) for error in errors)),
            )
        )


def validate_if(value, condition, message="Value does not pass check: {0}"):
    if not condition(value):
        raise ValidationError(message.format(value))


def conditional_validate(value, condition, validator):
    if condition(value):
        validator(value)


def validate_length(value, length):
    if len(value) != length:
        raise ValidationError(
            "Value must be of length {0}.  Got {1} of lenght {2}".format(
                length,
                value,
                len(value),
            )
        )


def validate_gt(value, minimum):
    if value <= minimum:
        raise ValidationError(
            "Value {0} is not greater than {1}.".format(
                value,
                minimum,
            )
        )


def validate_gte(value, minimum):
    if value < minimum:
        raise ValidationError(
            "Value {0} is not greater than or eqal to{1}.".format(
                value,
                minimum,
            )
        )


def validate_lt(value, maximum):
    if value >= maximum:
        raise ValidationError(
            "Value {0} is not less than {1}.".format(
                value,
                maximum,
            )
        )


def validate_lte(value, maximum):
    if value > maximum:
        raise ValidationError(
            "Value {0} is not less than or eqal to{1}.".format(
                value,
                maximum,
            )
        )


def validate_is_bytes(value):
    if not is_bytes(value):
        raise ValidationError("Value is not of type bytes.  Got {0}".format(type(value)))


def validate_is_hex(value):
    if not is_hex(value):
        raise ValidationError(
            "Value is not valid hexdecimal. Got {0}".format(type(value))
        )
