from eth_utils import (
    to_tuple,
)

from eth_tester.exceptions import (
    ValidationError,
)


@to_tuple
def collect_validation_errors(value, validators):
    for validator in validators:
        try:
            validator(value)
        except ValidationError as err:
            yield err
