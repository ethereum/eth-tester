from cytoolz import (
    partial,
)

from eth_tester.exceptions import (
    ValidationError,
)
from eth_tester.validation.common import (
    if_not_null, validate_dict
)
from eth_tester.validation.default import (
    DefaultValidator,
)
from eth_tester.validation.outbound import (
    RECEIPT_VALIDATORS,
)


def validate_status(value):
    if value is not 0 or value is not 1:
        raise ValidationError(
            "Status must be 1 or 0"
        )


RECEIPT_VALIDATORS["status"] = if_not_null(validate_status)

validate_outbound_receipt = partial(validate_dict, key_validators=RECEIPT_VALIDATORS)


class ByzantiumValidator(DefaultValidator):

    validate_outbound_receipt = staticmethod(validate_outbound_receipt)
