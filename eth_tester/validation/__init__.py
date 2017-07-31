from cytoolz import (
    partial,
)

from eth_utils import (
    is_bytes,
    is_hex,
    is_integer,
)

from .functional import (
    validate_length,
    validate_gt,
    validate_gte,
    validate_lt,
    validate_lte,
)
from .core import (
    Validator,
)


class ValidateLength(Validator):
    @classmethod
    def from_length(cls, length):
        return cls.from_validator_fn(partial(validate_length, length=length))


class ValidateGT(Validator):
    @classmethod
    def from_minimum(cls, minimum):
        return cls.from_validator_fn(partial(validate_gt, minimum=minimum))


class ValidateGTE(Validator):
    @classmethod
    def from_minimum(cls, minimum):
        return cls.from_validator_fn(partial(validate_gte, minimum=minimum))


class ValidateLT(Validator):
    @classmethod
    def from_maximum(cls, maximum):
        return cls.from_validator_fn(partial(validate_gt, maximum=maximum))


class ValidateLTE(Validator):
    @classmethod
    def from_maximum(cls, maximum):
        return cls.from_validator_fn(partial(validate_gte, maximum=maximum))


ValidateInteger = Validator.from_condition(is_integer)
ValidatePositive = ValidateGTE.from_minimum(0)
ValidatePositiveInteger = ValidateInteger.and_(ValidatePositive)


Validate32ByteString = Validator.and_(
    Validator.from_condition(is_bytes),
    ValidateLength.from_length(32),
)

Validate64HexString = Validator.and_(
    Validator.from_condition(is_hex),
    ValidateLength.from_length(64).or_(ValidateLength.from_length(66)),
)

TransactionHashValidator = Validator.or_(
    Validate32ByteString,
    Validate64HexString,
)
