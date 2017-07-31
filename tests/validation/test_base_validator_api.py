import pytest

from eth_utils import (
    is_integer,
)

from eth_tester.exceptions import (
    ValidationError,
)
from eth_tester.validation import (
    Validator,
)


def is_truthy_validator(value):
    if not value:
        raise ValidationError('Value must be `True`')


def is_2_validator(value):
    if not value == 2:
        raise ValidationError("Value must be the number 2")


def test_class_factory_from_conditional():
    IsTruthyValidator = Validator.from_condition(bool)

    validator = IsTruthyValidator()

    validator(True)
    validator(1)
    validator('arst')

    with pytest.raises(ValidationError):
        validator(False)
    with pytest.raises(ValidationError):
        validator(0)
    with pytest.raises(ValidationError):
        validator('')


def test_class_factory_from_validator_fn():
    IsTruthyValidator = Validator.from_validator_fn(is_truthy_validator)

    validator = IsTruthyValidator()

    validator(True)
    validator(1)
    validator('arst')

    with pytest.raises(ValidationError):
        validator(False)
    with pytest.raises(ValidationError):
        validator(0)
    with pytest.raises(ValidationError):
        validator('')


def test_validator_or_composition():
    IsTruthyValidator = Validator.from_validator_fn(is_truthy_validator)
    Is2Validator = Validator.from_validator_fn(is_2_validator)

    Is2AndTruthyValidator = IsTruthyValidator.or_(Is2Validator)

    validator = Is2AndTruthyValidator()

    validator(2)
    validator(2.0)

    with pytest.raises(ValidationError):
        validator(False)
    with pytest.raises(ValidationError):
        validator('')
    with pytest.raises(ValidationError):
        validator([])


def test_validator_and_composition():
    IsTruthyValidator = Validator.from_validator_fn(is_truthy_validator)
    Is2Validator = Validator.from_validator_fn(is_2_validator)

    Is2AndTruthyValidator = IsTruthyValidator.and_(Is2Validator)

    validator = Is2AndTruthyValidator()

    validator(2)
    validator(2.0)

    with pytest.raises(ValidationError):
        validator(True)
    with pytest.raises(ValidationError):
        validator(1)
    with pytest.raises(ValidationError):
        validator('2')


def test_validator_only_if():
    Is2Validator = Validator.from_validator_fn(is_2_validator).only_if(is_integer)

    validator = Is2Validator()

    validator(2)
    validator('2')
    validator(False)
    validator('')
    validator([])

    with pytest.raises(ValidationError):
        validator(3)
    with pytest.raises(ValidationError):
        validator(1)
