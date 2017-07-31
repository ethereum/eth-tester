from cytoolz import (
    partial,
)

from eth_tester.exceptions import (
    ValidationError,
)

from .functional import (
    validate_any,
    validate_all,
    validate_if,
    conditional_validate,
)


class Validator(object):
    validator_fn = None

    @classmethod
    def from_validator_fn(cls, validator_fn):
        return type(
            cls.__name__,
            (Validator,),
            {'validator_fn': staticmethod(validator_fn)}
        )

    @classmethod
    def from_condition(cls, condition):
        return type(
            cls.__name__,
            (Validator,),
            {'validator_fn': staticmethod(partial(validate_if, condition=condition))}
        )

    def __call__(self, value):
        if self.validator_fn is not None:
            return self.validator_fn(value)

    def is_valid(self, value):
        try:
            self(value)
        except ValidationError:
            return False
        else:
            return True

    @classmethod
    def normalize_other(self, other):
        if isinstance(other, type) and issubclass(other, Validator):
            return other()
        elif callable(other):
            return other
        else:
            raise ValidationError("Must be a callable.  Got: {0}".format(other))

    @classmethod
    def or_(cls, *others):
        return cls.from_validator_fn(
            partial(validate_any, validators=[
                cls(),
            ] + [
                cls.normalize_other(other) for other in others
            ])
        )

    @classmethod
    def and_(cls, *others):
        return cls.from_validator_fn(
            partial(validate_all, validators=[
                cls(),
            ] + [
                cls.normalize_other(other) for other in others
            ])
        )

    @classmethod
    def only_if(cls, condition):
        return cls.from_validator_fn(
            partial(conditional_validate, condition=condition, validator=cls())
        )
