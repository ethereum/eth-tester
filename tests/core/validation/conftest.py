import pytest

from eth_tester.validation import (
    DefaultValidator,
)


@pytest.fixture
def validator() -> DefaultValidator:
    """
    Fixture to provide a DefaultValidator instance for testing.
    This fixture is used to validate various data structures and
    transactions.
    """
    _validator = DefaultValidator()
    return _validator
