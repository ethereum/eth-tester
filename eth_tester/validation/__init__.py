import os

from eth_tester.utils.module_loading import (
    get_import_path,
    import_string,
)

from .input import (
    InputValidationBackend,
)
from .output import (
    OutputValidationBackend,
)


DEFAULT_INPUT_VALIDATION_BACKEND_CLASS = get_import_path(InputValidationBackend)
DEFAULT_OUTPUT_VALIDATION_BACKEND_CLASS = get_import_path(OutputValidationBackend)


def get_validation_backend_class(backend_import_path):
    return import_string(backend_import_path)


def get_input_validator(backend_class=None):
    if backend_class is None:
        backend_import_path = os.environ.get(
            'ETHEREUM_TESTER_INPUT_VALIDATOR_BACKEND',
            DEFAULT_INPUT_VALIDATION_BACKEND_CLASS,
        )
        backend_class = get_validation_backend_class(backend_import_path)
    return backend_class()


def get_output_validator(backend_class=None):
    if backend_class is None:
        backend_import_path = os.environ.get(
            'ETHEREUM_TESTER_OUTPUT_VALIDATOR_BACKEND',
            DEFAULT_OUTPUT_VALIDATION_BACKEND_CLASS,
        )
        backend_class = get_validation_backend_class(backend_import_path)
    return backend_class()
