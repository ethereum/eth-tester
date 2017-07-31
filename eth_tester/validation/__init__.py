import os

from eth_tester.utils.module_loading import (
    get_import_path,
    import_string,
)

from .strict import (  # noqa: F401
    StrictValidationBackend,
)


DEFAULT_VALIDATION_BACKEND_CLASS = get_import_path(StrictValidationBackend)


def get_validation_backend_class(backend_import_path=None):
    if backend_import_path is None:
        backend_import_path = os.environ.get(
            'ETHEREUM_TESTER_VALIDATION_BACKEND',
            DEFAULT_VALIDATION_BACKEND_CLASS,
        )
    return import_string(backend_import_path)


def get_validation_backend(backend_class=None):
    if backend_class is None:
        backend_class = get_validation_backend_class()
    return backend_class()
