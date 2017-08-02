from __future__ import absolute_import

import os

from eth_tester.utils.module_loading import (
    get_import_path,
    import_string,
)

from .default import (
    DefaultValidator,
)


DEFAULT_VALIDATOR_CLASS = get_import_path(DefaultValidator)


def get_validation_backend_class(backend_import_path):
    return import_string(backend_import_path)


def get_validator(backend_class=None):
    if backend_class is None:
        backend_import_path = os.environ.get(
            'ETHEREUM_TESTER_VALIDATOR',
            DEFAULT_VALIDATOR_CLASS,
        )
        backend_class = get_validation_backend_class(backend_import_path)
    return backend_class()
