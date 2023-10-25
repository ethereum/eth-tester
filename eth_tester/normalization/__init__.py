from __future__ import (
    absolute_import,
)

import os

from eth_tester.utils.module_loading import (
    get_import_path,
    import_string,
)

from .default import (
    DefaultNormalizer,
)

DEFAULT_NORMALIZER_CLASS = get_import_path(DefaultNormalizer)


def get_normalizer_backend_class(backend_import_path=None):
    if backend_import_path is None:
        backend_import_path = os.environ.get(
            "ETHEREUM_TESTER_NORMALIZER_BACKEND",
            DEFAULT_NORMALIZER_CLASS,
        )
    return import_string(backend_import_path)


def get_normalizer_backend(backend_class=None):
    if backend_class is None:
        backend_class = get_normalizer_backend_class()
    return backend_class()
