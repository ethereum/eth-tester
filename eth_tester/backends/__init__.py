import os

from eth_tester.utils.module_loading import (
    get_import_path,
    import_string,
)

from .pyethereum.v16 import (
    PyEthereum16Backend,
)
from .pyethereum.v20 import (  # noqa: F401
    PyEthereum20Backend,
)


DEFAULT_CHAIN_BACKEND_CLASS = get_import_path(PyEthereum16Backend)


def get_chain_backend_class(backend_import_path=None):
    if backend_import_path is None:
        backend_import_path = os.environ.get(
            'ETHEREUM_TESTER_CHAIN_BACKEND',
            DEFAULT_CHAIN_BACKEND_CLASS,
        )
    return import_string(backend_import_path)


def get_chain_backend(backend_class=None):
    if backend_class is None:
        backend_class = get_chain_backend_class()
    return backend_class()
