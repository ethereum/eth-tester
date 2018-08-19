import os
import sys
import warnings

from eth_tester.utils.module_loading import (
    get_import_path,
    import_string,
)
from .mock import (   # noqa: F401
    MockBackend,
)
from .pyevm import (  # noqa: F401
    PyEVMBackend,
    is_pyevm_available,
)


def get_chain_backend_class(backend_import_path=None):
    warnings.simplefilter('default')

    if backend_import_path is None:
        if 'ETHEREUM_TESTER_CHAIN_BACKEND' in os.environ:
            backend_import_path = os.environ['ETHEREUM_TESTER_CHAIN_BACKEND']
        elif is_pyevm_available():
            vi = sys.version_info
            if vi.major != 3 or vi.minor < 5:
                warnings.warn(UserWarning("Py-EVM does not support python < 3.5"))
            backend_import_path = get_import_path(PyEVMBackend)
        else:
            warnings.warn(UserWarning(
                "Ethereum Tester: No backend was explicitely set, and no *full* "
                "backends were available.  Falling back to the `MockBackend` "
                "which does not support all EVM functionality.  Please refer to "
                "the `eth-tester` documentation for information on what "
                "backends are available and how to set them."
            ))
            backend_import_path = get_import_path(MockBackend)
    return import_string(backend_import_path)


def get_chain_backend(backend_class=None):
    if backend_class is None:
        backend_class = get_chain_backend_class()
    return backend_class()
