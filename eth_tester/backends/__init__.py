import os
import sys
import warnings

from eth_tester.utils.module_loading import (
    get_import_path,
    import_string,
)

from .mock import (
    MockBackend,
)
from .pyevm import (
    PyEVMBackend,
    is_supported_pyevm_version_available,
)


def get_chain_backend_class(backend_import_path=None):
    warnings.simplefilter("default")

    if backend_import_path is None:
        if "ETHEREUM_TESTER_CHAIN_BACKEND" in os.environ:
            backend_import_path = os.environ["ETHEREUM_TESTER_CHAIN_BACKEND"]
        elif is_supported_pyevm_version_available():
            backend_import_path = get_import_path(PyEVMBackend)
        else:
            warnings.warn(
                UserWarning(
                    "Ethereum Tester: No backend was explicitly set, and no *full* "
                    "backends were available.  Falling back to the `MockBackend` "
                    "which does not support all EVM functionality.  Please refer to "
                    "the `eth-tester` documentation for information on what "
                    "backends are available and how to set them.  Your py-evm "
                    "package may need to be updated."
                ),
                stacklevel=2,
            )
            backend_import_path = get_import_path(MockBackend)
    return import_string(backend_import_path)


def get_chain_backend(backend_class=None):
    if backend_class is None:
        backend_class = get_chain_backend_class()
    return backend_class()
