import os
from typing import (
    Optional,
)

from eth_tester.utils.module_loading import (
    get_import_path,
    import_string,
)

from .eels import (
    EELSBackend,
    eels_is_available,
)
from .pyevm import (
    PyEVMBackend,
    is_supported_pyevm_version_available,
)


def get_chain_backend_class(backend_import_path: Optional[str] = None):
    """
    Returns the chain backend class based on the configuration.

    The configuration is determined by the following order of precedence:

    1. Environment variable `ETHEREUM_TESTER_CHAIN_BACKEND`
    2. Availability of `py-evm` backend
    3. Availability of `eels` backend

    Args
    ----
        backend_import_path: The import path of the backend class.

    Returns
    -------
        The imported backend class.

    Raises
    ------
        ImportError: If no backend is configured and no default backends are available.

    """
    if backend_import_path is None:
        if "ETHEREUM_TESTER_CHAIN_BACKEND" in os.environ:
            backend_import_path = os.environ["ETHEREUM_TESTER_CHAIN_BACKEND"]
        elif is_supported_pyevm_version_available():
            backend_import_path = get_import_path(PyEVMBackend)
        elif eels_is_available():
            backend_import_path = get_import_path(EELSBackend)
        else:
            raise ImportError(
                "Ethereum Tester: No backend was explicitly set, and no default "
                "backends were available. Please refer to "
                "the `eth-tester` documentation for information on what "
                "backends are available and how to set them."
            )
    return import_string(backend_import_path)


def get_chain_backend(backend_class=None):
    if backend_class is None:
        backend_class = get_chain_backend_class()
    return backend_class()
