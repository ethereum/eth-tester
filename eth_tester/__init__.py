from importlib.metadata import (
    version as __version,
)

from .backends import (
    EELSBackend,
    MockBackend,
    PyEVMBackend,
)
from .main import (
    EthereumTester,
)

__version__ = __version("eth-tester")
