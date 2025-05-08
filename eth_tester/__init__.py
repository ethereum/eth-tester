from importlib.metadata import (
    version as __version,
)

from .backends import (
    EELSBackend,
    PyEVMBackend,
)
from .main import (
    EthereumTester,
)
from .rpc import (
    run_server,
)

__version__ = __version("eth-tester")
