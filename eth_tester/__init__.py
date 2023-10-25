import sys

import pkg_resources

from .backends import (  # noqa: F401
    MockBackend,
    PyEVMBackend,
)
from .main import (  # noqa: F401
    EthereumTester,
)

if sys.version_info.major < 3:
    raise EnvironmentError("eth-tester only supports Python 3")


__version__ = pkg_resources.get_distribution("eth-tester").version
