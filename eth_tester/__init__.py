import pkg_resources
import sys

from .main import (  # noqa: F401
    EthereumTester,
)
from .backends import (  # noqa: F401
    MockBackend,
    PyEthereum16Backend,
    PyEthereum21Backend,
    PyEVMBackend,
)


if sys.version_info.major < 3:
    raise EnvironmentError("eth-tester only supports Python 3")


__version__ = pkg_resources.get_distribution("eth-tester").version
