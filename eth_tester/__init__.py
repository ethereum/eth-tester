import pkg_resources
import sys
import warnings

from .main import (  # noqa: F401
    EthereumTester,
)
from .backends import (  # noqa: F401
    MockBackend,
    PyEthereum16Backend,
    PyEVMBackend,
)


if sys.version_info.major < 3:
    warnings.simplefilter('always', DeprecationWarning)
    warnings.warn(DeprecationWarning(
        "The `eth-tester` library is dropping support for Python 2.  Upgrade to Python 3."
    ))
    warnings.resetwarnings()


__version__ = pkg_resources.get_distribution("eth-tester").version
