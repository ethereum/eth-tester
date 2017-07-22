import pkg_resources

from .main import (  # noqa: F401
    EthereumTester,
)
from .backends import (  # noqa: F401
    PyEthereum16Backend,
    PyEthereum20Backend,
)


__version__ = pkg_resources.get_distribution("ethereum-tester").version
