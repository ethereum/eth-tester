import pkg_resources

from .main import (
    EthereumTester,
)
from .backends import (
    PyEthereum16Backend,
    PyEthereum20Backend,
)


__version__ = pkg_resources.get_distribution("ethereum-tester").version
