import pytest

from eth_utils import is_address
from eth_tester import (
    EthereumTester,
    PyEthereum20Backend,
)

from eth_tester.backends.pyethereum.utils import (
    is_pyethereum20_available,
)

from eth_tester.utils.backend_testing import (
    BaseTestEthereumTester,
)


@pytest.fixture
def eth_tester():
    if not is_pyethereum20_available():
        pytest.skip("PyEthereum >=2.0.0,<2.1.0 not available")
    backend = PyEthereum20Backend()
    return EthereumTester(backend=backend)


class TestPyEthereum20Backend(BaseTestEthereumTester):
    pass
