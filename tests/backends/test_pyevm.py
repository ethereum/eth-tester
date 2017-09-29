from __future__ import unicode_literals

import pytest

from eth_tester import (
    EthereumTester,
    PyEVMBackend,
)

from eth_tester.backends.pyevm.utils import (
    is_pyevm_available,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
)


@pytest.fixture
def eth_tester():
    if not is_pyevm_available():
        pytest.skip("PyEVM is not available")
    backend = PyEVMBackend()
    return EthereumTester(backend=backend)


class TestPyEVMBackendDirect(BaseTestBackendDirect):
    pass
