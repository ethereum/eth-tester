from __future__ import unicode_literals

import pytest

from eth_tester import (
    EthereumTester,
)

from eth_tester.backends.pyevm import (
    PyEvmBackend,
)

from eth_tester.backends.pyevm.utils import (
    is_pyevm_available,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
    BaseTestBackendFuzz,
)

@pytest.fixture
def eth_tester():
    if not is_pyevm_available():
        pytest.skip("PyEvm version >=0.2.0 not available")
    backend = PyEvmBackend()
    return EthereumTester(backend=backend)


class TestPyEvmBackendDirect(BaseTestBackendDirect):
    pass


class TestPyEvmBackendFuzz(BaseTestBackendFuzz):
    pass
