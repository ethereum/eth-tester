from __future__ import unicode_literals

import pytest

from eth_tester import (
    EthereumTester,
    MockBackend,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
)


@pytest.fixture
def eth_tester():
    backend = MockBackend()
    return EthereumTester(backend=backend)



class TestMockBackendDirect(BaseTestBackendDirect):
    supports_evm_execution = False
