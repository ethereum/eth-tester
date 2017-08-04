from __future__ import unicode_literals

import pytest

from hypothesis import (
    settings,
)

from eth_tester import (
    EthereumTester,
    MockBackend,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
    BaseTestBackendFuzz,
    EVMStateFuzzer,
)


@pytest.fixture
def eth_tester():
    backend = MockBackend()
    return EthereumTester(backend=backend)



class TestMockBackendDirect(BaseTestBackendDirect):
    pass


#class TestMockBackendFuzz(BaseTestBackendFuzz):
#    pass



#TestPyEthereum16EVMStateFuzzer = EVMStateFuzzer.TestCase
#TestPyEthereum16EVMStateFuzzer.settings = settings(max_examples=20, stateful_step_count=50)
