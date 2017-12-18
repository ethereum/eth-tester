from __future__ import unicode_literals

import pytest

from hypothesis import (
    settings,
)

from eth_tester import (
    EthereumTester,
    PyEthereum20Backend,
)

from eth_tester.backends.pyethereum.utils import (
    is_pyethereum20_available,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
    BaseTestBackendFuzz,
    EVMStateFuzzer,
)


pytestmark = pytest.mark.filterwarnings("ignore:implicit cast from 'char *'")


@pytest.fixture
def eth_tester():
    if not is_pyethereum20_available():
        pytest.skip("PyEthereum >=2.0.0,<2.2.0 not available")
    backend = PyEthereum20Backend()
    return EthereumTester(backend=backend)


class TestPyEthereum20BackendDirect(BaseTestBackendDirect):
    pass


class TestPyEthereum20BackendFuzz(BaseTestBackendFuzz):
    pass



#TestPyEthereum20EVMStateFuzzer = EVMStateFuzzer.TestCase
#TestPyEthereum20EVMStateFuzzer.settings = settings(max_examples=20, stateful_step_count=50)
