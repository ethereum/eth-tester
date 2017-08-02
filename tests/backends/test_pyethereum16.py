from __future__ import unicode_literals

import pytest

from hypothesis import (
    settings,
)

from eth_utils import is_address
from eth_tester import (
    EthereumTester,
    PyEthereum16Backend,
)

from eth_tester.backends.pyethereum.utils import (
    is_pyethereum16_available,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
    BaseTestBackendFuzz,
    EVMStateFuzzer,
)


@pytest.fixture
def eth_tester():
    if not is_pyethereum16_available():
        pytest.skip("PyEthereum >=1.6.0,<1.7.0 not available")
    backend = PyEthereum16Backend()
    return EthereumTester(backend=backend)


class TestPyEthereum16BackendDirect(BaseTestBackendDirect):
    pass


class TestPyEthereum16BackendFuzz(BaseTestBackendFuzz):
    pass



#TestPyEthereum16EVMStateFuzzer = EVMStateFuzzer.TestCase
#TestPyEthereum16EVMStateFuzzer.settings = settings(max_examples=20, stateful_step_count=50)
