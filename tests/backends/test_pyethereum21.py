from __future__ import unicode_literals

import os
import pytest

from eth_tester import (
    EthereumTester,
    PyEthereum21Backend,
)

from eth_tester.backends.pyethereum.utils import (
    is_pyethereum21_available,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
)


pytestmark = pytest.mark.filterwarnings("ignore:implicit cast from 'char *'")


@pytest.fixture
def eth_tester():
    if not is_pyethereum21_available():
        pytest.skip("PyEthereum >=2.0.0,<2.2.0 not available")
    if os.environ.get('ETHEREUM_TESTER_VALIDATOR') is not None:
        del os.environ['ETHEREUM_TESTER_VALIDATOR']
    backend = PyEthereum21Backend()
    return EthereumTester(backend=backend)


class TestPyEthereum21BackendDirect(BaseTestBackendDirect):
    pass
