from __future__ import unicode_literals

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
    backend = PyEthereum21Backend()
    return EthereumTester(backend=backend)


class TestPyEthereum21BackendDirect(BaseTestBackendDirect):

    @pytest.mark.skip(reason="v2.1 not supported")
    def test_revert_reason_message(self, eth_tester):
        pass
