from __future__ import unicode_literals

import pytest

from eth_tester import (
    EthereumTester,
    PyEthereum16Backend,
)

from eth_tester.backends.pyethereum.utils import (
    is_pyethereum16_available,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
)


pytestmark = pytest.mark.filterwarnings("ignore:implicit cast from 'char *'")


@pytest.fixture
def eth_tester():
    if not is_pyethereum16_available():
        pytest.skip("PyEthereum >=1.6.0,<1.7.0 not available")
    backend = PyEthereum16Backend()
    return EthereumTester(backend=backend)


class TestPyEthereum16BackendDirect(BaseTestBackendDirect):

    @pytest.mark.skip(reason="v1.6 not supported")
    def test_call_query_previous_state(self, eth_tester):
        pass

    @pytest.mark.skip(reason="v1.6 not supported")
    def test_get_transaction_receipt_byzantium(self, eth_tester):
        pass

    @pytest.mark.skip(reason="v1.6 not supported")
    def test_get_transaction_receipt_byzantium(self, eth_tester, test_transaction):
        pass

    @pytest.mark.skip(reason="v1.6 not supported")
    def test_get_transaction_receipt_byzantium(self, eth_tester, test_transaction):
        pass

    @pytest.mark.skip(reason="v1.6 not supported")
    def test_revert_reason_message(self, eth_tester):
        pass
