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


@pytest.fixture
def test_transaction():
    return {
        "from": "0x" + "1" * 40,
        "to": "0x" + "2" * 40,
        "gas": 21000,
        "value": 1000000000000000000,
        "data": "0x1234",
        "nonce": 0,
    }


class TestMockBackendDirect(BaseTestBackendDirect):
    supports_evm_execution = False

    @pytest.mark.skip(reason="receipt status not supported in MockBackend")
    def test_get_transaction_receipt_byzantium(self, eth_tester, test_transaction):
        pass

    def test_estimate_gas_raises_not_implemented(self, eth_tester, test_transaction):
        with pytest.raises(NotImplementedError):
            eth_tester.estimate_gas(test_transaction, block_number="pending")
