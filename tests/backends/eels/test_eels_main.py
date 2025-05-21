"""
Tests for the main EELSBackend implementation.
"""
import pytest

from eth_tester import (
    EthereumTester,
)
from eth_tester.backends.eels import (
    EELSBackend,
)
from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
)


@pytest.fixture(scope="function")
def eth_tester():
    return EthereumTester(backend=EELSBackend())


class TestEELSBackendBasics:
    """Basic tests for the EELSBackend."""

    def setup_method(self):
        self.backend = EELSBackend()
        self.tester = EthereumTester(backend=self.backend)

    def test_initialization(self):
        """Test that the backend initializes correctly."""
        assert isinstance(self.backend, EELSBackend)
        assert isinstance(self.tester, EthereumTester)

    def test_get_accounts(self):
        """Test that accounts are available."""
        accounts = self.tester.get_accounts()
        assert len(accounts) > 0
        # Default should be 10 accounts
        assert len(accounts) == 10

    def test_get_block_by_number(self):
        """Test retrieving a block by number."""
        # Get the genesis block
        block = self.tester.get_block_by_number(0)
        assert block["number"] == 0
        assert "hash" in block
        assert "parentHash" in block


class TestEELSBackendAccountState(BaseTestBackendDirect):
    """Basic tests for the EELSBackend."""

    # def setup_method(self):
    #     self.backend = EELSBackend()
    #     self.tester = EthereumTester(backend=self.backend)

    # def test_get_nonce(self):
    #     """Test that account nonces can be retrieved."""
    #     accounts = self.tester.get_accounts()
    #     nonce = self.tester.get_nonce(accounts[0])
    #     # Default account nonce should be zero
    #     assert nonce == 0

    # def test_get_balance(self):
    #     """Test that account balances can be retrieved."""
    #     accounts = self.tester.get_accounts()
    #     balance = self.tester.get_balance(accounts[0])
    #     # Default account balance should be non-zero
    #     assert balance > 0

    # def test_get_code(self):
    #     """Test that account code can be retrieved."""
    #     accounts = self.tester.get_accounts()
    #     code = self.tester.get_code(accounts[0])
    #     # Default account code should be non-zero
    #     assert code == "0x"

    # def test_get_storage(self):
    #     """Test that account storage can be retrieved."""
    #     accounts = self.tester.get_accounts()
    #     storage = self.tester.get_storage(accounts[0], 0)
    #     # Default account storage should be non-zero
    #     assert storage > 0

    # def test_get_base_fee(self):
    #     """Test that the base fee can be retrieved."""
    #     base_fee = self.tester.get_base_fee()
    #     # Default base fee should be non-zero
    #     assert base_fee > 0
