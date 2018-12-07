from __future__ import unicode_literals

import pytest
from eth_utils import to_wei

from eth_tester import EthereumTester, PyEVMBackend
from eth_tester.backends.pyevm.main import (
    generate_genesis_state_for_keys,
    get_default_account_keys,
    get_default_genesis_params,
)
from eth_tester.backends.pyevm.utils import is_pyevm_available
from eth_tester.exceptions import ValidationError
from eth_tester.utils.backend_testing import BaseTestBackendDirect, SIMPLE_TRANSACTION


ZERO_ADDRESS_HEX = "0x0000000000000000000000000000000000000000"


@pytest.fixture
def eth_tester():
    if not is_pyevm_available():
        pytest.skip("PyEVM is not available")
    backend = PyEVMBackend()
    return EthereumTester(backend=backend)


class TestPyEVMBackendDirect(BaseTestBackendDirect):
    def test_generate_custom_genesis_state(self):
        state_overrides = {"balance": to_wei(900000, "ether")}
        invalid_overrides = {"gato": "con botas"}

        # Test creating a specific number of accounts
        account_keys = get_default_account_keys(quantity=2)
        assert len(account_keys) == 2
        account_keys = get_default_account_keys(quantity=10)
        assert len(account_keys) == 10

        # Test the underlying state merging functionality
        genesis_state = generate_genesis_state_for_keys(
            account_keys=account_keys, overrides=state_overrides
        )
        assert len(genesis_state) == len(account_keys) == 10
        for _public_address, account_state in genesis_state.items():
            assert account_state["balance"] == state_overrides["balance"]
            assert account_state["code"] == b""

        # Only existing default genesis state keys can be overridden
        with pytest.raises(ValueError):
            _invalid_genesis_state = generate_genesis_state_for_keys(
                account_keys=account_keys, overrides=invalid_overrides
            )

        # Use staticmethod state overriding
        genesis_state = PyEVMBackend._generate_genesis_state(
            overrides=state_overrides, num_accounts=3
        )
        assert len(genesis_state) == 3
        for _public_address, account_state in genesis_state.items():
            assert account_state["balance"] == state_overrides["balance"]
            assert account_state["code"] == b""

        # Only existing default genesis state keys can be overridden
        with pytest.raises(ValueError):
            _invalid_genesis_state = PyEVMBackend._generate_genesis_state(
                overrides=invalid_overrides
            )

    def test_override_genesis_state(self):
        state_overrides = {"balance": to_wei(900000, "ether")}
        test_accounts = 3

        # Initialize PyEVM backend with custom genesis state
        genesis_state = PyEVMBackend._generate_genesis_state(
            overrides=state_overrides, num_accounts=test_accounts
        )

        # Test the correct number of accounts are created with the specified balance override
        pyevm_backend = PyEVMBackend(genesis_state=genesis_state)
        assert len(pyevm_backend.account_keys) == test_accounts
        for private_key in pyevm_backend.account_keys:
            account = private_key.public_key.to_canonical_address()
            balance = pyevm_backend.get_balance(account=account)
            assert balance == state_overrides["balance"]

        # Test integration with EthereumTester
        tester = EthereumTester(backend=pyevm_backend)
        for private_key in pyevm_backend.account_keys:
            account = private_key.public_key.to_checksum_address()
            balance = tester.get_balance(account=account)
            assert balance == state_overrides["balance"]

    def test_generate_custom_genesis_parameters(self):

        # Establish parameter overrides, for example a custom genesis gas limit
        param_overrides = {"gas_limit": 4750000}

        # Test the underlying default parameter merging functionality
        genesis_params = get_default_genesis_params(overrides=param_overrides)
        assert genesis_params["block_number"] == 0
        assert genesis_params["gas_limit"] == param_overrides["gas_limit"]

        # Use the the staticmethod to generate custom genesis parameters
        genesis_params = PyEVMBackend._generate_genesis_params(param_overrides)
        assert genesis_params["block_number"] == 0
        assert genesis_params["gas_limit"] == param_overrides["gas_limit"]

        # Only existing default genesis parameter keys can be overridden
        invalid_overrides = {"gato": "con botas"}
        with pytest.raises(ValueError):
            _invalid_genesis_params = PyEVMBackend._generate_genesis_params(
                overrides=invalid_overrides
            )

    def test_override_genesis_parameters(self):

        # Establish a custom gas limit
        param_overrides = {"gas_limit": 4750000}
        block_one_gas_limit = 4745362

        # Initialize PyEVM backend with custom genesis parameters
        genesis_params = PyEVMBackend._generate_genesis_params(
            overrides=param_overrides
        )
        pyevm_backend = PyEVMBackend(genesis_parameters=genesis_params)
        genesis_block = pyevm_backend.get_block_by_number(0)
        assert genesis_block["gas_limit"] == param_overrides["gas_limit"]
        genesis_block = pyevm_backend.get_block_by_number(1)
        assert genesis_block["gas_limit"] == block_one_gas_limit

        # Integrate with EthereumTester
        tester = EthereumTester(backend=pyevm_backend)
        genesis_block = tester.get_block_by_number(0)
        assert genesis_block["gas_limit"] == param_overrides["gas_limit"]
        genesis_block = tester.get_block_by_number(1)
        assert genesis_block["gas_limit"] == block_one_gas_limit

    def test_send_transaction_invalid_from(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        with pytest.raises(ValidationError) as excinfo:
            self._send_and_check_transaction(
                eth_tester, SIMPLE_TRANSACTION, ZERO_ADDRESS_HEX
            )

        assert "does this account exist?" in str(excinfo.value)
