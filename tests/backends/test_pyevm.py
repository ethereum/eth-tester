from __future__ import unicode_literals

import pytest
from eth_utils import to_wei

from eth_tester import (
    EthereumTester,
    PyEVMBackend,
)
from eth_tester.backends.pyevm.main import generate_genesis_state, get_default_account_keys

from eth_tester.backends.pyevm.utils import (
    is_pyevm_available,
)
from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
)


@pytest.fixture
def eth_tester():
    if not is_pyevm_available():
        pytest.skip("PyEVM is not available")
    backend = PyEVMBackend()
    return EthereumTester(backend=backend)


class TestPyEVMBackendDirect(BaseTestBackendDirect):

    def test_generate_custom_genesis_state(self):
        state_overrides = {'balance': to_wei(900000, 'ether')}

        # Test creating a specific number of accounts
        account_keys = get_default_account_keys(quantity=2)
        assert len(account_keys) == 2
        account_keys = get_default_account_keys(quantity=10)
        assert len(account_keys) == 10

        # Test the underlying state merging functionality
        genesis_state = generate_genesis_state(account_keys=account_keys, overrides=state_overrides)
        assert len(genesis_state) == len(account_keys) == 10
        for _public_address, account_state in genesis_state.items():
            assert account_state['balance'] == state_overrides['balance']
            assert account_state['code'] == b''

        # Use staticmethod state overriding
        genesis_state = PyEVMBackend.generate_genesis_state(overrides=state_overrides, accounts=3)
        assert len(genesis_state) == 3
        for _public_address, account_state in genesis_state.items():
            assert account_state['balance'] == state_overrides['balance']
            assert account_state['code'] == b''

    def test_override_genesis_state(self):

        state_overrides = {'balance': to_wei(900000, 'ether')}

        # Initialize PyEVM backend with custom genesis state
        genesis_state = PyEVMBackend.generate_genesis_state(overrides=state_overrides, accounts=3)
        pyevm_backend = PyEVMBackend(genesis_state=genesis_state)
        assert len(pyevm_backend.account_keys) == 3
        for account, state in genesis_state.items():
            assert pyevm_backend.get_balance(account=account) == state_overrides['balance']

    def test_generate_custom_genesis_parameters(self):
        # Establish overrides, for example a custom genesis gas limit
        param_overrides = {'gas_limit': 4750000}

        # Use the the staticmethod to generate custom genesis parameters
        genesis_params = PyEVMBackend.generate_genesis_params(param_overrides)
        assert genesis_params['block_number'] == 0
        assert genesis_params['gas_limit'] == param_overrides['gas_limit']

        # Only existing default genesis parameter keys can be overridden
        invalid_overrides = {'gato': 'con botas'}
        with pytest.raises(ValueError):
            _invalid_genesis_params = PyEVMBackend.generate_genesis_params(overrides=invalid_overrides)

    def test_override_genesis_parameters(self):
        # Establish a custom gas limit
        param_overrides = {'gas_limit': 4750000}
        block_one_gas_limit = 4745362

        # Initialize PyEVM backend with custom genesis parameters
        genesis_params = PyEVMBackend.generate_genesis_params(overrides=param_overrides)
        pyevm_backend = PyEVMBackend(genesis_parameters=genesis_params)
        genesis_block = pyevm_backend.get_block_by_number(0)
        assert genesis_block['gas_limit'] == param_overrides['gas_limit']
        genesis_block = pyevm_backend.get_block_by_number(1)
        assert genesis_block['gas_limit'] == block_one_gas_limit

        # Integrate with EthereumTester
        tester = EthereumTester(backend=pyevm_backend)
        genesis_block = tester.get_block_by_number(0)
        assert genesis_block['gas_limit'] == param_overrides['gas_limit']
        genesis_block = tester.get_block_by_number(1)
        assert genesis_block['gas_limit'] == block_one_gas_limit

    def test_from_genesis_overrides(self):
        state_overrides = {'balance': to_wei(900000, 'ether')}
        param_overrides = {'gas_limit': 4750000}
        block_one_gas_limit = 4745362

        # Use the alternate constructor to create a backend from custom genesis parameters
        pyevm_backend = PyEVMBackend.from_genesis_overrides(parameter_overrides=param_overrides,
                                                            state_overrides=state_overrides,
                                                            accounts=6)
        assert len(pyevm_backend.account_keys) == 6
        for private_key in pyevm_backend.account_keys:
            balance = pyevm_backend.get_balance(account=private_key.public_key.to_canonical_address())
            assert balance == state_overrides['balance']
        genesis_block = pyevm_backend.get_block_by_number(0)
        assert genesis_block['gas_limit'] == param_overrides['gas_limit']
        genesis_block = pyevm_backend.get_block_by_number(1)
        assert genesis_block['gas_limit'] == block_one_gas_limit
