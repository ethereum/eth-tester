from __future__ import unicode_literals

import pytest

from eth_tester import (
    EthereumTester,
    PyEVMBackend,
)

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

    def test_override_genesis_parameters(self, eth_tester):
        super().test_reset_to_genesis(eth_tester)

        param_overrides = {'gas_limit': 4750000}

        # Use the the static method to generate custom genesis params
        genesis_params = PyEVMBackend.generate_genesis_params(param_overrides)
        assert genesis_params['block_number'] == 0
        assert genesis_params['gas_limit'] == 4750000

        # Only default genesis paraeter keys can be overriden
        invalid_overrides = {'gato': 'con botas'}
        with pytest.raises(ValueError):
            _invalid_genesis_params = PyEVMBackend.generate_genesis_params(invalid_overrides)

        # Initialize pyevm backend with genesis params
        pyevm_backend = PyEVMBackend(genesis_params)
        assert pyevm_backend.chain.header._gas_limit == 4745362

        # Or use the alternate constructor
        pyevm_backend = PyEVMBackend.from_genesis_overrides(parameter_overrides=param_overrides)
        assert pyevm_backend.chain.header._gas_limit == 4745362

        # Integrate with eth-tester
        tester = EthereumTester(backend=pyevm_backend)
        assert tester.backend.chain.header._block_number == 1
        assert tester.backend.chain.header._gas_limit == 4745362
