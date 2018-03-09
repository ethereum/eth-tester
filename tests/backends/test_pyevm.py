from __future__ import unicode_literals

import pytest

from cytoolz.dicttoolz import (
    dissoc,
)

from eth_tester import (
    EthereumTester,
    PyEVMBackend,
)

from eth_tester.backends.pyevm.utils import (
    is_pyevm_available,
)

from eth_tester.utils.math_contract import (
    _deploy_math,
    _make_call_math_transaction,
    _decode_math_result,
)
from eth_tester.utils.throws_contract import (
    _deploy_throws,
    _make_call_throws_transaction,
    _decode_throws_result,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
)

from evm.exceptions import (
    InvalidInstruction
)


@pytest.fixture
def eth_tester():
    if not is_pyevm_available():
        pytest.skip("PyEVM is not available")
    backend = PyEVMBackend()
    return EthereumTester(backend=backend)


class TestPyEVMBackendDirect(BaseTestBackendDirect):
    def test_can_estimate_gas_after_exception_raised_estimating_gas(self, eth_tester):
        self.skip_if_no_evm_execution()

        throws_address = _deploy_throws(eth_tester)
        call_will_throw_transaction = _make_call_throws_transaction(
            eth_tester,
            throws_address,
            'willThrow',
        )
        with pytest.raises(InvalidInstruction):
            eth_tester.estimate_gas(dissoc(call_will_throw_transaction, 'gas'))

        call_set_value_transaction = _make_call_throws_transaction(
            eth_tester,
            throws_address,
            'setValue',
            fn_args=(2,),
        )
        gas_estimation = eth_tester.estimate_gas(dissoc(call_set_value_transaction, 'gas'))
        assert gas_estimation
