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


@pytest.fixture
def eth_tester():
    if not is_pyevm_available():
        pytest.skip("PyEVM is not available")
    backend = PyEVMBackend()
    return EthereumTester(backend=backend)


class TestPyEVMBackendDirect(BaseTestBackendDirect):
        pass
