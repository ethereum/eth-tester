import pytest


from eth_tester import (
    EthereumTester,
    MockBackend,
)

from eth_tester.web3 import (
    EthereumTesterProvider,
    ethereum_tester_middleware,
)

from eth_tester.backends.pyethereum.utils import (
    is_pyethereum16_available,
)

from eth_tester.utils.backend_testing import (
    BaseTestBackendDirect,
    BaseTestBackendFuzz,
    EVMStateFuzzer,
)


@pytest.fixture
def eth_tester():
    if not is_pyethereum16_available():
        pytest.skip("PyEthereum >=1.6.0,<1.7.0 not available")
    backend = PyEthereum16Backend()
    return EthereumTester(backend=backend)


@pytest.fixture
def eth_tester():
    _eth_tester = EthereumTester(backend=MockBackend())
    return _eth_tester


def is_web3_available():
    try:
        import web3
    except ImportError:
        return False
    else:
        return True


@pytest.fixture
def web3_provider(eth_tester):
    return EthereumTesterProvider(eth_tester)


@pytest.fixture
def web3(web3_provider):
    if not is_web3_available():
        pytest.skip('Web3 is not available')
    from web3 import Web3
    from web3.middleware import attrdict_middleware
    web3 = Web3(web3_provider, middlewares=[attrdict_middleware, ethereum_tester_middleware])
    return web3
