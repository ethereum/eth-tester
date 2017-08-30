import pytest


def test_web3_unknown_method(web3):
    with pytest.raises(ValueError) as err:
        web3.manager.request_blocking('unknown_methodName', [])
    assert 'unknown' in str(err).lower()


def not_implemented(*args, **kwargs):
    raise NotImplementedError('not implemented')


def test_web3_not_implemented_method(web3):
    web3.currentProvider.api_endpoints = {'not': {'implementedMethod': not_implemented}}
    with pytest.raises(ValueError) as err:
        web3.manager.request_blocking('not_implementedMethod', [])
    assert 'implemented' in str(err).lower()
