from __future__ import absolute_import

import functools
import operator

from cytoolz.functoolz import (
    compose,
    curry,
)

from eth_utils import (
    keccak,
    decode_hex,
    encode_hex,
)

from web3.providers import (
    BaseProvider,
)


def not_implemented(*args, **kwargs):
    raise NotImplementedError("RPC method not implemented")


@curry
def call_eth_tester(fn_name, eth_tester, fn_args, **fn_kwargs):
    return getattr(eth_tester, fn_name)(*fn_args, **fn_kwargs)


def without_eth_tester(fn):
    @functools.wraps(fn)
    def inner(eth_tester, params):
        return fn(params)
    return inner


def static_return(value):
    def inner(*args, **kwargs):
        return value
    return inner


API_ENDPOINTS = {
    'web3': {
        'clientVersion': not_implemented,
        'sha3': without_eth_tester(compose(
            encode_hex,
            keccak,
            decode_hex,
            operator.itemgetter(0),
        )),
    },
    'net': {
        'version': not_implemented,
        'peerCount': not_implemented,
        'listening': not_implemented,
    },
    'eth': {
        'protocolVersion': not_implemented,
        'syncing': static_return(False),
        'coinbase': compose(
            operator.itemgetter(0),
            call_eth_tester('get_accounts'),
        ),
        'mining': static_return(False),
        'hashrate': static_return(0),
        'gasPrice': static_return(1),
        'accounts': call_eth_tester('get_accounts'),
        'blockNumber': compose(
            operator.itemgetter('number'),
            call_eth_tester('get_block_by_number', block_number='latest'),
        ),
        'getBalance': call_eth_tester('get_balance'),
        'getStorageAt': not_implemented,
        'getTransactionCount': call_eth_tester('get_nonce'),
        'getBlockTransactionCountByHash': not_implemented,
        'getBlockTransactionCountByNumber': not_implemented,
        'getUncleCountByBlockHash': not_implemented,
        'getUncleCountByBlockNumber': not_implemented,
        'getCode': call_eth_tester('get_code'),
        'sign': not_implemented,
        'sendTransaction': call_eth_tester('send_transaction'),
        'sendRawTransaction': not_implemented,
        'call': not_implemented,
        'estimateGas': not_implemented,
        'getBlockByHash': call_eth_tester('get_block_by_hash'),
        'getBlockByNumber': call_eth_tester('get_block_by_number'),
        'getTransactionByHash': call_eth_tester('get_transaction_by_hash'),
        'getTransactionByBlockHashAndIndex': not_implemented,
        'getTransactionByBlockNumberAndIndex': not_implemented,
        'getTransactionReceipt': call_eth_tester('get_transaction_receipt'),
        'getUncleByBlockHashAndIndex': not_implemented,
        'getUncleByBlockNumberAndIndex': not_implemented,
        'getCompilers': not_implemented,
        'compileLLL': not_implemented,
        'compileSolidity': not_implemented,
        'compileSerpent': not_implemented,
        'newFilter': not_implemented,
        'newBlockFilter': not_implemented,
        'newPendingTransactionFilter': not_implemented,
        'uninstallFilter': not_implemented,
        'getFilterChanges': not_implemented,
        'getFilterLogs': not_implemented,
        'getLogs': not_implemented,
        'getWork': not_implemented,
        'submitWork': not_implemented,
        'submitHashrate': not_implemented,
    },
    'db': {
        'putString': not_implemented,
        'getString': not_implemented,
        'putHex': not_implemented,
        'getHex': not_implemented,
    },
    'shh': {
        'post': not_implemented,
        'version': not_implemented,
        'newIdentity': not_implemented,
        'hasIdentity': not_implemented,
        'newGroup': not_implemented,
        'addToGroup': not_implemented,
        'newFilter': not_implemented,
        'uninstallFilter': not_implemented,
        'getFilterChanges': not_implemented,
        'getMessages': not_implemented,
    },
    'admin': {
        'addPeer': not_implemented,
        'datadir': not_implemented,
        'nodeInfo': not_implemented,
        'peers': not_implemented,
        'setSolc': not_implemented,
        'startRPC': not_implemented,
        'startWS': not_implemented,
        'stopRPC': not_implemented,
        'stopWS': not_implemented,
    },
    'debug': {
        'backtraceAt': not_implemented,
        'blockProfile': not_implemented,
        'cpuProfile': not_implemented,
        'dumpBlock': not_implemented,
        'gtStats': not_implemented,
        'getBlockRLP': not_implemented,
        'goTrace': not_implemented,
        'memStats': not_implemented,
        'seedHashSign': not_implemented,
        'setBlockProfileRate': not_implemented,
        'setHead': not_implemented,
        'stacks': not_implemented,
        'startCPUProfile': not_implemented,
        'startGoTrace': not_implemented,
        'stopCPUProfile': not_implemented,
        'stopGoTrace': not_implemented,
        'traceBlock': not_implemented,
        'traceBlockByNumber': not_implemented,
        'traceBlockByHash': not_implemented,
        'traceBlockFromFile': not_implemented,
        'traceTransaction': not_implemented,
        'verbosity': not_implemented,
        'vmodule': not_implemented,
        'writeBlockProfile': not_implemented,
        'writeMemProfile': not_implemented,
    },
    'miner': {
        'makeDAG': not_implemented,
        'setExtra': not_implemented,
        'setGasPrice': not_implemented,
        'start': not_implemented,
        'startAutoDAG': not_implemented,
        'stop': not_implemented,
        'stopAutoDAG': not_implemented,
    },
    'personal': {
        'ecRecover': not_implemented,
        'importRawKey': not_implemented,
        'listAccounts': not_implemented,
        'lockAccount': not_implemented,
        'newAccount': not_implemented,
        'unlockAccount': not_implemented,
        'sendTransaction': not_implemented,
        'sign': not_implemented,
    },
    'txpool': {
        'content': not_implemented,
        'inspect': not_implemented,
        'status': not_implemented,
    }
}


class EthereumTesterProvider(BaseProvider):
    ethereum_tester = None
    api_endpoints = None

    def __init__(self, ethereum_tester, api_endpoints=API_ENDPOINTS):
        self.ethereum_tester = ethereum_tester
        self.api_endpoints = api_endpoints

    def make_request(self, method, params):
        namespace, _, endpoint = method.partition('_')
        try:
            delegator = self.api_endpoints[namespace][endpoint]
        except KeyError:
            return {
                "error": "Unknown RPC Endpoint: {0}".format(method),
            }

        try:
            response = delegator(self.ethereum_tester, params)
        except NotImplementedError:
            return {
                "error": "RPC Endpoint has not been implemented: {0}".format(method),
            }
        else:
            return {
                'result': response,
            }

    def isConnected(self):
        return True
