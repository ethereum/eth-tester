import operator


class BaseProvider(object):
    """
    Copied from the web3.py codebase for now until the provider logic can be
    extracted from web3.
    """
    def make_request(self, method, params):
        raise NotImplementedError("Providers must implement this method")

    def isConnected(self):
        raise NotImplementedError("Providers must implement this method")


def not_implemented(*args, **kwargs):
    raise NotImplementedError("RPC method not implemented")


API_ENDPOINTS = {
    'web3': {
        'clientVersion': not_implemented,
        'sha3': not_implemented,
    },
    'net': {
        'version': not_implemented,
        'peerCount': not_implemented,
        'listening': not_implemented,
    },
    'eth': {
        'protocolVersion': not_implemented,
        'syncing': not_implemented,
        'coinbase': not_implemented,
        'mining': not_implemented,
        'hashrate': not_implemented,
        'gasPrice': not_implemented,
        'accounts': operator.methodcaller('get_accounts'),
        'blockNumber': not_implemented,
        'getBalance': not_implemented,
        'getStorageAt': not_implemented,
        'getTransactionCount': not_implemented,
        'getBlockTransactionCountByHash': not_implemented,
        'getBlockTransactionCountByNumber': not_implemented,
        'getUncleCountByBlockHash': not_implemented,
        'getUncleCountByBlockNumber': not_implemented,
        'getCode': not_implemented,
        'sign': not_implemented,
        'sendTransaction': not_implemented,
        'sendRawTransaction': not_implemented,
        'call': not_implemented,
        'estimateGas': not_implemented,
        'getBlockByHash': not_implemented,
        'getBlockByNumber': not_implemented,
        'getTransactionByHash': not_implemented,
        'getTransactionByBlockHashAndIndex': not_implemented,
        'getTransactionByBlockNumberAndIndex': not_implemented,
        'getTransactionReceipt': not_implemented,
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


class EthereumTesterProvider(object):
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
            response = delegator(self.ethereum_tester)
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
