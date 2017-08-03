class BaseProvider(object):
    """
    Copied from the web3.py codebase for now until the provider logic can be
    extracted from web3.
    """
    def make_request(self, method, params):
        raise NotImplementedError("Providers must implement this method")

    def isConnected(self):
        raise NotImplementedError("Providers must implement this method")


API_ENDPOINTS = {
    'web3': {
        'clientVersion': NotImplementedError("RPC method not implemented"),
        'sha3': NotImplementedError("RPC method not implemented"),
    },
    'net': {
        'version': NotImplementedError("RPC method not implemented"),
        'peerCount': NotImplementedError("RPC method not implemented"),
        'listening': NotImplementedError("RPC method not implemented"),
    },
    'eth': {
        'protocolVersion': NotImplementedError("RPC method not implemented"),
        'syncing': NotImplementedError("RPC method not implemented"),
        'coinbase': NotImplementedError("RPC method not implemented"),
        'mining': NotImplementedError("RPC method not implemented"),
        'hashrate': NotImplementedError("RPC method not implemented"),
        'gasPrice': NotImplementedError("RPC method not implemented"),
        'accounts': NotImplementedError("RPC method not implemented"),
        'blockNumber': NotImplementedError("RPC method not implemented"),
        'getBalance': NotImplementedError("RPC method not implemented"),
        'getStorageAt': NotImplementedError("RPC method not implemented"),
        'getTransactionCount': NotImplementedError("RPC method not implemented"),
        'getBlockTransactionCountByHash': NotImplementedError("RPC method not implemented"),
        'getBlockTransactionCountByNumber': NotImplementedError("RPC method not implemented"),
        'getUncleCountByBlockHash': NotImplementedError("RPC method not implemented"),
        'getUncleCountByBlockNumber': NotImplementedError("RPC method not implemented"),
        'getCode': NotImplementedError("RPC method not implemented"),
        'sign': NotImplementedError("RPC method not implemented"),
        'sendTransaction': NotImplementedError("RPC method not implemented"),
        'sendRawTransaction': NotImplementedError("RPC method not implemented"),
        'call': NotImplementedError("RPC method not implemented"),
        'estimateGas': NotImplementedError("RPC method not implemented"),
        'getBlockByHash': NotImplementedError("RPC method not implemented"),
        'getBlockByNumber': NotImplementedError("RPC method not implemented"),
        'getTransactionByHash': NotImplementedError("RPC method not implemented"),
        'getTransactionByBlockHashAndIndex': NotImplementedError("RPC method not implemented"),
        'getTransactionByBlockNumberAndIndex': NotImplementedError("RPC method not implemented"),
        'getTransactionReceipt': NotImplementedError("RPC method not implemented"),
        'getUncleByBlockHashAndIndex': NotImplementedError("RPC method not implemented"),
        'getUncleByBlockNumberAndIndex': NotImplementedError("RPC method not implemented"),
        'getCompilers': NotImplementedError("RPC method not implemented"),
        'compileLLL': NotImplementedError("RPC method not implemented"),
        'compileSolidity': NotImplementedError("RPC method not implemented"),
        'compileSerpent': NotImplementedError("RPC method not implemented"),
        'newFilter': NotImplementedError("RPC method not implemented"),
        'newBlockFilter': NotImplementedError("RPC method not implemented"),
        'newPendingTransactionFilter': NotImplementedError("RPC method not implemented"),
        'uninstallFilter': NotImplementedError("RPC method not implemented"),
        'getFilterChanges': NotImplementedError("RPC method not implemented"),
        'getFilterLogs': NotImplementedError("RPC method not implemented"),
        'getLogs': NotImplementedError("RPC method not implemented"),
        'getWork': NotImplementedError("RPC method not implemented"),
        'submitWork': NotImplementedError("RPC method not implemented"),
        'submitHashrate': NotImplementedError("RPC method not implemented"),
    },
    'db': {
        'putString': NotImplementedError("RPC method not implemented"),
        'getString': NotImplementedError("RPC method not implemented"),
        'putHex': NotImplementedError("RPC method not implemented"),
        'getHex': NotImplementedError("RPC method not implemented"),
    },
    'shh': {
        'post': NotImplementedError("RPC method not implemented"),
        'version': NotImplementedError("RPC method not implemented"),
        'newIdentity': NotImplementedError("RPC method not implemented"),
        'hasIdentity': NotImplementedError("RPC method not implemented"),
        'newGroup': NotImplementedError("RPC method not implemented"),
        'addToGroup': NotImplementedError("RPC method not implemented"),
        'newFilter': NotImplementedError("RPC method not implemented"),
        'uninstallFilter': NotImplementedError("RPC method not implemented"),
        'getFilterChanges': NotImplementedError("RPC method not implemented"),
        'getMessages': NotImplementedError("RPC method not implemented"),
    },
    'admin': {
        'addPeer': NotImplementedError("RPC method not implemented"),
        'datadir': NotImplementedError("RPC method not implemented"),
        'nodeInfo': NotImplementedError("RPC method not implemented"),
        'peers': NotImplementedError("RPC method not implemented"),
        'setSolc': NotImplementedError("RPC method not implemented"),
        'startRPC': NotImplementedError("RPC method not implemented"),
        'startWS': NotImplementedError("RPC method not implemented"),
        'stopRPC': NotImplementedError("RPC method not implemented"),
        'stopWS': NotImplementedError("RPC method not implemented"),
    },
    'debug': {
        'backtraceAt': NotImplementedError("RPC method not implemented"),
        'blockProfile': NotImplementedError("RPC method not implemented"),
        'cpuProfile': NotImplementedError("RPC method not implemented"),
        'dumpBlock': NotImplementedError("RPC method not implemented"),
        'gtStats': NotImplementedError("RPC method not implemented"),
        'getBlockRLP': NotImplementedError("RPC method not implemented"),
        'goTrace': NotImplementedError("RPC method not implemented"),
        'memStats': NotImplementedError("RPC method not implemented"),
        'seedHashSign': NotImplementedError("RPC method not implemented"),
        'setBlockProfileRate': NotImplementedError("RPC method not implemented"),
        'setHead': NotImplementedError("RPC method not implemented"),
        'stacks': NotImplementedError("RPC method not implemented"),
        'startCPUProfile': NotImplementedError("RPC method not implemented"),
        'startGoTrace': NotImplementedError("RPC method not implemented"),
        'stopCPUProfile': NotImplementedError("RPC method not implemented"),
        'stopGoTrace': NotImplementedError("RPC method not implemented"),
        'traceBlock': NotImplementedError("RPC method not implemented"),
        'traceBlockByNumber': NotImplementedError("RPC method not implemented"),
        'traceBlockByHash': NotImplementedError("RPC method not implemented"),
        'traceBlockFromFile': NotImplementedError("RPC method not implemented"),
        'traceTransaction': NotImplementedError("RPC method not implemented"),
        'verbosity': NotImplementedError("RPC method not implemented"),
        'vmodule': NotImplementedError("RPC method not implemented"),
        'writeBlockProfile': NotImplementedError("RPC method not implemented"),
        'writeMemProfile': NotImplementedError("RPC method not implemented"),
    },
    'miner': {
        'makeDAG': NotImplementedError("RPC method not implemented"),
        'setExtra': NotImplementedError("RPC method not implemented"),
        'setGasPrice': NotImplementedError("RPC method not implemented"),
        'start': NotImplementedError("RPC method not implemented"),
        'startAutoDAG': NotImplementedError("RPC method not implemented"),
        'stop': NotImplementedError("RPC method not implemented"),
        'stopAutoDAG': NotImplementedError("RPC method not implemented"),
    },
    'personal': {
        'ecRecover': NotImplementedError("RPC method not implemented"),
        'importRawKey': NotImplementedError("RPC method not implemented"),
        'listAccounts': NotImplementedError("RPC method not implemented"),
        'lockAccount': NotImplementedError("RPC method not implemented"),
        'newAccount': NotImplementedError("RPC method not implemented"),
        'unlockAccount': NotImplementedError("RPC method not implemented"),
        'sendTransaction': NotImplementedError("RPC method not implemented"),
        'sign': NotImplementedError("RPC method not implemented"),
    },
    'txpool': {
        'content': NotImplementedError("RPC method not implemented"),
        'inspect': NotImplementedError("RPC method not implemented"),
        'status': NotImplementedError("RPC method not implemented"),
    }
}


class EthereumTesterProvider(object):
    ethereum_tester = None

    def __init__(self, ethereum_tester):
        self.ethereum_tester = ethereum_tester

    def make_request(self, method, params):
        assert False

    def isConnected(self):
        return True
