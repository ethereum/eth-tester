from __future__ import absolute_import

import functools
import operator
import sys

from cytoolz.functoolz import (
    excepts,
    compose,
    curry,
)

from eth_utils import (
    is_null,
    keccak,
    decode_hex,
    encode_hex,
)

from web3.providers import (
    BaseProvider,
)

from eth_tester.exceptions import (
    BlockNotFound,
    FilterNotFound,
    TransactionNotFound,
)

from eth_tester.utils.formatting import (
    apply_formatter_if,
)

from .middleware import (
    ethereum_tester_middleware,
)


def not_implemented(*args, **kwargs):
    raise NotImplementedError("RPC method not implemented")


@curry
def call_eth_tester(fn_name, eth_tester, fn_args, fn_kwargs=None):
    if fn_kwargs is None:
        fn_kwargs = {}
    return getattr(eth_tester, fn_name)(*fn_args, **fn_kwargs)


def without_eth_tester(fn):
    @functools.wraps(fn)
    def inner(eth_tester, params):
        return fn(params)
    return inner


@curry
def preprocess_params(eth_tester, params, preprocessor_fn):
    return eth_tester, preprocessor_fn(params)


def static_return(value):
    def inner(*args, **kwargs):
        return value
    return inner


def client_version(eth_tester, params):
    # TODO: account for the backend that is in use.
    from eth_tester import __version__
    return "EthereumTester/{version}/{platform}/python{v.major}.{v.minor}.{v.micro}".format(
        version=__version__,
        v=sys.version_info,
        platform=sys.platform,
    )


@curry
def null_if_excepts(exc_type, fn):
    return excepts(
        exc_type,
        fn,
        static_return(None),
    )


null_if_block_not_found = null_if_excepts(BlockNotFound)
null_if_transaction_not_found = null_if_excepts(TransactionNotFound)
null_if_filter_not_found = null_if_excepts(FilterNotFound)
null_if_indexerror = null_if_excepts(IndexError)


@null_if_indexerror
@null_if_block_not_found
def get_transaction_by_block_hash_and_index(eth_tester, params):
    block_hash, transaction_index = params
    block = eth_tester.get_block_by_hash(block_hash, full_transactions=True)
    transaction = block['transactions'][transaction_index]
    return transaction


@null_if_indexerror
@null_if_block_not_found
def get_transaction_by_block_number_and_index(eth_tester, params):
    block_number, transaction_index = params
    block = eth_tester.get_block_by_number(block_number, full_transactions=True)
    transaction = block['transactions'][transaction_index]
    return transaction


def create_log_filter(eth_tester, params):
    filter_params = params[0]
    filter_id = eth_tester.create_log_filter(**filter_params)
    return filter_id


API_ENDPOINTS = {
    'web3': {
        'clientVersion': client_version,
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
            call_eth_tester('get_block_by_number', fn_kwargs={'block_number': 'latest'}),
        ),
        'getBalance': call_eth_tester('get_balance'),
        'getStorageAt': not_implemented,
        'getTransactionCount': call_eth_tester('get_nonce'),
        'getBlockTransactionCountByHash': null_if_block_not_found(compose(
            len,
            operator.itemgetter('transactions'),
            call_eth_tester('get_block_by_hash'),
        )),
        'getBlockTransactionCountByNumber': null_if_block_not_found(compose(
            len,
            operator.itemgetter('transactions'),
            call_eth_tester('get_block_by_number'),
        )),
        'getUncleCountByBlockHash': not_implemented,
        'getUncleCountByBlockNumber': not_implemented,
        'getCode': call_eth_tester('get_code'),
        'sign': not_implemented,
        'sendTransaction': call_eth_tester('send_transaction'),
        'sendRawTransaction': not_implemented,
        'call': call_eth_tester('call'),  # TODO: untested
        'estimateGas': call_eth_tester('estimate_gas'),  # TODO: untested
        'getBlockByHash': null_if_block_not_found(call_eth_tester('get_block_by_hash')),
        'getBlockByNumber': null_if_block_not_found(call_eth_tester('get_block_by_number')),
        'getTransactionByHash': null_if_transaction_not_found(
            call_eth_tester('get_transaction_by_hash')
        ),
        'getTransactionByBlockHashAndIndex': get_transaction_by_block_hash_and_index,
        'getTransactionByBlockNumberAndIndex': get_transaction_by_block_number_and_index,
        'getTransactionReceipt': null_if_transaction_not_found(compose(
            apply_formatter_if(
                static_return(None),
                compose(is_null, operator.itemgetter('block_number')),
            ),
            call_eth_tester('get_transaction_receipt'),
        )),
        'getUncleByBlockHashAndIndex': not_implemented,
        'getUncleByBlockNumberAndIndex': not_implemented,
        'getCompilers': not_implemented,
        'compileLLL': not_implemented,
        'compileSolidity': not_implemented,
        'compileSerpent': not_implemented,
        'newFilter': create_log_filter,
        'newBlockFilter': call_eth_tester('create_block_filter'),
        'newPendingTransactionFilter': call_eth_tester('create_pending_transaction_filter'),
        'uninstallFilter': excepts(
            FilterNotFound,
            compose(
                is_null,
                call_eth_tester('delete_filter'),
            ),
            static_return(False),
        ),
        'getFilterChanges': null_if_filter_not_found(call_eth_tester('get_only_filter_changes')),
        'getFilterLogs': null_if_filter_not_found(call_eth_tester('get_all_filter_logs')),
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
    middlewares = [ethereum_tester_middleware]
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
