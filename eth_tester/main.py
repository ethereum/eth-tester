from eth_tester.exceptions import (
    TransactionNotFound,
)


def backend_proxy_method(backend_method_name):
    def proxy_method(self, *args, **kwargs):
        backend_method = getattr(self.backend, backend_method_name)
        return backend_method(*args, **kwargs)
    return proxy_method


def get_default_config():
    return {
        'auto_mine_transactions': True,
        'auto_mine_interval': None,
    }


def get_tester_backend():
    raise NotImplementedError("Not yet implemented")


class EthereumTester(object):
    backend = None

    def __init__(self, backend=None, config=None):
        if backend is None:
            backend = get_tester_backend()

        if config is None:
            config = get_default_config()

        self.backend = backend
        self.config = config

    def configure(self, **kwargs):
        for key, value in kwargs.items():
            if key in self.config:
                self.config[key] = value
            else:
                raise KeyError(
                    "Cannot set config values that are not already present in "
                    "config"
                )

    get_accounts = backend_proxy_method('get_accounts')
    get_balance = backend_proxy_method('get_balance')
    get_nonce = backend_proxy_method('get_nonce')
    get_latest_block = backend_proxy_method('get_latest_block')
    get_transaction_by_hash = backend_proxy_method('get_transaction_by_hash')
    get_block_by_number = backend_proxy_method('get_block_by_number')
    get_block_by_hash = backend_proxy_method('get_block_by_hash')
    get_transaction_receipt = backend_proxy_method('get_transaction_receipt')
    mine_blocks = backend_proxy_method('mine_blocks')

    def mine_block(self, coinbase=None):
        return self.mine_blocks(1, coinbase=coinbase)[0]

    def send_transaction(self, transaction):
        transaction_hash = self.backend.send_transaction(transaction)
        if self.config['auto_mine_transactions']:
            self.mine_block()
        return transaction_hash

    def get_transaction_receipt(self, transaction_hash):
        try:
            return self.backend.get_transaction_receipt(transaction_hash)
        except TransactionNotFound:
            return None
