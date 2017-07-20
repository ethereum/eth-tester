def backend_proxy_method(backend_method_name):
    def proxy_method(self, *args, **kwargs):
        backend_method = getattr(self.backend, backend_method_name)
        return backend_method(*args, **kwargs)
    return proxy_method


class EthereumTester(object):
    backend = None

    def __init__(self, backend):
        self.backend = backend

    get_accounts = backend_proxy_method('get_accounts')
    get_balance = backend_proxy_method('get_balance')
    get_nonce = backend_proxy_method('get_nonce')
    send_transaction = backend_proxy_method('send_transaction')
    get_latest_block = backend_proxy_method('get_latest_block')
    get_transaction_by_hash = backend_proxy_method('get_transaction_by_hash')
    get_block_by_number = backend_proxy_method('get_block_by_number')
    get_block_by_hash = backend_proxy_method('get_block_by_hash')
    get_transaction_receipt = backend_proxy_method('get_transaction_receipt')
    mine_blocks = backend_proxy_method('mine_blocks')

    def mine_block(self, coinbase=None):
        return self.mine_blocks(1, coinbase=coinbase)
