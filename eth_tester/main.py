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
