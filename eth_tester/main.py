import itertools

from toolz.functoolz import (
    partial,
)

from eth_utils import (
    is_integer,
)

from eth_tester.exceptions import (
    TransactionNotFound,
    FilterNotFound,
)

from eth_tester.backends import (
    get_tester_backend,
)

from eth_tester.utils.filters import (
    Filter,
    check_if_log_matches,
)


def backend_proxy_method(backend_method_name):
    def proxy_method(self, *args, **kwargs):
        backend_method = getattr(self.backend, backend_method_name)
        return backend_method(*args, **kwargs)
    return proxy_method


def get_default_config():
    return {
        'auto_mine_transactions': True,
        'auto_mine_interval': None,  # TODO
        'fork_homestead_block': 0,  # TODO
        'fork_dao_block': 0,  # TODO
        'fork_anti_dos_block': 0,  # TODO
        'fork_state_cleanup_block': 0,  # TODO
    }


class EthereumTester(object):
    backend = None

    def __init__(self, backend=None, config=None):
        if backend is None:
            backend = get_tester_backend()

        if config is None:
            config = get_default_config()

        self.backend = backend
        self.config = config

        #
        self._filter_counter = itertools.count()
        self._log_filters = {}
        self._block_filters = {}
        self._pending_transaction_filters = {}

    #
    # Configuration
    #
    def configure(self, **kwargs):
        for key, value in kwargs.items():
            if key in self.config:
                self.config[key] = value
            else:
                raise KeyError(
                    "Cannot set config values that are not already present in "
                    "config"
                )

    #
    # Configuration
    #
    def time_travel(self, to_timestamp):
        # TODO
        raise NotImplementedError("not yet impleented")

    #
    # Accounts
    #
    get_accounts = backend_proxy_method('get_accounts')
    get_balance = backend_proxy_method('get_balance')
    get_nonce = backend_proxy_method('get_nonce')

    #
    # Blocks, Transactions, Receipts
    #
    get_transaction_by_hash = backend_proxy_method('get_transaction_by_hash')
    get_block_by_number = backend_proxy_method('get_block_by_number')
    get_block_by_hash = backend_proxy_method('get_block_by_hash')

    def get_transaction_receipt(self, transaction_hash):
        try:
            return self.backend.get_transaction_receipt(transaction_hash)
        except TransactionNotFound:
            return None

    #
    # Mining
    #
    def mine_blocks(self, num_blocks=1, coinbase=None):
        block_hashes = self.backend.mine_blocks(num_blocks, coinbase)
        assert len(block_hashes) == num_blocks

        # feed the block hashes to any block filters
        for block_hash in block_hashes:
            block = self.get_block_by_hash(block_hash)

            for _, block_filter in self._block_filters.items():
                block_filter.add(block_hash)

            self._process_block_logs(block)

        return block_hashes

    def mine_block(self, coinbase=None):
        return self.mine_blocks(1, coinbase=coinbase)[0]

    #
    # Transaction Sending
    #
    def send_transaction(self, transaction):
        transaction_hash = self.backend.send_transaction(transaction)

        # feed the transaction hash to any pending transaction filters.
        for _, filter in self._pending_transaction_filters.items():
            filter.add(transaction_hash)

        if self._log_filters:
            receipt = self.backend.get_transaction_receipt(transaction_hash)
            for log_entry in receipt['logs']:
                for _, filter in self._log_filters.items():
                    filter.add(log_entry)

        # mine the transaction if auto-transaction-mining is enabled.
        if self.config['auto_mine_transactions']:
            self.mine_block()

        return transaction_hash

    def call(self, transaction):
        # TODO
        raise NotImplementedError("not yet implemented")

    def estimate_gas(self, transaction):
        # TODO
        raise NotImplementedError("not yet implemented")

    #
    # Snapshot and Revert
    #
    def take_snapshot(self):
        # TODO
        raise NotImplementedError("not yet implemented")

    def revert_to_snapshot(self):
        # TODO
        raise NotImplementedError("not yet implemented")

    def reset_to_genesis(self):
        # TODO
        raise NotImplementedError("not yet implemented")

    #
    # Filters
    #
    def create_block_filter(self):
        filter_id = next(self._filter_counter)
        self._block_filters[filter_id] = Filter(filter_params=None)
        return filter_id

    def create_pending_transaction_filter(self, *args, **kwargs):
        filter_id = next(self._filter_counter)
        self._pending_transaction_filters[filter_id] = Filter(filter_params=None)
        return filter_id

    def create_log_filter(self, from_block=None, to_block=None, address=None, topics=None):
        filter_id = next(self._filter_counter)
        filter_params = {
            'from_block': from_block,
            'to_block': to_block,
            'addresses': address,
            'topics': topics,
        }
        filter_fn = partial(
            check_if_log_matches,
            **filter_params
        )
        self._log_filters[filter_id] = Filter(filter_params=filter_params, filter_fn=filter_fn)
        if is_integer(from_block):
            if is_integer(to_block):
                upper_bound = to_block
            else:
                upper_bound = self.get_block_by_number('pending')['number']
            for block_number in range(from_block, upper_bound):
                block = self.get_block_by_number(block_number)
                self._process_block_logs(block)

        return filter_id

    def delete_filter(self, filter_id):
        if filter_id in self._block_filters:
            del self._block_filters[filter_id]
        elif filter_id in self._pending_transaction_filters:
            del self._pending_transaction_filters[filter_id]
        elif filter_id in self._log_filters:
            del self._log_filters[filter_id]
        else:
            raise FilterNotFound("Unknown filter id")

    def get_only_filter_changes(self, filter_id):
        if filter_id in self._block_filters:
            filter = self._block_filters[filter_id]
        elif filter_id in self._pending_transaction_filters:
            filter = self._pending_transaction_filters[filter_id]
        elif filter_id in self._log_filters:
            filter = self._log_filters[filter_id]
        else:
            raise FilterNotFound("Unknown filter id")
        return filter.get_changes()

    def get_all_filter_logs(self, filter_id):
        if filter_id in self._block_filters:
            filter = self._block_filters[filter_id]
        elif filter_id in self._pending_transaction_filters:
            filter = self._pending_transaction_filters[filter_id]
        elif filter_id in self._log_filters:
            filter = self._log_filters[filter_id]
        else:
            raise FilterNotFound("Unknown filter id")
        return filter.get_all()

    #
    # Private API
    #
    def _process_block_logs(self, block):
        for _, filter in self._log_filters.items():
            for transaction_hash in block['transactions']:
                receipt = self.get_transaction_receipt(transaction_hash)
                for log_entry in receipt['logs']:
                    filter.add(log_entry)
