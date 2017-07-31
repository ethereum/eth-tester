import itertools
import operator

from cytoolz.itertoolz import (
    remove,
)
from cytoolz.functoolz import (
    compose,
    excepts,
    partial,
)

from eth_utils import (
    is_integer,
)

from eth_tester.exceptions import (
    BlockNotFound,
    FilterNotFound,
    SnapshotNotFound,
    TransactionNotFound,
    ValidationError,
)

from eth_tester.backends import (
    get_tester_backend,
)

from eth_tester.utils.filters import (
    Filter,
    check_if_log_matches,
)

from .validation import (
    validate_timestamp,
)


def backend_proxy_method(backend_method_name):
    def proxy_method(self, *args, **kwargs):
        backend_method = getattr(self.backend, backend_method_name)
        return backend_method(*args, **kwargs)
    return proxy_method


def get_default_fork_blocks():
    return {
        'FORK_HOMESTEAD': 0,
        'FORK_DAO': 0,
        'FORK_ANTI_DOS': 0,
        'FORK_STATE_CLEANUP': 0,
    }


class EthereumTester(object):
    backend = None
    auto_mine_transactions = None
    auto_mine_interval = None
    fork_blocks = None

    def __init__(self,
                 backend=None,
                 auto_mine_transactions=True,
                 auto_mine_interval=None,
                 fork_blocks=None):
        if backend is None:
            backend = get_tester_backend()

        if fork_blocks is None:
            fork_blocks = get_default_fork_blocks()

        self.backend = backend
        self.auto_mine_transactions = auto_mine_transactions
        self.auto_mine_interval = auto_mine_interval
        self.fork_blocks = fork_blocks

        self._reset_local_state()

    #
    # Private API
    #
    def _reset_local_state(self):
        # fork blocks
        for fork_name, fork_block in self.fork_blocks.items():
            self.set_fork_block(fork_name, fork_block)

        # filter tracking
        self._filter_counter = itertools.count()
        self._log_filters = {}
        self._block_filters = {}
        self._pending_transaction_filters = {}

        # snapshot tracking
        self._snapshot_counter = itertools.count()
        self._snapshots = {}

    #
    # Fork Rules
    #
    set_fork_block = backend_proxy_method('set_fork_block')
    get_fork_block = backend_proxy_method('get_fork_block')

    #
    # Time Traveling
    #
    def time_travel(self, to_timestamp):
        validate_timestamp(to_timestamp)
        # make sure we are not traveling back in time as this is not possible.
        current_timestamp = self.get_block_by_number('pending')['timestamp']
        if to_timestamp <= current_timestamp:
            raise ValidationError(
                "Space time continuum distortion detected.  Traveling backwards "
                "in time violates interdimensional ordinance 31415-926."
            )
        self.backend.time_travel(to_timestamp)

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
    def enable_auto_mine_transactions(self):
        self.auto_mine_transactions = True

    def disable_auto_mine_transactions(self):
        self.auto_mine_transactions = False

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
        if self.auto_mine_transactions:
            self.mine_block()

        return transaction_hash

    call = backend_proxy_method('call')
    estimate_gas = backend_proxy_method('estimate_gas')

    #
    # Snapshot and Revert
    #
    def take_snapshot(self):
        snapshot = self.backend.take_snapshot()
        snapshot_id = next(self._snapshot_counter)
        self._snapshots[snapshot_id] = snapshot
        return snapshot_id

    def revert_to_snapshot(self, snapshot_id):
        try:
            snapshot = self._snapshots[snapshot_id]
        except KeyError:
            raise SnapshotNotFound("No snapshot found for id: {0}".format(snapshot_id))
        else:
            self.backend.revert_to_snapshot(snapshot)

        for block_filter in self._block_filters.values():
            self._revert_block_filter(block_filter)
        for pending_transaction_filter in self._pending_transaction_filters.values():
            self._revert_pending_transaction_filter(pending_transaction_filter)
        for log_filter in self._log_filters.values():
            self._revert_log_filter(log_filter)

    def _revert_block_filter(self, filter):
        is_valid_block_hash = excepts(
            (BlockNotFound,),
            compose(bool, self.get_block_by_hash),
            lambda v: False,
        )
        values_to_remove = remove(is_valid_block_hash, filter.get_all())
        filter.remove(*values_to_remove)

    def _revert_pending_transaction_filter(self, filter):
        is_valid_transaction_hash = excepts(
            (TransactionNotFound,),
            compose(bool, self.get_transaction_by_hash),
            lambda v: False,
        )
        values_to_remove = remove(is_valid_transaction_hash, filter.get_all())
        filter.remove(*values_to_remove)

    def _revert_log_filter(self, filter):
        is_valid_transaction_hash = excepts(
            (TransactionNotFound,),
            compose(
                bool,
                self.get_transaction_by_hash,
                operator.itemgetter('transaction_hash'),
            ),
            lambda v: False,
        )
        values_to_remove = remove(is_valid_transaction_hash, filter.get_all())
        filter.remove(*values_to_remove)

    def reset_to_genesis(self):
        self.backend.reset_to_genesis()
        self._reset_local_state()

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
