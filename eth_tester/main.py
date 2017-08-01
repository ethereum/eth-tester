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
    get_chain_backend,
)
from eth_tester.validation import (
    get_input_validator,
    get_output_validator,
)

from eth_tester.utils.filters import (
    Filter,
    check_if_log_matches,
)


def backend_proxy_method(backend_method_name):
    def proxy_method(self, *args, **kwargs):
        backend_method = getattr(self.chain_backend, backend_method_name)
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
                 input_validator=None,
                 output_validator=None,
                 auto_mine_transactions=True,
                 auto_mine_interval=None,
                 fork_blocks=None):
        if backend is None:
            backend = get_chain_backend()

        if input_validator is None:
            input_validator = get_input_validator()

        if output_validator is None:
            output_validator = get_output_validator()

        if fork_blocks is None:
            fork_blocks = get_default_fork_blocks()

        self.backend = backend
        self.input_validator = input_validator
        self.output_validator = output_validator

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
        self.input_validator.validate_timestamp(to_timestamp)
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
    # TODO: validate
    get_accounts = backend_proxy_method('get_accounts')
    # TODO: validate
    get_balance = backend_proxy_method('get_balance')
    # TODO: validate
    get_nonce = backend_proxy_method('get_nonce')

    #
    # Blocks, Transactions, Receipts
    #
    # TODO: validate
    get_transaction_by_hash = backend_proxy_method('get_transaction_by_hash')

    def get_block_by_number(self, block_number="latest"):
        self.input_validator.validate_block_number(block_number)
        # TODO: validate
        return self.backend.get_block_by_number(block_number)

    def get_block_by_hash(self, block_hash):
        self.input_validator.validate_block_hash(block_hash)
        # TODO: validate
        return self.backend.get_block_by_hash(block_hash)

    def get_transaction_receipt(self, transaction_hash):
        self.input_validator.validate_transaction_hash(transaction_hash)
        try:
            # TODO: validate
            return self.backend.get_transaction_receipt(transaction_hash)
        except TransactionNotFound:
            # TODO: don't return None
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

        for block_hash in block_hashes:
            self.output_validator.validate_block_hash(block_hash)
        return block_hashes

    def mine_block(self, coinbase=None):
        block_hash = self.mine_blocks(1, coinbase=coinbase)[0]
        self.output_validator.validate_block_hash(block_hash)
        return block_hash

    #
    # Private mining API
    #
    def _process_block_logs(self, block):
        for _, filter in self._log_filters.items():
            for transaction_hash in block['transactions']:
                receipt = self.get_transaction_receipt(transaction_hash)
                for log_entry in receipt['logs']:
                    filter.add(log_entry)

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

        # TODO: validate
        return transaction_hash

    # TODO: validate input & output
    call = backend_proxy_method('call')
    # TODO: validate input & output
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

    def reset_to_genesis(self):
        self.backend.reset_to_genesis()
        self._reset_local_state()

    #
    # Private filter API
    #
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

    #
    # Filters
    #
    def create_block_filter(self):
        filter_id = next(self._filter_counter)
        self._block_filters[filter_id] = Filter(filter_params=None)
        return filter_id

    def create_pending_transaction_filter(self):
        filter_id = next(self._filter_counter)
        self._pending_transaction_filters[filter_id] = Filter(filter_params=None)
        return filter_id

    def create_log_filter(self, from_block=None, to_block=None, address=None, topics=None):
        self.input_validator.validate_filter_params(
            from_block=from_block,
            to_block=to_block,
            address=address,
            topics=topics,
        )

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
        self.input_validator.validate_filter_id(filter_id)

        if filter_id in self._block_filters:
            del self._block_filters[filter_id]
        elif filter_id in self._pending_transaction_filters:
            del self._pending_transaction_filters[filter_id]
        elif filter_id in self._log_filters:
            del self._log_filters[filter_id]
        else:
            raise FilterNotFound("Unknown filter id")

    def get_only_filter_changes(self, filter_id):
        self.input_validator.validate_filter_id(filter_id)

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
        self.input_validator.validate_filter_id(filter_id)

        if filter_id in self._block_filters:
            filter = self._block_filters[filter_id]
        elif filter_id in self._pending_transaction_filters:
            filter = self._pending_transaction_filters[filter_id]
        elif filter_id in self._log_filters:
            filter = self._log_filters[filter_id]
        else:
            raise FilterNotFound("Unknown filter id")
        return filter.get_all()
