from __future__ import unicode_literals

import collections
import itertools
import operator
import time

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
    is_same_address,
    to_tuple,
)

from eth_tester.exceptions import (
    AccountLocked,
    BlockNotFound,
    FilterNotFound,
    SnapshotNotFound,
    TransactionNotFound,
    ValidationError,
)

from eth_tester.normalization import (
    get_normalizer_backend,
)
from eth_tester.backends import (
    get_chain_backend,
)
from eth_tester.validation import (
    get_validator,
)

from eth_tester.utils.accounts import (
    private_key_to_address,
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


def get_default_fork_blocks():
    return {
        'FORK_HOMESTEAD': 0,
        'FORK_DAO': 0,
        'FORK_ANTI_DOS': 0,
        'FORK_STATE_CLEANUP': 0,
    }


class EthereumTester(object):
    backend = None

    validator = None
    normalizer = None

    fork_blocks = None

    auto_mine_transactions = None

    def __init__(self,
                 backend=None,
                 validator=None,
                 normalizer=None,
                 auto_mine_transactions=True,
                 fork_blocks=None):
        if backend is None:
            backend = get_chain_backend()

        if validator is None:
            validator = get_validator()

        if normalizer is None:
            normalizer = get_normalizer_backend()

        if fork_blocks is None:
            fork_blocks = get_default_fork_blocks()

        self.backend = backend
        self.validator = validator
        self.normalizer = normalizer

        self.auto_mine_transactions = auto_mine_transactions

        for fork_name, fork_block in fork_blocks.items():
            self.set_fork_block(fork_name, fork_block)

        self._reset_local_state()

    #
    # Private API
    #
    _filter_counter = None
    _log_filters = None
    _block_filters = None
    _pending_transaction_filters = None

    _snapshot_counter = None
    _snapshots = None

    _account_passwords = None
    _account_unlock = None

    def _reset_local_state(self):
        # filter tracking
        self._filter_counter = itertools.count()
        self._log_filters = {}
        self._block_filters = {}
        self._pending_transaction_filters = {}

        # snapshot tracking
        self._snapshot_counter = itertools.count()
        self._snapshots = {}

        # raw accounts
        self._account_passwords = {}
        self._account_unlock = collections.defaultdict(lambda: False)

    #
    # Fork Rules
    #
    set_fork_block = backend_proxy_method('set_fork_block')
    get_fork_block = backend_proxy_method('get_fork_block')

    #
    # Time Traveling
    #
    def time_travel(self, to_timestamp):
        self.validator.validate_inbound_timestamp(to_timestamp)
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
    def get_accounts(self):
        raw_accounts = self.backend.get_accounts()
        self.validator.validate_outbound_accounts(raw_accounts)
        accounts = self.normalizer.normalize_outbound_account_list(raw_accounts)
        return accounts

    def add_account(self, private_key, password=None):
        # TODO: validation
        self.validator.validate_inbound_private_key(private_key)
        raw_private_key = self.normalizer.normalize_inbound_private_key(private_key)
        raw_account = private_key_to_address(raw_private_key)
        account = self.normalizer.normalize_outbound_account(raw_account)
        if any((is_same_address(account, value) for value in self.get_accounts())):
            raise ValidationError("Account already present in account list")

        self.backend.add_account(raw_private_key)
        self._account_passwords[raw_account] = password
        # TODO: outbound normalization
        return account

    def unlock_account(self, account, password, unlock_seconds=None):
        self.validator.validate_inbound_account(account)
        raw_account = self.normalizer.normalize_inbound_account(account)
        try:
            account_password = self._account_passwords[raw_account]
        except KeyError:
            raise ValidationError("Unknown account")

        if account_password is None:
            raise ValidationError("Account does not have a password")

        if account_password != password:
            raise ValidationError("Wrong password")

        if unlock_seconds is None:
            unlock_until = None
        else:
            unlock_until = time.time() + unlock_seconds

        self._account_unlock[raw_account] = unlock_until

    def lock_account(self, account):
        self.validator.validate_inbound_account(account)
        raw_account = self.normalizer.normalize_inbound_account(account)

        if raw_account not in self._account_passwords:
            raise ValidationError("Unknown account")
        elif self._account_passwords[raw_account] is None:
            raise ValidationError("Account does not have a password")

        self._account_unlock[raw_account] = False

    def get_balance(self, account, block_number="latest"):
        self.validator.validate_inbound_account(account)
        self.validator.validate_inbound_block_number(block_number)
        raw_account = self.normalizer.normalize_inbound_account(account)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_balance = self.backend.get_balance(raw_account, raw_block_number)
        self.validator.validate_outbound_balance(raw_balance)
        balance = self.normalizer.normalize_outbound_balance(raw_balance)
        return balance

    def get_code(self, account, block_number="latest"):
        self.validator.validate_inbound_account(account)
        self.validator.validate_inbound_block_number(block_number)
        raw_account = self.normalizer.normalize_inbound_account(account)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_code = self.backend.get_code(raw_account, raw_block_number)
        self.validator.validate_outbound_code(raw_code)
        code = self.normalizer.normalize_outbound_code(raw_code)
        return code

    def get_nonce(self, account, block_number="latest"):
        self.validator.validate_inbound_account(account)
        self.validator.validate_inbound_block_number(block_number)
        raw_account = self.normalizer.normalize_inbound_account(account)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_nonce = self.backend.get_nonce(raw_account, raw_block_number)
        self.validator.validate_outbound_nonce(raw_nonce)
        nonce = self.normalizer.normalize_outbound_nonce(raw_nonce)
        return nonce

    #
    # Blocks, Transactions, Receipts
    #
    def get_transaction_by_hash(self, transaction_hash):
        self.validator.validate_inbound_transaction_hash(transaction_hash)
        raw_transaction_hash = self.normalizer.normalize_inbound_transaction_hash(
            transaction_hash,
        )
        raw_transaction = self.backend.get_transaction_by_hash(raw_transaction_hash)
        self.validator.validate_outbound_transaction(raw_transaction)
        transaction = self.normalizer.normalize_outbound_transaction(raw_transaction)
        return transaction

    def get_block_by_number(self, block_number="latest", full_transactions=False):
        self.validator.validate_inbound_block_number(block_number)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_block = self.backend.get_block_by_number(raw_block_number, full_transactions)
        self.validator.validate_outbound_block(raw_block)
        block = self.normalizer.normalize_outbound_block(raw_block)
        return block

    def get_block_by_hash(self, block_hash, full_transactions=False):
        self.validator.validate_inbound_block_hash(block_hash)
        raw_block_hash = self.normalizer.normalize_inbound_block_hash(block_hash)
        raw_block = self.backend.get_block_by_hash(raw_block_hash, full_transactions)
        self.validator.validate_outbound_block(raw_block)
        block = self.normalizer.normalize_outbound_block(raw_block)
        return block

    def get_transaction_receipt(self, transaction_hash):
        self.validator.validate_inbound_transaction_hash(transaction_hash)
        raw_transaction_hash = self.normalizer.normalize_inbound_transaction_hash(
            transaction_hash,
        )
        raw_receipt = self.backend.get_transaction_receipt(raw_transaction_hash)
        self.validator.validate_outbound_receipt(raw_receipt)
        receipt = self.normalizer.normalize_outbound_receipt(raw_receipt)
        return receipt

    #
    # Mining
    #
    def enable_auto_mine_transactions(self):
        self.auto_mine_transactions = True

    def disable_auto_mine_transactions(self):
        self.auto_mine_transactions = False

    def mine_blocks(self, num_blocks=1, coinbase=None):
        if coinbase is None:
            raw_coinbase = None
        else:
            self.validator.validate_inbound_account(coinbase)
            raw_coinbase = self.normalizer.normalize_inbound_account(coinbase)

        raw_block_hashes = self.backend.mine_blocks(num_blocks, raw_coinbase)

        if len(raw_block_hashes) != num_blocks:
            raise ValidationError(
                "Invariant: tried to mine {0} blocks.  Got {1} mined block hashes.".format(
                    num_blocks,
                    len(raw_block_hashes),
                )
            )

        for raw_block_hash in raw_block_hashes:
            self.validator.validate_outbound_block_hash(raw_block_hash)
        block_hashes = [
            self.normalizer.normalize_outbound_block_hash(raw_block_hash)
            for raw_block_hash
            in raw_block_hashes
        ]

        # feed the block hashes to any block filters
        for block_hash in block_hashes:
            block = self.get_block_by_hash(block_hash)

            for _, block_filter in self._block_filters.items():
                raw_block_hash = self.normalizer.normalize_inbound_block_hash(block_hash)
                block_filter.add(raw_block_hash)

            self._process_block_logs(block)

        return block_hashes

    def mine_block(self, coinbase=None):
        block_hash = self.mine_blocks(1, coinbase=coinbase)[0]
        return block_hash

    #
    # Private mining API
    #
    def _process_block_logs(self, block):
        for _, filter in self._log_filters.items():
            for transaction_hash in block['transactions']:
                receipt = self.get_transaction_receipt(transaction_hash)
                for log_entry in receipt['logs']:
                    raw_log_entry = self.normalizer.normalize_inbound_log_entry(log_entry)
                    filter.add(raw_log_entry)

    #
    # Transaction Sending
    #
    def send_transaction(self, transaction):
        self.validator.validate_inbound_transaction(transaction, txn_type='send')
        raw_transaction = self.normalizer.normalize_inbound_transaction(transaction)

        if raw_transaction['from'] in self._account_passwords:
            unlocked_until = self._account_unlock[raw_transaction['from']]
            account_password = self._account_passwords[raw_transaction['from']]
            is_locked = account_password is not None and unlocked_until is not None and (
                unlocked_until is False or time.time() > unlocked_until
            )
            if is_locked:
                raise AccountLocked("The account is currently locked")

        raw_transaction_hash = self.backend.send_transaction(raw_transaction)
        self.validator.validate_outbound_transaction_hash(raw_transaction_hash)
        transaction_hash = self.normalizer.normalize_outbound_transaction_hash(
            raw_transaction_hash,
        )

        # feed the transaction hash to any pending transaction filters.
        for _, filter in self._pending_transaction_filters.items():
            raw_transaction_hash = self.normalizer.normalize_inbound_transaction_hash(
                transaction_hash,
            )
            filter.add(raw_transaction_hash)

        if self._log_filters:
            receipt = self.get_transaction_receipt(transaction_hash)
            for log_entry in receipt['logs']:
                for _, filter in self._log_filters.items():
                    raw_log_entry = self.normalizer.normalize_inbound_log_entry(log_entry)
                    filter.add(raw_log_entry)

        # mine the transaction if auto-transaction-mining is enabled.
        if self.auto_mine_transactions:
            self.mine_block()

        return transaction_hash

    def call(self, transaction, block_number="latest"):
        self.validator.validate_inbound_transaction(transaction, txn_type='call')
        raw_transaction = self.normalizer.normalize_inbound_transaction(transaction)
        self.validator.validate_inbound_block_number(block_number)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_result = self.backend.call(raw_transaction, raw_block_number)
        self.validator.validate_outbound_return_data(raw_result)
        result = self.normalizer.normalize_outbound_return_data(raw_result)
        return result

    def estimate_gas(self, transaction):
        self.validator.validate_inbound_transaction(transaction, txn_type='estimate')
        raw_transaction = self.normalizer.normalize_inbound_transaction(transaction)
        raw_gas_estimate = self.backend.estimate_gas(raw_transaction)
        self.validator.validate_outbound_gas_estimate(raw_gas_estimate)
        gas_estimate = self.normalizer.normalize_outbound_gas_estimate(raw_gas_estimate)
        return gas_estimate

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
            compose(
                bool,
                self.get_block_by_hash,
                self.normalizer.normalize_outbound_block_hash,
            ),
            lambda v: False,
        )
        values_to_remove = remove(is_valid_block_hash, filter.get_all())
        filter.remove(*values_to_remove)

    def _revert_pending_transaction_filter(self, filter):
        is_valid_transaction_hash = excepts(
            (TransactionNotFound,),
            compose(
                bool,
                self.get_transaction_by_hash,
                self.normalizer.normalize_outbound_transaction_hash,
            ),
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
                self.normalizer.normalize_outbound_transaction_hash,
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
        raw_filter_id = next(self._filter_counter)
        self._block_filters[raw_filter_id] = Filter(filter_params=None)
        filter_id = self.normalizer.normalize_outbound_filter_id(raw_filter_id)
        return filter_id

    def create_pending_transaction_filter(self):
        raw_filter_id = next(self._filter_counter)
        self._pending_transaction_filters[raw_filter_id] = Filter(filter_params=None)
        filter_id = self.normalizer.normalize_outbound_filter_id(raw_filter_id)
        return filter_id

    def create_log_filter(self, from_block=None, to_block=None, address=None, topics=None):
        self.validator.validate_inbound_filter_params(
            from_block=from_block,
            to_block=to_block,
            address=address,
            topics=topics,
        )
        (
            raw_from_block,
            raw_to_block,
            raw_address,
            raw_topics,
        ) = self.normalizer.normalize_inbound_filter_params(
            from_block=from_block,
            to_block=to_block,
            address=address,
            topics=topics,
        )

        raw_filter_id = next(self._filter_counter)
        raw_filter_params = {
            'from_block': raw_from_block,
            'to_block': raw_to_block,
            'addresses': raw_address,
            'topics': raw_topics,
        }
        filter_fn = partial(
            check_if_log_matches,
            **raw_filter_params
        )
        self._log_filters[raw_filter_id] = Filter(
            filter_params=raw_filter_params,
            filter_fn=filter_fn,
        )

        if is_integer(raw_from_block):
            if is_integer(raw_to_block):
                upper_bound = raw_to_block
            else:
                upper_bound = self.get_block_by_number('pending')['number']
            for block_number in range(raw_from_block, upper_bound):
                block = self.get_block_by_number(block_number)
                self._process_block_logs(block)

        filter_id = self.normalizer.normalize_outbound_filter_id(raw_filter_id)
        return filter_id

    def delete_filter(self, filter_id):
        self.validator.validate_inbound_filter_id(filter_id)
        raw_filter_id = self.normalizer.normalize_inbound_filter_id(filter_id)

        if raw_filter_id in self._block_filters:
            del self._block_filters[raw_filter_id]
        elif raw_filter_id in self._pending_transaction_filters:
            del self._pending_transaction_filters[raw_filter_id]
        elif raw_filter_id in self._log_filters:
            del self._log_filters[raw_filter_id]
        else:
            raise FilterNotFound("Unknown filter id")

    @to_tuple
    def get_only_filter_changes(self, filter_id):
        self.validator.validate_inbound_filter_id(filter_id)
        raw_filter_id = self.normalizer.normalize_inbound_filter_id(filter_id)

        if raw_filter_id in self._block_filters:
            filter = self._block_filters[raw_filter_id]
            normalize_fn = self.normalizer.normalize_outbound_block_hash
        elif raw_filter_id in self._pending_transaction_filters:
            filter = self._pending_transaction_filters[raw_filter_id]
            normalize_fn = self.normalizer.normalize_outbound_transaction_hash
        elif raw_filter_id in self._log_filters:
            filter = self._log_filters[raw_filter_id]
            normalize_fn = self.normalizer.normalize_outbound_log_entry
        else:
            raise FilterNotFound("Unknown filter id")

        for item in filter.get_changes():
            yield normalize_fn(item)

    @to_tuple
    def get_all_filter_logs(self, filter_id):
        self.validator.validate_inbound_filter_id(filter_id)
        raw_filter_id = self.normalizer.normalize_inbound_filter_id(filter_id)

        if raw_filter_id in self._block_filters:
            filter = self._block_filters[raw_filter_id]
            normalize_fn = self.normalizer.normalize_outbound_block_hash
        elif raw_filter_id in self._pending_transaction_filters:
            filter = self._pending_transaction_filters[raw_filter_id]
            normalize_fn = self.normalizer.normalize_outbound_transaction_hash
        elif raw_filter_id in self._log_filters:
            filter = self._log_filters[raw_filter_id]
            normalize_fn = self.normalizer.normalize_outbound_log_entry
        else:
            raise FilterNotFound("Unknown filter id")

        for item in filter.get_all():
            yield normalize_fn(item)
