import collections
import functools
import itertools
import operator
import time
from typing import (
    List,
)

from eth_typing import (
    HexAddress,
    HexStr,
)
from eth_utils import (
    is_integer,
    is_same_address,
    to_list,
    to_tuple,
)
from eth_utils.toolz import (
    assoc,
    compose,
    dissoc,
    excepts,
    partial,
    remove,
)

from eth_tester.backends import (
    get_chain_backend,
)
from eth_tester.constants import (
    ZERO_ADDRESS_HEX,
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
from eth_tester.utils.accounts import (
    private_key_to_address,
)
from eth_tester.utils.filters import (
    Filter,
    check_if_log_matches,
)
from eth_tester.utils.transactions import (
    extract_transaction_type,
    extract_valid_transaction_params,
    remove_matching_transaction_from_list,
)
from eth_tester.validation import (
    get_validator,
)


def backend_proxy_method(backend_method_name):
    def proxy_method(self, *args, **kwargs):
        backend_method = getattr(self.backend, backend_method_name)
        return backend_method(*args, **kwargs)

    return proxy_method


def handle_auto_mining(func):
    @functools.wraps(func)
    def func_wrapper(self, *args, **kwargs):
        if self.auto_mine_transactions:
            transaction_hash = func(self, *args, **kwargs)
            self.mine_block()
        else:
            snapshot = self.take_snapshot()
            try:
                transaction_hash = func(self, *args, **kwargs)
                pending_transaction = self.get_transaction_by_hash(transaction_hash)
                # Remove any pending transactions with the same nonce
                self._pending_transactions = remove_matching_transaction_from_list(
                    self._pending_transactions, pending_transaction
                )
                cleaned_transaction = _clean_pending_transaction(pending_transaction)
                self._pending_transactions.append(cleaned_transaction)
            finally:
                self.revert_to_snapshot(snapshot)
        return transaction_hash

    def _clean_pending_transaction(pending_transaction):
        cleaned_transaction = dissoc(pending_transaction, "type")

        # TODO: Sometime in 2022 the inclusion of gas_price may be removed from
        #  dynamic fee transactions and we can get rid of this behavior.
        #  https://github.com/ethereum/execution-specs/pull/251
        # remove gas_price for dynamic fee transactions
        if "gas_price" and "max_fee_per_gas" in pending_transaction:
            cleaned_transaction = dissoc(cleaned_transaction, "gas_price")

        return cleaned_transaction

    return func_wrapper


class EthereumTester:
    backend = None

    validator = None
    normalizer = None

    fork_blocks = None

    auto_mine_transactions = None

    def __init__(
        self, backend=None, validator=None, normalizer=None, auto_mine_transactions=True
    ):
        if backend is None:
            backend = get_chain_backend()

        if validator is None:
            validator = get_validator()

        if normalizer is None:
            normalizer = get_normalizer_backend()

        self.backend = backend
        self.validator = validator
        self.normalizer = normalizer

        self.auto_mine_transactions = auto_mine_transactions

        self._reset_local_state()

    #
    # Private API
    #
    _filter_counter = None
    _log_filters = None
    _block_filters = None
    _pending_transaction_filters = None

    _pending_transactions = []

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
        self._account_unlock = collections.defaultdict(bool)

    #
    # Time Traveling
    #
    def time_travel(self, to_timestamp):
        self.validator.validate_inbound_timestamp(to_timestamp)
        # make sure we are not traveling back in time as this is not possible.
        current_timestamp = self.get_block_by_number("pending")["timestamp"]
        if to_timestamp == current_timestamp:
            # no change, return immediately
            return
        elif to_timestamp < current_timestamp:
            raise ValidationError(
                "Space time continuum distortion detected.  Traveling backwards "
                "in time violates interdimensional ordinance 31415-926."
            )
        else:
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
        if any(is_same_address(account, value) for value in self.get_accounts()):
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

    def get_storage_at(
        self,
        account: HexAddress,
        slot: HexStr,
        # properly type hint once eth-typing brings in updated `BlockIdentifier`
        block_number="latest",
    ) -> int:
        self.validator.validate_inbound_account(account)
        self.validator.validate_inbound_storage_slot(slot)
        self.validator.validate_inbound_block_number(block_number)
        raw_account = self.normalizer.normalize_inbound_account(account)
        raw_slot = self.normalizer.normalize_inbound_storage_slot(slot)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_storage = self.backend.get_storage(raw_account, raw_slot, raw_block_number)
        self.validator.validate_outbound_storage(raw_storage)
        storage = self.normalizer.normalize_outbound_storage(raw_storage)
        return storage

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

    @staticmethod
    def _normalize_pending_transaction(pending_transaction):
        """
        Add the transaction type and, if a dynamic fee transaction, add gas_price =
        max_fee_per_gas as highlighted in the execution-specs link below.
        """
        _type = extract_transaction_type(pending_transaction)
        pending_transaction = assoc(pending_transaction, "type", _type)

        # TODO: Sometime in 2022 the inclusion of gas_price may be removed from
        # dynamic fee transactions and we can get rid of this behavior.
        # https://github.com/ethereum/execution-specs/pull/251
        # add gas_price = max_fee_per_gas to pending dynamic fee transactions
        if _type == "0x2":
            pending_transaction = assoc(
                pending_transaction, "gas_price", pending_transaction["max_fee_per_gas"]
            )
        return pending_transaction

    def _get_pending_transaction_by_hash(self, transaction_hash):
        for transaction in self._pending_transactions:
            if transaction["hash"] == transaction_hash:
                return transaction
        raise TransactionNotFound(
            f"No transaction found for transaction hash: {transaction_hash}"
        )

    def get_transaction_by_hash(self, transaction_hash):
        self.validator.validate_inbound_transaction_hash(transaction_hash)
        try:
            pending_transaction = self._get_pending_transaction_by_hash(
                transaction_hash
            )
            return self._normalize_pending_transaction(pending_transaction)
        except TransactionNotFound:
            raw_transaction_hash = self.normalizer.normalize_inbound_transaction_hash(
                transaction_hash,
            )
            raw_transaction = self.backend.get_transaction_by_hash(raw_transaction_hash)
            self.validator.validate_outbound_transaction(raw_transaction)
            transaction = self.normalizer.normalize_outbound_transaction(
                raw_transaction
            )
            return transaction

    def get_block_by_number(self, block_number="latest", full_transactions=False):
        self.validator.validate_inbound_block_number(block_number)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_block = self.backend.get_block_by_number(
            raw_block_number, full_transactions
        )
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

    def get_fee_history(
        self, block_count=1, newest_block="latest", reward_percentiles: List[int] = ()
    ):
        fee_history = self.backend.get_fee_history(
            block_count, newest_block, reward_percentiles
        )
        return fee_history

    #
    # Mining
    #
    def enable_auto_mine_transactions(self):
        self.auto_mine_transactions = True
        sent_transaction_hashes = self._pop_pending_transactions_to_pending_block()
        self.mine_block()
        return sent_transaction_hashes

    def disable_auto_mine_transactions(self):
        self.auto_mine_transactions = False

    def mine_blocks(self, num_blocks=1, coinbase=ZERO_ADDRESS_HEX):
        self.validator.validate_inbound_account(coinbase)
        normalized_coinbase = self.normalizer.normalize_inbound_account(coinbase)

        if not self.auto_mine_transactions:
            self._pop_pending_transactions_to_pending_block()

        raw_block_hashes = self.backend.mine_blocks(num_blocks, normalized_coinbase)

        if len(raw_block_hashes) != num_blocks:
            raise ValidationError(
                f"Invariant: tried to mine {num_blocks} blocks.  Got "
                f"{len(raw_block_hashes)} mined block hashes."
            )

        for raw_block_hash in raw_block_hashes:
            self.validator.validate_outbound_block_hash(raw_block_hash)
        block_hashes = [
            self.normalizer.normalize_outbound_block_hash(raw_block_hash)
            for raw_block_hash in raw_block_hashes
        ]

        # feed the block hashes to any block filters
        for block_hash in block_hashes:
            block = self.get_block_by_hash(block_hash)

            for _, block_filter in self._block_filters.items():
                raw_block_hash = self.normalizer.normalize_inbound_block_hash(
                    block_hash
                )
                block_filter.add(raw_block_hash)

            self._process_block_logs(block)

        return block_hashes

    def mine_block(self, coinbase=ZERO_ADDRESS_HEX):
        self.validator.validate_inbound_account(coinbase)
        block_hash = self.mine_blocks(1, coinbase=coinbase)[0]
        return block_hash

    #
    # Private mining API
    #
    def _process_block_logs(self, block):
        for _fid, filter in self._log_filters.items():
            self._add_log_entries_to_filter(block, filter)

    def _add_log_entries_to_filter(self, block, filter_):
        for transaction_hash in block["transactions"]:
            receipt = self.get_transaction_receipt(transaction_hash)
            for log_entry in receipt["logs"]:
                raw_log_entry = self.normalizer.normalize_inbound_log_entry(log_entry)
                filter_.add(raw_log_entry)

    def _pop_pending_transactions_to_pending_block(self):
        sent_transaction_hashes = self._add_all_to_pending_block(
            self._pending_transactions
        )
        self._pending_transactions.clear()
        return sent_transaction_hashes

    @to_list
    def _add_all_to_pending_block(self, pending_transactions):
        for pending in pending_transactions:
            txn = extract_valid_transaction_params(pending)
            yield self._add_transaction_to_pending_block(
                txn, txn_internal_type="send_signed"
            )

    #
    # Transaction Sending
    #
    def _handle_filtering_for_transaction(self, transaction_hash):
        # feed the transaction hash to any pending transaction filters.
        for _, filter in self._pending_transaction_filters.items():
            raw_transaction_hash = self.normalizer.normalize_inbound_transaction_hash(
                transaction_hash,
            )
            filter.add(raw_transaction_hash)

        if self._log_filters:
            receipt = self.get_transaction_receipt(transaction_hash)
            for log_entry in receipt["logs"]:
                for _, filter in self._log_filters.items():
                    raw_log_entry = self.normalizer.normalize_inbound_log_entry(
                        log_entry
                    )
                    filter.add(raw_log_entry)

    @handle_auto_mining
    def send_raw_transaction(self, raw_transaction_hex):
        self.validator.validate_inbound_raw_transaction(raw_transaction_hex)
        raw_transaction = self.normalizer.normalize_inbound_raw_transaction(
            raw_transaction_hex
        )
        raw_transaction_hash = self.backend.send_raw_transaction(raw_transaction)
        self.validator.validate_outbound_transaction_hash(raw_transaction_hash)
        transaction_hash = self.normalizer.normalize_outbound_transaction_hash(
            raw_transaction_hash,
        )
        self._handle_filtering_for_transaction(transaction_hash)
        return transaction_hash

    @handle_auto_mining
    def send_transaction(self, transaction):
        return self._add_transaction_to_pending_block(transaction)

    def call(self, transaction, block_number="latest"):
        self.validator.validate_inbound_transaction(
            transaction, txn_internal_type="call"
        )
        raw_transaction = self.normalizer.normalize_inbound_transaction(transaction)
        self.validator.validate_inbound_block_number(block_number)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_result = self.backend.call(raw_transaction, raw_block_number)
        self.validator.validate_outbound_return_data(raw_result)
        result = self.normalizer.normalize_outbound_return_data(raw_result)
        return result

    def estimate_gas(self, transaction, block_number="latest"):
        self.validator.validate_inbound_transaction(
            transaction, txn_internal_type="estimate"
        )
        raw_transaction = self.normalizer.normalize_inbound_transaction(transaction)
        self.validator.validate_inbound_block_number(block_number)
        raw_block_number = self.normalizer.normalize_inbound_block_number(block_number)
        raw_gas_estimate = self.backend.estimate_gas(raw_transaction, raw_block_number)
        self.validator.validate_outbound_gas_estimate(raw_gas_estimate)
        gas_estimate = self.normalizer.normalize_outbound_gas_estimate(raw_gas_estimate)
        return gas_estimate

    #
    # Private Transaction API
    #
    def _add_transaction_to_pending_block(self, transaction, txn_internal_type="send"):
        self.validator.validate_inbound_transaction(
            transaction, txn_internal_type=txn_internal_type
        )
        raw_transaction = self.normalizer.normalize_inbound_transaction(transaction)

        if raw_transaction["from"] in self._account_passwords:
            unlocked_until = self._account_unlock[raw_transaction["from"]]
            account_password = self._account_passwords[raw_transaction["from"]]
            is_locked = (
                account_password is not None
                and unlocked_until is not None
                and (unlocked_until is False or time.time() > unlocked_until)
            )
            if is_locked:
                raise AccountLocked("The account is currently locked")

        if {"r", "s", "v"}.issubset(transaction.keys()):
            try:
                raw_transaction_hash = self.backend.send_signed_transaction(
                    raw_transaction
                )
            except NotImplementedError:
                unsigned_transaction = dissoc(raw_transaction, "r", "s", "v")
                raw_transaction_hash = self.backend.send_transaction(
                    unsigned_transaction
                )
        else:
            raw_transaction_hash = self.backend.send_transaction(raw_transaction)

        self.validator.validate_outbound_transaction_hash(raw_transaction_hash)
        transaction_hash = self.normalizer.normalize_outbound_transaction_hash(
            raw_transaction_hash,
        )

        self._handle_filtering_for_transaction(transaction_hash)

        return transaction_hash

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
            raise SnapshotNotFound(f"No snapshot found for id: {snapshot_id}")
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
        values_to_remove = tuple(remove(is_valid_block_hash, filter.get_all()))
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
                operator.itemgetter("transaction_hash"),
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

    def create_log_filter(
        self, from_block=None, to_block=None, address=None, topics=None
    ):
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
            "from_block": raw_from_block,
            "to_block": raw_to_block,
            "addresses": raw_address,
            "topics": raw_topics,
        }
        filter_fn = partial(check_if_log_matches, **raw_filter_params)
        new_filter = Filter(
            filter_params=raw_filter_params,
            filter_fn=filter_fn,
        )
        self._log_filters[raw_filter_id] = new_filter

        if is_integer(raw_from_block):
            if is_integer(raw_to_block):
                upper_bound = raw_to_block + 1
            else:
                upper_bound = self.get_block_by_number("pending")["number"]
            for block_number in range(raw_from_block, upper_bound):
                block = self.get_block_by_number(block_number)
                self._add_log_entries_to_filter(block, new_filter)

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

    @to_tuple
    def get_logs(self, from_block=None, to_block=None, address=None, topics=None):
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

        # Setup the filter object
        raw_filter_params = {
            "from_block": raw_from_block,
            "to_block": raw_to_block,
            "addresses": raw_address,
            "topics": raw_topics,
        }
        filter_fn = partial(
            check_if_log_matches,
            **raw_filter_params,
        )
        log_filter = Filter(
            filter_params=raw_filter_params,
            filter_fn=filter_fn,
        )

        # Set from/to block defaults
        if raw_from_block is None:
            raw_from_block = "latest"
        if raw_to_block is None:
            raw_to_block = "latest"

        # Determine lower bound for block range.
        if isinstance(raw_from_block, int):
            lower_bound = raw_from_block
        else:
            lower_bound = self.get_block_by_number(raw_from_block)["number"]

        # Determine upper bound for block range.
        if isinstance(raw_to_block, int):
            upper_bound = raw_to_block
        else:
            upper_bound = self.get_block_by_number(raw_to_block)["number"]

        # Enumerate the blocks in the block range to find all log entries which match.
        for block_number in range(lower_bound, upper_bound + 1):
            block = self.get_block_by_number(block_number)
            for transaction_hash in block["transactions"]:
                receipt = self.get_transaction_receipt(transaction_hash)
                for log_entry in receipt["logs"]:
                    raw_log_entry = self.normalizer.normalize_inbound_log_entry(
                        log_entry
                    )
                    log_filter.add(raw_log_entry)

        # Return the matching log entries
        for item in log_filter.get_all():
            yield self.normalizer.normalize_outbound_log_entry(item)
