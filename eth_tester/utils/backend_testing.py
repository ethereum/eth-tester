from __future__ import unicode_literals

import pytest

from cytoolz.dicttoolz import (
    merge,
    assoc,
)
from hypothesis import (
    strategies as st,
    given,
    settings,
)
from hypothesis.stateful import (
    RuleBasedStateMachine,
    Bundle,
    rule,
)

from eth_utils import (
    to_normalized_address,
    is_address,
    is_integer,
    is_same_address,
    is_dict,
    is_hex,
    denoms,
)

from eth_tester.constants import (
    UINT256_MIN,
    UINT256_MAX,
    BURN_ADDRESS,
    FORK_HOMESTEAD,
    FORK_DAO,
    FORK_ANTI_DOS,
    FORK_STATE_CLEANUP,
)
from eth_tester.exceptions import (
    AccountLocked,
    FilterNotFound,
    ValidationError,
)

from .emitter_contract import (
    _deploy_emitter,
    _call_emitter,
    EMITTER_ENUM,
)
from .math_contract import (
    _deploy_math,
    _make_call_math_transaction,
    _decode_math_result,
)


PK_A = '0x58d23b55bc9cdce1f18c2500f40ff4ab7245df9a89505e9b1fa4851f623d241d'
PK_A_ADDRESS = '0xdc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd'


SIMPLE_TRANSACTION = {
    "to": BURN_ADDRESS,
    "gas_price": 1,
    "value": 0,
    "gas": 21000,
}


BLOCK_KEYS = {
    "number",
    "hash",
    "parent_hash",
    "nonce",
    "sha3_uncles",
    "logs_bloom",
    "transactions_root",
    "receipts_root",
    "state_root",
    "miner",
    "difficulty",
    "total_difficulty",
    "size",
    "extra_data",
    "gas_limit",
    "gas_used",
    "timestamp",
    "transactions",
    "uncles",
}


def _validate_serialized_block(block):
    missing_keys = BLOCK_KEYS.difference(block.keys())
    if missing_keys:
        error_message = "Serialized block is missing the following keys: {0}".format(
            "|".join(sorted(missing_keys)),
        )
        raise AssertionError(error_message)


class BaseTestBackendDirect(object):
    #
    # Utils
    #
    def _send_and_check_transaction(self, eth_tester, _from):
        transaction = assoc(SIMPLE_TRANSACTION, 'from', _from)

        txn_hash = eth_tester.send_transaction(transaction)
        txn = eth_tester.get_transaction_by_hash(txn_hash)

        assert is_same_address(txn['from'], transaction['from'])
        assert is_same_address(txn['to'], transaction['to'])
        assert txn['gas_price'] == transaction['gas_price']
        assert txn['gas'] == transaction['gas']
        assert txn['value'] == transaction['value']
    #
    # Testing Flags
    #
    supports_evm_execution = True

    def skip_if_no_evm_execution(self):
        if not self.supports_evm_execution:
            pytest.skip('EVM Execution is not supported.')

    #
    # Accounts
    #
    def test_get_accounts(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts
        assert all(
            is_address(account)
            for account
            in accounts
        )

    def test_add_account_no_password(self, eth_tester):
        account = eth_tester.add_account(PK_A)
        assert is_address(account)
        assert any((
            is_same_address(account, value)
            for value
            in eth_tester.get_accounts()
        ))

        # Fund it
        eth_tester.send_transaction({
            'from': eth_tester.get_accounts()[0],
            'to': account,
            'value': 1 * denoms.ether,
            'gas': 21000,
            'gas_price': 1,
        })

        self._send_and_check_transaction(eth_tester, account)

    def test_add_account_with_password(self, eth_tester):
        account = eth_tester.add_account(PK_A, 'test-password')
        assert is_address(account)
        assert any((
            is_same_address(account, value)
            for value
            in eth_tester.get_accounts()
        ))

        # Fund it
        eth_tester.send_transaction({
            'from': eth_tester.get_accounts()[0],
            'to': account,
            'value': 1 * denoms.ether,
            'gas': 21000,
            'gas_price': 1,
        })

        with pytest.raises(AccountLocked):
            self._send_and_check_transaction(eth_tester, account)

        eth_tester.unlock_account(account, 'test-password')
        self._send_and_check_transaction(eth_tester, account)

        eth_tester.lock_account(account)

        with pytest.raises(AccountLocked):
            self._send_and_check_transaction(eth_tester, account)

    def test_get_balance_of_listed_accounts(self, eth_tester):
        for account in eth_tester.get_accounts():
            balance = eth_tester.get_balance(account)
            assert is_integer(balance)
            assert balance >= UINT256_MIN
            assert balance <= UINT256_MAX

    def test_get_nonce(self, eth_tester):
        for account in eth_tester.get_accounts():
            nonce = eth_tester.get_nonce(account)
        assert is_integer(nonce)
        assert nonce >= UINT256_MIN
        assert nonce <= UINT256_MAX

    #
    # Mining
    #
    def test_mine_block_single(self, eth_tester):
        eth_tester.mine_blocks()
        before_block_number = eth_tester.get_block_by_number('latest')['number']
        eth_tester.mine_blocks()
        after_block_number = eth_tester.get_block_by_number('latest')['number']
        assert is_integer(before_block_number)
        assert is_integer(after_block_number)
        assert before_block_number == after_block_number - 1

    def test_mine_multiple_blocks(self, eth_tester):
        eth_tester.mine_blocks()
        before_block_number = eth_tester.get_block_by_number('latest')['number']
        eth_tester.mine_blocks(10)
        after_block_number = eth_tester.get_block_by_number('latest')['number']
        assert is_integer(before_block_number)
        assert is_integer(after_block_number)
        assert before_block_number == after_block_number - 10

    #
    # Transaction Sending
    #
    def test_send_transaction(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        self._send_and_check_transaction(eth_tester, accounts[0])

    def test_auto_mine_transactions_enabled(self, eth_tester):
        eth_tester.mine_blocks()
        eth_tester.enable_auto_mine_transactions()
        before_block_number = eth_tester.get_block_by_number('latest')['number']
        eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        after_block_number = eth_tester.get_block_by_number('latest')['number']
        assert before_block_number == after_block_number - 1

    def test_auto_mine_transactions_disabled(self, eth_tester):
        eth_tester.mine_blocks()
        eth_tester.disable_auto_mine_transactions()
        before_block_number = eth_tester.get_block_by_number('latest')['number']
        eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        after_block_number = eth_tester.get_block_by_number('latest')['number']
        assert before_block_number == after_block_number

    #
    # Blocks
    #
    def test_get_genesis_block_by_number(self, eth_tester):
        block = eth_tester.get_block_by_number(0)
        assert block['number'] == 0
        _validate_serialized_block(block)

    def test_get_genesis_block_by_hash(self, eth_tester):
        genesis_hash = eth_tester.get_block_by_number(0)['hash']
        block = eth_tester.get_block_by_hash(genesis_hash)
        assert block['number'] == 0
        _validate_serialized_block(block)

    def test_get_block_by_number(self, eth_tester):
        origin_block_number = eth_tester.get_block_by_number('pending')['number']
        mined_block_hashes = eth_tester.mine_blocks(10)
        for offset, block_hash in enumerate(mined_block_hashes):
            block_number = origin_block_number + offset
            block = eth_tester.get_block_by_number(block_number)
            assert block['number'] == block_number
            assert block['hash'] == block_hash
            _validate_serialized_block(block)

    def test_get_block_by_number_full_transactions(self, eth_tester):
        eth_tester.mine_blocks(2)
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        block = eth_tester.get_block_by_number(
            transaction['block_number'],
            full_transactions=True,
        )
        assert is_dict(block['transactions'][0])

    def test_get_block_by_number_only_transaction_hashes(self, eth_tester):
        eth_tester.mine_blocks(2)
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        block = eth_tester.get_block_by_number(
            transaction['block_number'],
            full_transactions=False,
        )
        assert is_hex(block['transactions'][0])

    def test_get_block_by_hash(self, eth_tester):
        origin_block_number = eth_tester.get_block_by_number('pending')['number']

        mined_block_hashes = eth_tester.mine_blocks(10)
        for offset, block_hash in enumerate(mined_block_hashes):
            block_number = origin_block_number + offset
            block = eth_tester.get_block_by_hash(block_hash)
            assert block['number'] == block_number
            assert block['hash'] == block_hash

    def test_get_block_by_hash_full_transactions(self, eth_tester):
        eth_tester.mine_blocks(2)
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        block = eth_tester.get_block_by_hash(
            transaction['block_hash'],
            full_transactions=True,
        )
        assert is_dict(block['transactions'][0])

    def test_get_block_by_hash_only_transaction_hashes(self, eth_tester):
        eth_tester.mine_blocks(2)
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        block = eth_tester.get_block_by_hash(
            transaction['block_hash'],
            full_transactions=False,
        )
        assert is_hex(block['transactions'][0])

    def test_get_block_by_earliest(self, eth_tester):
        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number('earliest')
        assert block['number'] == 0

    def test_get_block_by_latest_unmined_genesis(self, eth_tester):
        block = eth_tester.get_block_by_number('latest')
        assert block['number'] == 0

    def test_get_block_by_latest_only_genesis(self, eth_tester):
        block = eth_tester.get_block_by_number('latest')
        assert block['number'] == 0

    def test_get_block_by_latest(self, eth_tester):
        origin_block_number = eth_tester.get_block_by_number('pending')['number']

        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number('latest')
        assert block['number'] == 9 + origin_block_number

    def test_get_block_by_pending(self, eth_tester):
        origin_block_number = eth_tester.get_block_by_number('pending')['number']

        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number('pending')
        assert block['number'] == 10 + origin_block_number

    # Transactions
    def test_get_transaction_by_hash(self, eth_tester):
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        assert transaction['hash'] == transaction_hash

    def test_get_transaction_receipt_for_mined_transaction(self, eth_tester):
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt['transaction_hash'] == transaction_hash

    def test_get_transaction_receipt_for_unmined_transaction(self, eth_tester):
        eth_tester.disable_auto_mine_transactions()
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt['block_number'] is None

    def test_call_return13(self, eth_tester):
        self.skip_if_no_evm_execution()

        math_address = _deploy_math(eth_tester)
        call_math_transaction = _make_call_math_transaction(
            eth_tester,
            math_address,
            'return13',
        )
        raw_result = eth_tester.call(call_math_transaction)
        result = _decode_math_result('return13', raw_result)
        assert result == (13,)

    def test_call_add(self, eth_tester):
        self.skip_if_no_evm_execution()

        math_address = _deploy_math(eth_tester)
        call_math_transaction = _make_call_math_transaction(
            eth_tester,
            math_address,
            'add',
            fn_args=(7, 13),
        )
        raw_result = eth_tester.call(call_math_transaction)
        result = _decode_math_result('add', raw_result)
        assert result == (20,)

    def test_estimate_gas(self, eth_tester):
        self.skip_if_no_evm_execution()

        math_address = _deploy_math(eth_tester)
        estimate_call_math_transaction = _make_call_math_transaction(
            eth_tester,
            math_address,
            'increment',
        )
        gas_estimation = eth_tester.estimate_gas(estimate_call_math_transaction)
        call_math_transaction = assoc(estimate_call_math_transaction, 'gas', gas_estimation)
        transaction_hash = eth_tester.send_transaction(call_math_transaction)
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt['gas_used'] == gas_estimation

    #
    # Snapshot and Revert
    #
    def test_genesis_snapshot_and_revert(self, eth_tester):
        origin_latest = eth_tester.get_block_by_number('latest')['number']
        origin_pending = eth_tester.get_block_by_number('pending')['number']

        snapshot_id = eth_tester.take_snapshot()

        # now mine 10 blocks in
        eth_tester.mine_blocks(10)
        assert eth_tester.get_block_by_number('latest')['number'] == origin_latest + 10
        assert eth_tester.get_block_by_number('pending')['number'] == origin_pending + 10

        eth_tester.revert_to_snapshot(snapshot_id)
        assert eth_tester.get_block_by_number('latest')['number'] == origin_latest
        assert eth_tester.get_block_by_number('pending')['number'] == origin_pending

    def test_snapshot_and_revert_post_genesis(self, eth_tester):
        eth_tester.mine_blocks(5)

        origin_latest = eth_tester.get_block_by_number('latest')['number']
        origin_pending = eth_tester.get_block_by_number('pending')['number']

        snapshot_id = eth_tester.take_snapshot()

        # now mine 10 blocks in
        eth_tester.mine_blocks(10)
        assert eth_tester.get_block_by_number('latest')['number'] == origin_latest + 10
        assert eth_tester.get_block_by_number('pending')['number'] == origin_pending + 10

        eth_tester.revert_to_snapshot(snapshot_id)

        assert eth_tester.get_block_by_number('latest')['number'] == origin_latest
        assert eth_tester.get_block_by_number('pending')['number'] == origin_pending

    def test_revert_cleans_up_invalidated_pending_block_filters(self, eth_tester):
        # first mine 10 blocks in
        eth_tester.mine_blocks(2)

        # setup a filter
        filter_a_id = eth_tester.create_block_filter()
        filter_b_id = eth_tester.create_block_filter()

        # mine 5 blocks before the snapshot
        common_blocks = set(eth_tester.mine_blocks(2))

        snapshot_id = eth_tester.take_snapshot()

        # mine another 5 blocks
        fork_a_transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
            "value": 1,
        })
        fork_a_transaction_block_hash = eth_tester.get_transaction_by_hash(
            fork_a_transaction_hash,
        )['block_hash']
        fork_a_blocks = eth_tester.mine_blocks(2)

        before_revert_changes_logs_a = eth_tester.get_only_filter_changes(filter_a_id)
        before_revert_all_logs_a = eth_tester.get_all_filter_logs(filter_a_id)
        before_revert_all_logs_b = eth_tester.get_all_filter_logs(filter_b_id)

        assert common_blocks.intersection(before_revert_changes_logs_a) == common_blocks
        assert common_blocks.intersection(before_revert_all_logs_a) == common_blocks
        assert common_blocks.intersection(before_revert_all_logs_b) == common_blocks

        expected_before_block_hashes = common_blocks.union([
            fork_a_transaction_block_hash,
        ]).union(fork_a_blocks)

        # sanity check that the filters picked up on the log changes.
        assert set(before_revert_changes_logs_a) == expected_before_block_hashes
        assert set(before_revert_changes_logs_a) == expected_before_block_hashes
        assert set(before_revert_all_logs_a) == expected_before_block_hashes
        assert set(before_revert_all_logs_b) == expected_before_block_hashes

        # now revert to snapshot
        eth_tester.revert_to_snapshot(snapshot_id)

        # send a different transaction to ensure our new blocks are different
        fork_b_transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
            "value": 2,
        })
        fork_b_transaction_block_hash = eth_tester.get_transaction_by_hash(
            fork_b_transaction_hash,
        )['block_hash']
        fork_b_blocks = eth_tester.mine_blocks(2)

        # check that are blocks don't intersect
        assert not set(fork_a_blocks).intersection(fork_b_blocks)

        after_revert_changes_logs_a = eth_tester.get_only_filter_changes(filter_a_id)
        after_revert_changes_logs_b = eth_tester.get_only_filter_changes(filter_b_id)
        after_revert_all_logs_a = eth_tester.get_all_filter_logs(filter_a_id)
        after_revert_all_logs_b = eth_tester.get_all_filter_logs(filter_b_id)

        expected_all_after_blocks = common_blocks.union([
            fork_b_transaction_block_hash,
        ]).union(fork_b_blocks)
        expected_new_after_blocks = set(fork_b_blocks).union([
            fork_b_transaction_block_hash,
        ])

        assert set(after_revert_changes_logs_a) == expected_new_after_blocks
        assert set(after_revert_changes_logs_b) == expected_all_after_blocks
        assert set(after_revert_all_logs_a) == expected_all_after_blocks
        assert set(after_revert_all_logs_b) == expected_all_after_blocks

    def test_revert_cleans_up_invalidated_pending_transaction_filters(self, eth_tester):
        def _transaction(**kwargs):
            return merge(
                {"from": eth_tester.get_accounts()[0], "to": BURN_ADDRESS, "gas": 21000},
                kwargs,
            )

        # send a few initial transactions
        for _ in range(5):
            eth_tester.send_transaction(_transaction())

        # setup a filter
        filter_id = eth_tester.create_pending_transaction_filter()

        # send 2 transactions
        common_transactions = set([
            eth_tester.send_transaction(_transaction(value=1)),
            eth_tester.send_transaction(_transaction(value=2)),
        ])

        # take a snapshot
        snapshot_id = eth_tester.take_snapshot()

        # send 3 transactions
        before_transactions = [
            eth_tester.send_transaction(_transaction(value=3)),
            eth_tester.send_transaction(_transaction(value=4)),
            eth_tester.send_transaction(_transaction(value=5)),
        ]

        # pull and sanity check the filter changes
        before_filter_changes = eth_tester.get_only_filter_changes(filter_id)
        before_filter_logs = eth_tester.get_all_filter_logs(filter_id)

        assert set(before_filter_changes) == common_transactions.union(before_transactions)
        assert set(before_filter_logs) == common_transactions.union(before_transactions)

        # revert the chain
        eth_tester.revert_to_snapshot(snapshot_id)

        # send 3 transactions on the new fork
        after_transactions = [
            eth_tester.send_transaction(_transaction(value=6)),
            eth_tester.send_transaction(_transaction(value=7)),
            eth_tester.send_transaction(_transaction(value=8)),
        ]

        # pull and sanity check the filter changes
        after_filter_changes = eth_tester.get_only_filter_changes(filter_id)
        after_filter_logs = eth_tester.get_all_filter_logs(filter_id)

        assert set(after_filter_changes) == set(after_transactions)
        assert set(after_filter_logs) == common_transactions.union(after_transactions)

    def test_revert_cleans_up_invalidated_log_entries(self, eth_tester):
        self.skip_if_no_evm_execution()

        # setup the emitter
        emitter_address = _deploy_emitter(eth_tester)

        def _emit(v):
            return _call_emitter(
                eth_tester,
                emitter_address,
                'logSingle',
                [EMITTER_ENUM['LogSingleWithIndex'], v],
            )

        # emit 2 logs pre-filtering
        _emit(1)
        _emit(2)

        # setup a filter
        filter_id = eth_tester.create_log_filter()

        # emit 2 logs pre-snapshot
        _emit(1)
        _emit(2)

        # take a snapshot
        snapshot_id = eth_tester.take_snapshot()

        # emit 3 logs after-snapshot
        _emit(3)
        _emit(4)
        _emit(5)

        before_changes = eth_tester.get_only_filter_changes(filter_id)
        before_all = eth_tester.get_all_filter_logs(filter_id)

        assert len(before_changes) == 5
        assert len(before_all) == 5

        # revert the chain
        eth_tester.revert_to_snapshot(snapshot_id)

        # emit 4 logs after-reverting
        _emit(6)
        _emit(7)
        _emit(8)
        _emit(9)

        after_changes = eth_tester.get_only_filter_changes(filter_id)
        after_all = eth_tester.get_all_filter_logs(filter_id)

        assert len(after_changes) == 4
        assert len(after_all) == 6

    def test_reset_to_genesis(self, eth_tester):
        origin_latest = eth_tester.get_block_by_number('latest')['number']
        origin_pending = eth_tester.get_block_by_number('pending')['number']
        eth_tester.mine_blocks(5)

        assert eth_tester.get_block_by_number('latest')['number'] == origin_latest + 5
        assert eth_tester.get_block_by_number('pending')['number'] == origin_pending + 5

        eth_tester.reset_to_genesis()

        assert eth_tester.get_block_by_number('latest')['number'] == origin_latest
        assert eth_tester.get_block_by_number('pending')['number'] == origin_pending

    #
    # Filters
    #
    def test_block_filter(self, eth_tester):
        # first mine 10 blocks in
        eth_tester.mine_blocks(10)

        # setup a filter
        filter_a_id = eth_tester.create_block_filter()

        # mine another 5 blocks
        blocks_10_to_14 = eth_tester.mine_blocks(5)

        # setup another filter
        filter_b_id = eth_tester.create_block_filter()

        # mine another 8 blocks
        blocks_15_to_22 = eth_tester.mine_blocks(8)

        filter_a_changes_part_1 = eth_tester.get_only_filter_changes(filter_a_id)
        filter_a_logs_part_1 = eth_tester.get_all_filter_logs(filter_a_id)
        filter_b_logs_part_1 = eth_tester.get_all_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_1) == 13
        assert len(filter_a_logs_part_1) == 13
        assert len(filter_b_logs_part_1) == 8

        assert set(filter_a_changes_part_1) == set(filter_a_logs_part_1)
        assert set(filter_a_changes_part_1) == set(blocks_10_to_14).union(blocks_15_to_22)
        assert set(filter_b_logs_part_1) == set(blocks_15_to_22)

        # mine another 7 blocks
        blocks_23_to_29 = eth_tester.mine_blocks(7)

        filter_a_changes_part_2 = eth_tester.get_only_filter_changes(filter_a_id)
        filter_b_changes = eth_tester.get_only_filter_changes(filter_b_id)
        filter_a_logs_part_2 = eth_tester.get_all_filter_logs(filter_a_id)
        filter_b_logs_part_2 = eth_tester.get_all_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_2) == 7
        assert len(filter_b_changes) == 15
        assert len(filter_a_logs_part_2) == 20
        assert len(filter_b_logs_part_2) == 15

        assert set(filter_a_changes_part_2) == set(blocks_23_to_29)
        assert set(filter_b_changes) == set(blocks_15_to_22).union(blocks_23_to_29)
        assert set(filter_b_changes) == set(filter_b_logs_part_2)
        assert set(filter_a_logs_part_2) == set(blocks_10_to_14).union(
            blocks_15_to_22,
        ).union(blocks_23_to_29)
        assert set(filter_b_logs_part_2) == set(blocks_15_to_22).union(blocks_23_to_29)

    def test_pending_transaction_filter(self, eth_tester):
        transaction = {
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        }

        # send a few initial transactions
        for _ in range(5):
            eth_tester.send_transaction(transaction)

        # setup a filter
        filter_a_id = eth_tester.create_pending_transaction_filter()

        # send 8 transactions
        transactions_0_to_7 = [
            eth_tester.send_transaction(transaction)
            for _ in range(8)
        ]

        # setup another filter
        filter_b_id = eth_tester.create_pending_transaction_filter()

        # send 5 transactions
        transactions_8_to_12 = [
            eth_tester.send_transaction(transaction)
            for _ in range(5)
        ]

        filter_a_changes_part_1 = eth_tester.get_only_filter_changes(filter_a_id)
        filter_a_logs_part_1 = eth_tester.get_all_filter_logs(filter_a_id)
        filter_b_logs_part_1 = eth_tester.get_all_filter_logs(filter_b_id)

        assert set(filter_a_changes_part_1) == set(filter_a_logs_part_1)
        assert set(filter_a_changes_part_1) == set(transactions_0_to_7).union(transactions_8_to_12)
        assert set(filter_b_logs_part_1) == set(transactions_8_to_12)

        # send 7 transactions
        transactions_13_to_20 = [
            eth_tester.send_transaction(transaction)
            for _ in range(7)
        ]

        filter_a_changes_part_2 = eth_tester.get_only_filter_changes(filter_a_id)
        filter_b_changes = eth_tester.get_only_filter_changes(filter_b_id)
        filter_a_logs_part_2 = eth_tester.get_all_filter_logs(filter_a_id)
        filter_b_logs_part_2 = eth_tester.get_all_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_2) == 7
        assert len(filter_b_changes) == 12
        assert len(filter_a_logs_part_2) == 20
        assert len(filter_b_logs_part_2) == 12

        assert set(filter_a_changes_part_2) == set(transactions_13_to_20)
        assert set(filter_b_changes) == set(filter_b_logs_part_2)
        assert set(filter_b_changes) == set(transactions_8_to_12).union(transactions_13_to_20)
        assert set(filter_a_logs_part_2) == set(transactions_0_to_7).union(
            transactions_8_to_12,
        ).union(transactions_13_to_20)
        assert set(filter_b_logs_part_2) == set(transactions_8_to_12).union(transactions_13_to_20)

    def test_log_filter_picks_up_new_logs(self, eth_tester):
        """
        Cases to test:
        - filter multiple transactions in one block.
        - filter mined.
        self.skip_if_no_evm_execution()

        - filter against topics.
        - filter against blocks numbers that are already mined.
        """
        self.skip_if_no_evm_execution()

        emitter_address = _deploy_emitter(eth_tester)
        emit_a_hash = _call_emitter(
            eth_tester,
            emitter_address,
            'logSingle',
            [EMITTER_ENUM['LogSingleWithIndex'], 1],
        )
        eth_tester.get_transaction_receipt(emit_a_hash)

        filter_any_id = eth_tester.create_log_filter()
        _call_emitter(
            eth_tester,
            emitter_address,
            'logSingle',
            [EMITTER_ENUM['LogSingleWithIndex'], 2],
        )

        logs_changes = eth_tester.get_only_filter_changes(filter_any_id)
        logs_all = eth_tester.get_all_filter_logs(filter_any_id)
        assert len(logs_changes) == len(logs_all) == 1

    def test_log_filter_includes_old_logs(self, eth_tester):
        """
        Cases to test:
        - filter multiple transactions in one block.
        - filter mined.
        self.skip_if_no_evm_execution()

        - filter against topics.
        - filter against blocks numbers that are already mined.
        """
        self.skip_if_no_evm_execution()

        emitter_address = _deploy_emitter(eth_tester)
        _call_emitter(
            eth_tester,
            emitter_address,
            'logSingle',
            [EMITTER_ENUM['LogSingleWithIndex'], 1],
        )

        filter_any_id = eth_tester.create_log_filter(from_block=0)
        _call_emitter(
            eth_tester,
            emitter_address,
            'logSingle',
            [EMITTER_ENUM['LogSingleWithIndex'], 2],
        )

        logs_changes = eth_tester.get_only_filter_changes(filter_any_id)
        logs_all = eth_tester.get_all_filter_logs(filter_any_id)
        assert len(logs_changes) == len(logs_all) == 2

    def test_delete_filter(self, eth_tester):
        self.skip_if_no_evm_execution()

        filter_id = eth_tester.create_block_filter()

        eth_tester.get_all_filter_logs(filter_id)
        eth_tester.get_only_filter_changes(filter_id)

        eth_tester.delete_filter(filter_id)

        with pytest.raises(FilterNotFound):
            eth_tester.get_all_filter_logs(filter_id)
        with pytest.raises(FilterNotFound):
            eth_tester.get_only_filter_changes(filter_id)

        with pytest.raises(FilterNotFound):
            eth_tester.delete_filter(filter_id)

        with pytest.raises(FilterNotFound):
            eth_tester.delete_filter(12345)

    #
    # Time Travel
    #
    def test_time_traveling(self, eth_tester):
        # first mine a few blocks
        eth_tester.mine_blocks(3)

        # check the time
        before_timestamp = eth_tester.get_block_by_number('pending')['timestamp']

        # now travel forward 2 minutes
        eth_tester.time_travel(before_timestamp + 120)

        # now check the time
        after_timestamp = eth_tester.get_block_by_number('pending')['timestamp']

        assert before_timestamp + 120 == after_timestamp

    def test_time_traveling_backwards_not_allowed(self, eth_tester):
        # first mine a few blocks
        eth_tester.mine_blocks(3)

        # check the time
        before_timestamp = eth_tester.get_block_by_number('pending')['timestamp']

        # now travel forward 2 minutes
        with pytest.raises(ValidationError):
            eth_tester.time_travel(before_timestamp - 10)

    #
    # Fork Configuration
    #
    @pytest.mark.parametrize(
        'fork_name,expected_init_block,set_to_block',
        (
            (FORK_HOMESTEAD, 0, 12345),
            (FORK_DAO, 0, 12345),
            (FORK_ANTI_DOS, 0, 12345),
            (FORK_STATE_CLEANUP, 0, 12345),
        )
    )
    def test_getting_and_setting_fork_blocks(self,
                                             eth_tester,
                                             fork_name,
                                             expected_init_block,
                                             set_to_block):
        # TODO: this should realy test something about the EVM actually using
        # the *right* rules but for now this should suffice.
        init_fork_block = eth_tester.get_fork_block(fork_name)
        assert init_fork_block == expected_init_block

        eth_tester.set_fork_block(fork_name, set_to_block)
        after_set_fork_block = eth_tester.get_fork_block(fork_name)
        assert after_set_fork_block == set_to_block


address = st.binary(
    min_size=20,
    max_size=20,
).map(to_normalized_address)


class BaseTestBackendFuzz(object):
    @given(account=address)
    @settings(max_examples=10)
    def test_get_balance_simple_fuzzing(self, eth_tester, account):
        balance = eth_tester.get_balance(account)
        assert is_integer(balance)
        assert balance >= UINT256_MIN
        assert balance <= UINT256_MAX

    @given(account=address)
    @settings(max_examples=10)
    def test_get_nonce_simple_fuzzing(self, eth_tester, account):
        nonce = eth_tester.get_nonce(account)
        assert is_integer(nonce)
        assert nonce >= UINT256_MIN
        assert nonce <= UINT256_MAX


tx_gas = st.integers(min_value=0, max_value=10000000)
tx_gas_price = st.integers(min_value=1, max_value=1e15)
tx_value = st.integers(min_value=0, max_value=1e21)

transaction_st = st.tuples(
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'from': address}),
    ),
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'to': address}),
    ),
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'value': tx_value}),
    ),
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'gas': tx_gas}),
    ),
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'gas_price': tx_gas_price}),
    ),
).map(lambda parts: merge(*parts))


class EVMStateFuzzer(RuleBasedStateMachine):
    sent_transactions = Bundle('Transactions')

    def __init__(self, *args, **kwargs):
        from eth_tester import (
            EthereumTester,
            PyEthereum16Backend,
        )
        backend = PyEthereum16Backend()
        self.eth_tester = EthereumTester(backend=backend)
        super(EVMStateFuzzer, self).__init__(*args, **kwargs)

    @rule(target=sent_transactions, transaction=transaction_st)
    def send_transaction(self, transaction=transaction_st):
        transaction = {
            "from": self.eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        }
        transaction_hash = self.eth_tester.send_transaction(transaction)
        return (transaction, transaction_hash)

    @rule(sent_transaction=sent_transactions)
    def check_transaction_hashes(self, sent_transaction):
        transaction, transaction_hash = sent_transaction
        actual_transaction = self.eth_tester.get_transaction_by_hash(transaction_hash)
        assert actual_transaction['hash'] == transaction_hash
