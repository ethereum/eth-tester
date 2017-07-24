import pytest

from toolz.dicttoolz import (
    merge,
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
)

from eth_tester.constants import (
    UINT256_MIN,
    UINT256_MAX,
    BURN_ADDRESS,
)
from eth_tester.exceptions import (
    FilterNotFound,
)

from .emitter import (
    _deploy_emitter,
    _call_emitter,
    EMITTER_ENUM,
)


class BaseTestBackendDirect(object):
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

        transaction = {
            "from": accounts[0],
            "to": BURN_ADDRESS,
            "gas_price": 1,
            "value": 0,
            "gas": 21000,
        }
        txn_hash = eth_tester.send_transaction(transaction)
        txn = eth_tester.get_transaction_by_hash(txn_hash)

        assert is_same_address(txn['from'], transaction['from'])
        assert is_same_address(txn['to'], transaction['to'])
        assert txn['gas_price'] == transaction['gas_price']
        assert txn['gas'] == transaction['gas']
        assert txn['value'] == transaction['value']

    def test_auto_mine_transactions_enabled(self, eth_tester):
        eth_tester.mine_blocks()
        eth_tester.configure(auto_mine_transactions=True)
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
        eth_tester.configure(auto_mine_transactions=False)
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

    def test_get_genesis_block_by_hash(self, eth_tester):
        genesis_hash = eth_tester.get_block_by_number(0)['hash']
        block = eth_tester.get_block_by_hash(genesis_hash)
        assert block['number'] == 0

    def test_get_block_by_number(self, eth_tester):
        mined_block_hashes = eth_tester.mine_blocks(10)
        for block_number, block_hash in enumerate(mined_block_hashes):
            block = eth_tester.get_block_by_number(block_number)
            assert block['number'] == block_number
            assert block['hash'] == block_hash

    def test_get_block_by_hash(self, eth_tester):
        mined_block_hashes = eth_tester.mine_blocks(10)
        for block_number, block_hash in enumerate(mined_block_hashes):
            block = eth_tester.get_block_by_hash(block_hash)
            assert block['number'] == block_number
            assert block['hash'] == block_hash

    def test_get_block_by_earliest(self, eth_tester):
        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number('earliest')
        assert block['number'] == 0

    def test_get_block_by_latest_unmined_genesis(self, eth_tester):
        block = eth_tester.get_block_by_number('latest')
        assert block['number'] == 0

    def test_get_block_by_latest_only_genesis(self, eth_tester):
        eth_tester.mine_blocks()
        block = eth_tester.get_block_by_number('latest')
        assert block['number'] == 0

    def test_get_block_by_latest(self, eth_tester):
        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number('latest')
        assert block['number'] == 9

    def test_get_block_by_pending(self, eth_tester):
        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number('pending')
        assert block['number'] == 10

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
        eth_tester.configure(auto_mine_transactions=False)
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt['block_number'] is None

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
        assert set(filter_a_logs_part_2) == set(blocks_10_to_14).union(blocks_15_to_22).union(blocks_23_to_29)
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
        assert set(filter_a_logs_part_2) == set(transactions_0_to_7).union(transactions_8_to_12).union(transactions_13_to_20)
        assert set(filter_b_logs_part_2) == set(transactions_8_to_12).union(transactions_13_to_20)

    def test_log_filter_picks_up_new_logs(self, eth_tester):
        """
        Cases to test:
        - filter multiple transactions in one block.
        - filter pending (make sure that from_block and to_block checks don't skip these).
        - filter mined.
        - filter against topics.
        - filter against blocks numbers that are already mined.
        """
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
        - filter pending (make sure that from_block and to_block checks don't skip these).
        - filter mined.
        - filter against topics.
        - filter against blocks numbers that are already mined.
        """
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
