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
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.mine_blocks()
        after_block_number = eth_tester.get_latest_block()['number']
        assert is_integer(before_block_number)
        assert is_integer(after_block_number)
        assert before_block_number == after_block_number - 1

    def test_mine_multiple_blocks(self, eth_tester):
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.mine_blocks(10)
        after_block_number = eth_tester.get_latest_block()['number']
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
        eth_tester.configure(auto_mine_transactions=True)
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        after_block_number = eth_tester.get_latest_block()['number']
        assert before_block_number == after_block_number - 1

    def test_auto_mine_transactions_disabled(self, eth_tester):
        eth_tester.configure(auto_mine_transactions=False)
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        after_block_number = eth_tester.get_latest_block()['number']
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

    # TODO: get_block_by_number('latest')
    # TODO: get_block_by_number('earliest')

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
        assert receipt is None

    #
    # Filters
    #
    def test_block_filter(self, eth_tester):
        # first mine 10 blocks in
        blocks_0_to_9 = eth_tester.mine_blocks(10)

        # setup a filter
        filter_a_id = eth_tester.create_block_filter()

        # mine another 5 blocks
        blocks_10_to_14 = eth_tester.mine_blocks(5)

        # setup another filter
        filter_b_id = eth_tester.create_block_filter()

        # mine another 8 blocks
        blocks_15_to_22 = eth_tester.mine_blocks(8)

        filter_a_changes_part_1 = eth_tester.get_filter_changes(filter_a_id)
        filter_a_logs_part_1 = eth_tester.get_filter_logs(filter_a_id)
        filter_b_logs_part_1 = eth_tester.get_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_1) == 13
        assert len(filter_a_logs_part_1) == 13
        assert len(filter_b_logs_part_1) == 8

        # mine another 7 blocks
        blocks_23_to_29 = eth_tester.mine_blocks(7)

        filter_a_changes_part_2 = eth_tester.get_filter_changes(filter_a_id)
        filter_b_changes = eth_tester.get_filter_changes(filter_b_id)
        filter_a_logs_part_2 = eth_tester.get_filter_logs(filter_a_id)
        filter_b_logs_part_2 = eth_tester.get_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_2) == 7
        assert len(filter_b_changes) == 15
        assert len(filter_a_logs_part_2) == 20
        assert len(filter_b_logs_part_2) == 15



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

    #@rule(target=transactions, transaction=transaction_st)
    @rule(target=sent_transactions)
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
