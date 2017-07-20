from hypothesis import (
    strategies as st,
    given,
    settings,
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


address = st.binary(
    min_size=20,
    max_size=20,
).map(to_normalized_address)


class BaseTestBackendDirect(object):
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

    def test_mine_block_single(self, eth_tester):
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.mine_blocks()
        after_block_number = eth_tester.get_latest_block()['number']
        assert is_integer(before_block_number)
        assert is_integer(after_block_number)
        assert before_block_number == after_block_number - 1

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
