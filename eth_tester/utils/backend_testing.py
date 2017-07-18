from hypothesis import (
    strategies as st,
    given,
    settings,
)

from eth_utils import (
    to_normalized_address,
    is_address,
    is_integer,
)


BALANCE_MIN = 0
BALANCE_MAX = 2**256 - 1


address = st.binary(
    min_size=20,
    max_size=20,
).map(to_normalized_address)


class BaseTestEthereumTester(object):
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
            assert balance >= BALANCE_MIN
            assert balance <= BALANCE_MAX

    @given(account=address)
    @settings(max_examples=10)
    def test_get_balance_simple_fuzzing(self, eth_tester, account):
        balance = eth_tester.get_balance(account)
        assert is_integer(balance)
        assert balance >= BALANCE_MIN
        assert balance <= BALANCE_MAX
