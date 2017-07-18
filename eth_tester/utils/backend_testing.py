from eth_utils import is_address


class BaseTestEthereumTester(object):
    def test_get_accounts(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts
        assert all(
            is_address(account)
            for account
            in accounts
        )
