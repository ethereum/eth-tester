from eth_utils import (
    is_address,
)


def test_web3_eth_accounts(web3):
    accounts = web3.eth.accounts
    assert accounts
    assert all(is_address(account) for account in accounts)
