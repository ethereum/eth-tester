from eth_utils import (
    is_address,
)


def test_web3_eth_accounts(web3):
    accounts = web3.eth.accounts
    assert accounts
    assert all(is_address(account) for account in accounts)


def test_web3_eth_blockNumber(web3, eth_tester):
    block_number = web3.eth.blockNumber
    assert block_number == eth_tester.get_block_by_number('latest')['number']


def test_web3_eth_coinbase(web3, eth_tester):
    coinbase = web3.eth.coinbase
    assert coinbase == eth_tester.get_accounts()[0]
