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


def test_web3_eth_getBalance(web3, eth_tester):
    coinbase = web3.eth.coinbase
    balance = web3.eth.getBalance(coinbase)
    assert balance == eth_tester.get_balance(coinbase)


def test_web3_eth_getTransactionCount(web3, eth_tester):
    coinbase = web3.eth.coinbase
    transaction_count = web3.eth.getTransactionCount(coinbase)
    assert transaction_count == 0


def test_web3_eth_getBlockByNumber_with_number(web3, eth_tester):
    latest_block = web3.eth.getBlock(0)
    assert latest_block['number'] == 0


def test_web3_eth_getBlockByNumber_with_latest(web3, eth_tester):
    latest_block = web3.eth.getBlock('latest')
    assert latest_block['number'] == web3.eth.blockNumber
