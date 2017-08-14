from eth_utils import (
    is_address,
    is_same_address,
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
    assert is_same_address(coinbase, eth_tester.get_accounts()[0])


def test_web3_eth_getBalance(web3, eth_tester):
    coinbase = web3.eth.coinbase
    balance = web3.eth.getBalance(coinbase)
    assert balance == eth_tester.get_balance(coinbase)


def test_web3_eth_getCode_empty_account(web3, eth_tester):
    coinbase = web3.eth.coinbase
    code = web3.eth.getCode(coinbase)
    assert code == eth_tester.get_code(coinbase)


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


def test_web3_eth_getBlockByHash(web3, eth_tester):
    block_by_number = web3.eth.getBlock('latest')
    block = web3.eth.getBlock(block_by_number['hash'])
    assert block == block_by_number


def test_send_basic_transaction(web3, eth_tester):
    coinbase = web3.eth.coinbase
    transaction_hash = web3.eth.sendTransaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    transaction = eth_tester.get_transaction_by_hash(transaction_hash)
    assert is_same_address(transaction['from'], coinbase)
    assert is_same_address(transaction['to'], coinbase)
    assert transaction['gas'] == 21000
    assert transaction['value'] == 1


def test_get_transaction_by_hash(web3, eth_tester):
    coinbase = web3.eth.coinbase
    transaction_hash = web3.eth.sendTransaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    transaction = web3.eth.getTransaction(transaction_hash)
    assert is_same_address(transaction['from'], coinbase)
    assert is_same_address(transaction['to'], coinbase)
    assert transaction['gas'] == 21000
    assert transaction['value'] == 1


def test_get_transaction_receipt(web3, eth_tester):
    coinbase = web3.eth.coinbase
    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    transaction = eth_tester.get_transaction_by_hash(transaction_hash)
    receipt = web3.eth.getTransactionReceipt(transaction_hash)
    assert receipt['transactionHash'] == transaction_hash
