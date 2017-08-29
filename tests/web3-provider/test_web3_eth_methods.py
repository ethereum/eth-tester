from eth_utils import (
    is_address,
    is_same_address,
    keccak,
    encode_hex,
    decode_hex,
)


UNKNOWN_HASH = '0xdeadbeef00000000000000000000000000000000000000000000000000000000'


def test_eth_accounts(web3):
    accounts = web3.eth.accounts
    assert accounts
    assert all(is_address(account) for account in accounts)


def test_eth_blockNumber(web3, eth_tester):
    block_number = web3.eth.blockNumber
    assert block_number == eth_tester.get_block_by_number('latest')['number']


def test_eth_coinbase(web3, eth_tester):
    coinbase = web3.eth.coinbase
    assert is_same_address(coinbase, eth_tester.get_accounts()[0])


def test_eth_getBalance(web3, eth_tester):
    coinbase = web3.eth.coinbase
    balance = web3.eth.getBalance(coinbase)
    assert balance == eth_tester.get_balance(coinbase)


def test_eth_getCode_empty_account(web3, eth_tester):
    coinbase = web3.eth.coinbase
    code = web3.eth.getCode(coinbase)
    assert code == eth_tester.get_code(coinbase)


def test_eth_getTransactionCount(web3, eth_tester):
    coinbase = web3.eth.coinbase
    transaction_count = web3.eth.getTransactionCount(coinbase)
    assert transaction_count == 0


def test_eth_getBlockByNumber_with_number(web3):
    latest_block = web3.eth.getBlock(0)
    assert latest_block['number'] == 0


def test_eth_getBlockByNumber_with_latest(web3):
    latest_block = web3.eth.getBlock('latest')
    assert latest_block['number'] == web3.eth.blockNumber


def test_eth_getBlockByNumber_not_found(web3):
    block = web3.eth.getBlock(1234567890)
    assert block is None


def test_eth_getBlockByHash(web3, eth_tester):
    block_by_number = web3.eth.getBlock('latest')
    block = web3.eth.getBlock(block_by_number['hash'])
    assert block == block_by_number


def test_eth_getBlockByHash_not_found(web3, eth_tester):
    block = web3.eth.getBlock(UNKNOWN_HASH)
    assert block is None


def test_eth_sendTransaction(web3, eth_tester):
    coinbase = web3.eth.coinbase
    transaction_hash = web3.eth.sendTransaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    transaction = eth_tester.get_transaction_by_hash(transaction_hash)
    assert is_same_address(transaction['from'], coinbase)
    assert is_same_address(transaction['to'], coinbase)
    assert transaction['gas'] == 21000
    assert transaction['value'] == 1


def test_eth_getTransaction(web3, eth_tester):
    coinbase = web3.eth.coinbase
    transaction_hash = web3.eth.sendTransaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    transaction = web3.eth.getTransaction(transaction_hash)
    assert is_same_address(transaction['from'], coinbase)
    assert is_same_address(transaction['to'], coinbase)
    assert transaction['gas'] == 21000
    assert transaction['value'] == 1


def test_eth_getTransaction_not_found(web3):
    transaction = web3.eth.getTransaction(UNKNOWN_HASH)
    assert transaction is None


def test_eth_getTransactionReceipt(web3, eth_tester):
    coinbase = web3.eth.coinbase
    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    transaction = eth_tester.get_transaction_by_hash(transaction_hash)
    receipt = web3.eth.getTransactionReceipt(transaction_hash)
    assert receipt['transactionHash'] == transaction_hash


def test_eth_getTransactionReceipt_not_found(web3):
    receipt = web3.eth.getTransactionReceipt(UNKNOWN_HASH)
    assert receipt is None


def test_eth_getTransactionReceipt_not_mined(web3, eth_tester):
    eth_tester.disable_auto_mine_transactions()

    coinbase = web3.eth.coinbase
    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })

    unmined_receipt = eth_tester.get_transaction_receipt(transaction_hash)
    assert unmined_receipt['block_number'] is None

    receipt = web3.eth.getTransactionReceipt(transaction_hash)
    assert receipt is None


def test_sha3(web3):
    expected = encode_hex(keccak('test-value'))
    actual = web3.sha3(encode_hex('test-value'), encoding='hex')
    assert expected == actual


def test_eth_syncing(web3):
    actual = web3.eth.syncing
    assert actual is False


def test_eth_mining(web3):
    actual = web3.eth.mining
    assert actual is False


def test_eth_gasPrice(web3):
    actual = web3.eth.gasPrice
    assert actual == 1


def test_eth_hashrate(web3):
    actual = web3.eth.hashrate
    assert actual == 0


def test_eth_getBlockTransactionCountByHash_empty_block(web3, eth_tester):
    empty_block_hash = eth_tester.mine_block()

    transaction_count = web3.eth.getBlockTransactionCount(empty_block_hash)
    assert transaction_count == 0


def test_eth_getBlockTransactionCountByHash_block_with_txn(web3, eth_tester):
    coinbase = web3.eth.coinbase

    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    block_with_txn_hash = eth_tester.get_transaction_receipt(transaction_hash)['block_hash']

    transaction_count = web3.eth.getBlockTransactionCount(block_with_txn_hash)
    assert transaction_count == 1


def test_eth_getBlockTransactionCountByHash_not_found(web3):
    transaction_count = web3.eth.getBlockTransactionCount(UNKNOWN_HASH)
    assert transaction_count is None


def test_eth_getBlockTransactionCountByNumber_empty_block(web3, eth_tester):
    coinbase = web3.eth.coinbase
    empty_block_hash = eth_tester.mine_block()
    empty_block_number = eth_tester.get_block_by_hash(empty_block_hash)['number']

    transaction_count = web3.eth.getBlockTransactionCount(empty_block_number)
    assert transaction_count == 0


def test_eth_getBlockTransactionCountByNumber_block_with_txn(web3, eth_tester):
    coinbase = web3.eth.coinbase

    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    block_with_txn_number = eth_tester.get_transaction_receipt(transaction_hash)['block_number']

    transaction_count = web3.eth.getBlockTransactionCount(block_with_txn_number)
    assert transaction_count == 1


def test_eth_getBlockTransactionCountByNumber_not_found(web3):
    transaction_count = web3.eth.getBlockTransactionCount(1234567890)
    assert transaction_count is None


def test_eth_getTransactionByBlockHashAndIndex(web3, eth_tester):
    coinbase = web3.eth.coinbase

    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    block_hash = eth_tester.get_transaction_receipt(transaction_hash)['block_hash']

    transaction = web3.eth.getTransactionFromBlock(block_hash, 0)
    assert transaction['hash'] == transaction_hash


def test_eth_getTransactionByBlockHashAndIndex_block_not_found(web3, eth_tester):
    transaction = web3.eth.getTransactionFromBlock(UNKNOWN_HASH, 0)
    assert transaction is None


def test_eth_getTransactionByBlockHashAndIndex_index_not_found(web3, eth_tester):
    coinbase = web3.eth.coinbase

    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    block_hash = eth_tester.get_transaction_receipt(transaction_hash)['block_hash']

    transaction = web3.eth.getTransactionFromBlock(block_hash, 12345)
    assert transaction is None


def test_eth_getTransactionByBlockNumberAndIndex(web3, eth_tester):
    coinbase = web3.eth.coinbase

    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })
    block_number = eth_tester.get_transaction_receipt(transaction_hash)['block_number']

    transaction = web3.eth.getTransactionFromBlock(block_number, 0)
    assert transaction['hash'] == transaction_hash


def test_eth_getTransactionByBlockNumberAndIndex_block_not_found(web3, eth_tester):
    transaction = web3.eth.getTransactionFromBlock(1234567890, 0)
    assert transaction is None


def test_eth_getTransactionByBlockNumberAndIndex_index_not_found(web3, eth_tester):
    empty_block_hash = eth_tester.mine_block()
    empty_block_number = eth_tester.get_block_by_hash(empty_block_hash)['number']
    transaction = web3.eth.getTransactionFromBlock(empty_block_number, 1234)
    assert transaction is None


def test_eth_newFilter(web3, eth_tester):
    filter = web3.eth.filter({})
    filter_id = filter.filter_id

    assert not eth_tester.get_only_filter_changes(filter_id)


def test_eth_newBlockFilter(web3, eth_tester):
    filter = web3.eth.filter('latest')
    filter_id = filter.filter_id

    mined_block_hash = eth_tester.mine_block()

    block_hashes = eth_tester.get_only_filter_changes(filter_id)
    assert set([mined_block_hash]) == set(block_hashes)


def test_eth_newPendingTransactionFilter(web3, eth_tester):
    coinbase = web3.eth.coinbase
    filter = web3.eth.filter('pending')
    filter_id = filter.filter_id

    transaction_hash = eth_tester.send_transaction({
        'from': coinbase, 'to': coinbase, 'gas': 21000, 'value': 1,
    })

    transaction_hashes = eth_tester.get_only_filter_changes(filter_id)
    assert set([transaction_hash]) == set(transaction_hashes)


def test_eth_uninstallFilter(web3, eth_tester):
    filter = web3.eth.filter({})
    filter_id = filter.filter_id

    assert not eth_tester.get_only_filter_changes(filter_id)

    assert web3.eth.uninstallFilter(filter_id)
    assert not web3.eth.uninstallFilter(filter_id)


def test_eth_getFilterChanges(web3, eth_tester):
    filter_id = eth_tester.create_log_filter()

    assert not web3.eth.getFilterChanges(filter_id)


def test_eth_getFilterChanges_not_found(web3, eth_tester):
    assert web3.eth.getFilterChanges('0x12345') is None


def test_eth_getFilterLogs(web3, eth_tester):
    filter_id = eth_tester.create_log_filter()

    assert not web3.eth.getFilterLogs(filter_id)


def test_eth_getFilterLogs_not_found(web3, eth_tester):
    assert not web3.eth.getFilterLogs('0x12345')
