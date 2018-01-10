# Ethereum Tester

[![Join the chat at https://gitter.im/ethereum/eth-tester](https://badges.gitter.im/ethereum/eth-tester.svg)](https://gitter.im/ethereum/eth-tester)

[![Build Status](https://travis-ci.org/ethereum/eth-tester.png)](https://travis-ci.org/ethereum/eth-tester)


Tools for testing ethereum based applications.


## Installation

```sh
pip install eth-tester
```


## Quick Start

```python
>>> from eth_tester import EthereumTester
>>> t = EthereumTester()
>>> t.get_accounts()
('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1',
 '0x7d577a597B2742b498Cb5Cf0C26cDCD726d39E6e',
 '0xDCEceAF3fc5C0a63d195d69b1A90011B7B19650D',
 '0x598443F1880Ef585B21f1d7585Bd0577402861E5',
 '0x13cBB8D99C6C4e0f2728C7d72606e78A29C4E224',
 '0x77dB2BEBBA79Db42a978F896968f4afCE746ea1F',
 '0x24143873e0E0815fdCBcfFDbe09C979CbF9Ad013',
 '0x10A1c1CB95c92EC31D3f22C66Eef1d9f3F258c6B',
 '0xe0FC04FA2d34a66B779fd5CEe748268032a146c0',
 '0x90F0B1EBbbA1C1936aFF7AAf20a7878FF9e04B6c')
>>> t.get_balance('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1')
1000000000000000000000000
>>> t.send_transaction({'from': '0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1', 'to': '0x7d577a597B2742b498Cb5Cf0C26cDCD726d39E6e', 'gas': 21000, 'value': 1})
'0x140c1da1370a908e4c0f7c6e33bb97182011707c6a9aff954bef1084c8a48b25'
>>> t.get_transaction_by_hash(0x140c1da1370a908e4c0f7c6e33bb97182011707c6a9aff954bef1084c8a48b25')
{'block_hash': '0x89c03ecb6bbf3ff533b04a663fa98d59c9d985de806d1a9dcafaad7c993ee6e8',
 'block_number': 0,
 'data': '0x',
 'from': '0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1',
 'gas': 21000,
 'gas_price': 1,
 'hash': '0x140c1da1370a908e4c0f7c6e33bb97182011707c6a9aff954bef1084c8a48b25',
 'nonce': 0,
 'r': 114833774457827084417823702749930473879683934597320921824765632039428214735160,
 's': 52192522150044217242428968890330558187037131043598164958282684822175843828481,
 'to': '0x7d577a597B2742b498Cb5Cf0C26cDCD726d39E6e',
 'transaction_index': 0,
 'v': 27,
 'value': 1}

>>> t.get_transaction_receipt('0x140c1da1370a908e4c0f7c6e33bb97182011707c6a9aff954bef1084c8a48b25')
{'block_hash': '0x89c03ecb6bbf3ff533b04a663fa98d59c9d985de806d1a9dcafaad7c993ee6e8',
 'block_number': 0,
 'contract_address': None,
 'cumulative_gas_used': 21000,
 'gas_used': 21000,
 'logs': (),
 'transaction_hash': '0x140c1da1370a908e4c0f7c6e33bb97182011707c6a9aff954bef1084c8a48b25',
 'transaction_index': 0}
```


## Development

```sh
pip install -e . -r requirements-dev.txt
```


### Running the tests

You can run the tests with:

```sh
py.test tests
```

Or you can install `tox` to run the full test suite.


### Releasing

Pandoc is required for transforming the markdown README to the proper format to
render correctly on pypi.

For Debian-like systems:

```
apt install pandoc
```

Or on OSX:

```sh
brew install pandoc
```

To release a new version:

```sh
bumpversion $$VERSION_PART_TO_BUMP$$
git push && git push --tags
make release
```


#### How to bumpversion

The version format for this repo is `{major}.{minor}.{patch}` for stable, and
`{major}.{minor}.{patch}-{stage}.{devnum}` for unstable (`stage` can be alpha or beta).

To issue the next version in line, use bumpversion and specify which part to bump,
like `bumpversion minor` or `bumpversion devnum`.

If you are in a beta version, `bumpversion stage` will switch to a stable.

To issue an unstable version when the current version is stable, specify the
new version explicitly, like `bumpversion --new-version 4.0.0-alpha.1 devnum`


# Documentation

## Input and output data formats

The ethereum tester library strictly enforces the following input formats and
types.

* Hexidecimal values **must** be text (not byte) strings.  The `0x` prefix is optional.
* Any address which contains mixed-case alpha characters will be validated as a checksummed address as specified by [EIP-55](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md)
* 32-byte hashes **must** be hexidecimal encoded.
* Numeric values **must** be in their integer representation.

Similarly, ethereum tester ensures that return values conform to similar rules.

* 32-byte hashes will be returned in their hexidecimal encoded representation.
* Addresses will be returned in their hexidecimal representation and EIP55 checksummed.
* Numeric values will be returned as integers.


## Block Numbers
<a id="block-numbers"></a>

Any `block_number` parameter will accept the following string values.

* `'latest'`: for the latest mined block.
* `'pending'`: for the current un-mined block.
* `'earliest'`: for the genesis block.

> Note: These **must** be text strings (not byte stringS)


## `eth_tester.EthereumTester`

### API

### Instantiation

* `eth_tester.EthereumTester(backend=None, validator=None, normalizer=None, auto_mine_transactions=True, fork_blocks=None)`

The `EthereumTester` object is the sole API entrypoint.  Instantiation of this
object accepts the following parameters.

- `backend`: The chain backend being used.  See the [chain backends](#chain-backends)
- `validator`: The validator to used.  See the [validators](#validation)
- `normalizer`: The normalizer to used.  See the [normalizers](#normalization)
- `auto_mine_transactions`: If *truthy* transactions will be automatically mined at the time they are submitted.  See [`enable_auto_mine_transactions`](#api-enable_auto_mine_transactions) and [`disable_auto_mine_transactions`](#api-disable_auto_mine_transactions).
- `fork_blocks`: configures which block numbers the various network hard fork rules will be activated.  See [fork-rules](#fork-rules)


```python
>>> from eth_tester import EthereumTester
>>> t = EthereumTester()
>>> t
<eth_tester.main.EthereumTester at 0x102255710>
```


### Fork Rules
<a id="fork-rules"></a>

Ethereum tester supports the following hard forks.

- Homestead
- DAO
- Anti DOS
- State Clearing

By default, all forks will be active at the genesis block (block 0).

Manual configuration and retrieval of fork rules can be done with the following
API.

#### `EthereumTester.set_fork_block(fork_name, fork_block)`

Sets the fork rules for the fork denoted by `fork_name` to activate at `fork_block`.

#### `EthereumTester.get_fork_block(fork_name)`

Returns the block number on which the named fork will activate.


The `fork_name` parameter must be one of the following strings.

- `"FORK_HOMESTEAD"`
- `"FORK_DAO"`
- `"FORK_ANTI_DOS"`
- `"FORK_STATE_CLEANUP"`


### Time Travel
<a id="time-travel"></a>

The chain can only time travel forward in time.

<a id="api-time_travel"></a>
#### `EthereumTester.time_travel(timestamp)`

The `timestamp` must be an integer, strictly greater than the current timestamp
of the latest block.  

> Note: Time traveling will result in a new block being mined.


### Mining

Manually mining blocks can be done with the following API.  The `coinbase`
parameter of these methods **must** be a hexidecimal encoded address.

<a id="api-mine_blocks"></a>
#### `EthereumTester.mine_blocks(num_blocks=1, coinbase=None)`

Mines `num_blocks` new blocks, returning an iterable of the newly mined block hashes.


<a id="api-mine_block"></a>
#### `EthereumTester.mine_block(coinbase=None)`

Mines a single new block, returning the mined block's hash.


<a id="api-auto_mine_transactions"></a>
#### Auto-mining transactions

By default all transactions are mined immediately.  This means that each transaction you send will result in a new block being mined, and that all blocks will only ever have at most a single transaction.  This behavior can be controlled with the following methods.

<a id="api-enable_auto_mine_transactions"></a>
#### `EthereumTester.enable_auto_mine_transactions()`

Turns on auto-mining of transactions.

<a id="api-disable_auto_mine_transactions"></a>
#### `EthereumTester.disable_auto_mine_transactions()`

Turns **off** auto-mining of transactions.


### Accounts

The following API can be used to interact with account data.  The `account`
parameter in these methods **must** be a hexidecimal encode address.

<a id="api-get_accounts"></a>
 `EthereumTester.get_accounts()`

Returns an iterable of the accounts that the tester knows about.  All accounts
in this list will be EIP55 checksummed.

```python
>>> t.get_accounts()
('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1',
 '0x7d577a597B2742b498Cb5Cf0C26cDCD726d39E6e',
 ...
 '0x90F0B1EBbbA1C1936aFF7AAf20a7878FF9e04B6c')
```


<a id="api-add_account"></a>
#### `EthereumTester.add_account(private_key, password=None)`

Adds a new account for the given private key.  Returns the hex encoded address
of the added account.

```python
>>> t.add_account('0x58d23b55bc9cdce1f18c2500f40ff4ab7245df9a89505e9b1fa4851f623d241d')
'0xdc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd'
```

By default, added accounts are unlocked and do not have a password.  If you
would like to add an account which has a password, you can supply the password
as the second parameter.

```python
>>> t.add_account('0x58d23b55bc9cdce1f18c2500f40ff4ab7245df9a89505e9b1fa4851f623d241d', 'my-secret')
'0xdc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd'
```


<a id="api-unlock_account"></a>
#### `EthereumTester.unlock_account(account, password, unlock_seconds=None)`

Unlocks the given account if the provided password matches.

Raises a `ValidationError` if:

* The account is not known.
* The password does not match.
* The account was created without a password.

```python
>>> t.unlock_account('0xdc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd', 'my-secret')
```

By default, accounts will be unlocked indefinitely.  You can however unlock an
account for a specified amount of time by providing the desired duration in
seconds.

```python
# unlock for 1 hour.
>>> t.unlock_account('0xdc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd', 'my-secret', 60 * 60)
```


<a id="api-unlock_account"></a>
#### `EthereumTester.lock_account(account)`

Locks the provide account.  

Raises a `ValidationError` if:

* The account is not known
* The account does not have a password.


<a id="api-get_balance"></a>
#### `EthereumTester.get_balance(account) -> integer`

Returns the balance, in wei, for the provided account.

```python
>>> t.get_balance('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1')
1000004999999999999999999
```


<a id="api-get_nonce"></a>
#### `EthereumTester.get_nonce(account) -> integer`

Returns the nonce for the provided account.

```python
>>> t.get_nonce('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1')
1
```

<a id="api-get_code"></a>
#### `EthereumTester.get_code(account) -> hex string`

Returns the code for the given account.

```python
>>> t.get_code('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1')
"0x"
```


### Blocks, Transactions, and Receipts

<a id="api-get_transaction_by_hash"></a>
#### `EthereumTester.get_transaction_by_hash(transaction_hash) -> transaction-object`

Returns the transaction for the given hash, raising a
[`TransactionNotFound`](#errors-TransactionNotFound) exception if the
transaction cannot be found.

```python
>>> t.get_transaction_by_hash('0x140c1da1370a908e4c0f7c6e33bb97182011707c6a9aff954bef1084c8a48b25')
{'block_hash': '0x89c03ecb6bbf3ff533b04a663fa98d59c9d985de806d1a9dcafaad7c993ee6e8',
 'block_number': 0,
 'hash': '0x140c1da1370a908e4c0f7c6e33bb97182011707c6a9aff954bef1084c8a48b25',
 'transaction_index': 0,
 'from': '0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1',
 'to': '0x7d577a597B2742b498Cb5Cf0C26cDCD726d39E6e',
 'value': 1,
 'gas': 21000,
 'gas_price': 1,
 'nonce': 0,
 'data': '0x',
 'v': 27,
 'r': 114833774457827084417823702749930473879683934597320921824765632039428214735160,
 's': 52192522150044217242428968890330558187037131043598164958282684822175843828481}
```

> Note: For unmined transaction, `transaction_index`, `block_number` and `block_hash` will all be `None`.


<a id="api-get_block_by_numbera>
#### `EthereumTester.get_block_by_number(block_number, full_transactions=False) -> block-object`

Returns the block for the given `block_number`.  See [block
numbers](#block-numbers) for named block numbers you can use.  If
`full_transactions` is truthy, then the transactions array will be populated
with full transaction objects as opposed to their hashes.

Raises [`BlockNotFound`](#errors-BlockNotFound) if a block for the given number
cannot be found.

```python
>>> t.get_block_by_numbers(1)
{'difficulty': 131072,
 'extra_data': '0x0000000000000000000000000000000000000000000000000000000000000000',
 'gas_limit': 999023468,
 'gas_used': 0,
 'hash': '0x0f50c8ea0f67ce0b7bff51ae866159edc443bde87de2ab26010a15b777244ddd',
 'logs_bloom': 0,
 'miner': '0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1',
 'nonce': '0x0000000000000000',
 'number': 1,
 'parent_hash': '0x89c03ecb6bbf3ff533b04a663fa98d59c9d985de806d1a9dcafaad7c993ee6e8',
 'sha3_uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',
 'size': 472,
 'state_root': '0xbd92123803c9e71018617ce3dc6cbbdf130973bdbd0e14ff340c57c8a835b74b',
 'timestamp': 1410973360,
 'total_difficulty': 262144,
 'transactions': (),
 'transactions_root': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421',
 'uncles': ()}
```


<a id="api-get_block_by_hash"></a>
#### `EthereumTester.get_block_by_hash(block_hash, full_transactions=True) -> block-object`

Returns the block for the given `block_hash`.  The `full_transactions`
parameter behaves the same as in
[`get_block_by_number`](#api-get_block_by_number).

Raises [`BlockNotFound`](#errors-BlockNotFound) if a block for the given hash
cannot be found.

```python
>>> t.get_block_by_hash('0x0f50c8ea0f67ce0b7bff51ae866159edc443bde87de2ab26010a15b777244ddd')
{'difficulty': 131072,
 'extra_data': '0x0000000000000000000000000000000000000000000000000000000000000000',
 'gas_limit': 999023468,
 'gas_used': 0,
 'hash': '0x0f50c8ea0f67ce0b7bff51ae866159edc443bde87de2ab26010a15b777244ddd',
 'logs_bloom': 0,
 'miner': '0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1',
 'nonce': '0x0000000000000000',
 'number': 1,
 'parent_hash': '0x89c03ecb6bbf3ff533b04a663fa98d59c9d985de806d1a9dcafaad7c993ee6e8',
 'sha3_uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',
 'size': 472,
 'state_root': '0xbd92123803c9e71018617ce3dc6cbbdf130973bdbd0e14ff340c57c8a835b74b',
 'timestamp': 1410973360,
 'total_difficulty': 262144,
 'transactions': (),
 'transactions_root': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421',
 'uncles': ()}
```

<a id="api-get_transaction_receipt"></a>
#### `EthereumTester.get_transaction_receipt(transaction_hash)`

Returns the receipt for the given `transaction_hash`, raising
[`TransactionNotFound`](#errors-TransactionNotFound) if no transaction can be
found for the given hash.


```python
>>> t.get_transaction_receipt('0x9a7cc8b7accf54ecb1901bf4d0178f28ca457bb9f9c245692c0ca8fabef08d3b')
 {'block_hash': '0x878f779d8bb25b25fb78fc16b8d64d70a5961310ef1689571aec632e9424290c',
 'block_number': 2,
 'contract_address': None,
 'cumulative_gas_used': 23154,
 'gas_used': 23154,
 'logs': ({'address': '0xd6F084Ee15E38c4f7e091f8DD0FE6Fe4a0E203Ef',
   'block_hash': '0x878f779d8bb25b25fb78fc16b8d64d70a5961310ef1689571aec632e9424290c',
   'block_number': 2,
   'data': '0x',
   'log_index': 0,
   'topics': (
    '0xf70fe689e290d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb15',
    '0x0000000000000000000000000000000000000000000000000000000000003039'),
   'transaction_hash': '0x9a7cc8b7accf54ecb1901bf4d0178f28ca457bb9f9c245692c0ca8fabef08d3b',
   'transaction_index': 0,
   'type': 'mined'},),
 'transaction_hash': '0x9a7cc8b7accf54ecb1901bf4d0178f28ca457bb9f9c245692c0ca8fabef08d3b',
 'transaction_index': 0}
```

- Receipts for unmined transactions will have all of `block_hash`, `block_number` and `transaction_index` set to `None`.  
- Receipts for transactions which create a contract will have the created contract address in the `contract_address` field.


### Transaction Sending

A transaction is a formatted as a dictionary with the following keys and
values.

* `from`: The address of the account sending the transaction (hexidecimal string).
* `to`: The address of the account the transaction is being sent to.  Empty string should be used to trigger contract creation (hexidecimal string).
* `gas`: Sets the gas limit for transaction execution (integer).
* `gas_price`: Sets the price per unit of gas in wei that will be paid for transaction execution (integer).
* `value`: The amount of ether in wei that should be sent with the transaction (integer).
* `data`: The data for the transaction (hexidecimal string).


#### Methods

<a id="api-send_transaction"></a>
#### `EthereumTester.send_transaction(transaction) -> transaction_hash`

Sends the provided `transaction` object, returning the `transaction_hash` for
the sent transaction.


<a id="api-call"></a>
#### `EthereumTester.call(transaction, block_number='latest')`

Executes the provided `transaction` object at the evm state from the block
denoted by the `block_number` parameter, returning the resulting bytes return
value from the evm.

<a id="api-estimate_gas"></a>
#### `EthereumTester.estimate_gas(transaction)`

Executes the provided `transaction` object, measuring and returning the gas
consumption.


### Logs and Filters

<a id="api-create_block_filter"></a>
#### `EthereumTester.create_block_filter() -> integer`

Creates a new filter for newly mined blocks.  Returns the `filter_id` which can
be used to retrieve the block hashes for the mined blocks.

```python
>>> filter_id = t.create_block_filter()
>>> filter_id = t.create_block_filter()
>>> t.mine_blocks(3)
>>> t.get_only_filter_changes(filter_id)
('0x07004287f82c1a7ab15d7b8baa03ac14d7e9167ab74e47e1dc4bd2213dd18431',
 '0x5e3222c506585e1202da08c7231afdc5e472c777c245b822f44f141d335c744a',
 '0x4051c3ba3dcca95da5db1be38e44f5b47fd1a855ba522123e3254fe3f8e271ea')
>>> t.mine_blocks(2)
>>> t.get_only_filter_changes(filter_id)
('0x6649c3a7cb3c7ede3a4fd10ae9dd63775eccdafe39ace5f5a9ae81d360089fba',
 '0x04890a08bca0ed2f1496eb29c5dc7aa66014c85377c6d9d9c2c315f85204b39c')
>>> t.get_all_filter_logs(filter_id)
('0x07004287f82c1a7ab15d7b8baa03ac14d7e9167ab74e47e1dc4bd2213dd18431',
 '0x5e3222c506585e1202da08c7231afdc5e472c777c245b822f44f141d335c744a',
 '0x4051c3ba3dcca95da5db1be38e44f5b47fd1a855ba522123e3254fe3f8e271ea',
 '0x6649c3a7cb3c7ede3a4fd10ae9dd63775eccdafe39ace5f5a9ae81d360089fba',
 '0x04890a08bca0ed2f1496eb29c5dc7aa66014c85377c6d9d9c2c315f85204b39c')
```

<a id="api-create_pending_transaction_filter"></a>
#### `EthereumTester.create_pending_transaction_filter() -> integer`

Creates a new filter for pending transactions.  Returns the `filter_id` which
can be used to retrieve the transaction hashes for the pending transactions.

```python
>>> filter_id = t.create_pending_transaction_filter()
>>> t.send_transaction({...})
'0x07f20bf9586e373ac914a40e99119c4932bee343d89ba852ccfc9af1fd541566'
>>> t.send_transaction({...})
'0xff85f7751d132b66c03e548e736f870797b0f24f3ed41dfe5fc628eb2cbc3505'
>>> t.get_only_filter_changes(filter_id)
('0x07f20bf9586e373ac914a40e99119c4932bee343d89ba852ccfc9af1fd541566',
 '0xff85f7751d132b66c03e548e736f870797b0f24f3ed41dfe5fc628eb2cbc3505')
>>> t.send_transaction({...})
'0xb07801f7e8b1cfa52b64271fa2673c4b8d64cc21cdbc5fde51d5858c94c2d26a'
>>> t.get_only_filter_changes(filter_id)
('0xb07801f7e8b1cfa52b64271fa2673c4b8d64cc21cdbc5fde51d5858c94c2d26a',)
>>> t.get_all_filter_logs(filter_id)
('0x07f20bf9586e373ac914a40e99119c4932bee343d89ba852ccfc9af1fd541566',
 '0xff85f7751d132b66c03e548e736f870797b0f24f3ed41dfe5fc628eb2cbc3505',
 '0xb07801f7e8b1cfa52b64271fa2673c4b8d64cc21cdbc5fde51d5858c94c2d26a')
```

<a id="api-create_log_filter"></a>
#### `EthereumTester.create_log_filter(from_block=None, to_block=None, address=None, topics=None) -> integer`

Creates a new filter for logs produced by transactions.  The parameters for
this function can be used to filter the log entries.  

```python
>>> filter_id = t.create_log_filter()
>>> t.send_transaction({...})  # something that produces a log entry
'0x728bf75fc7d23845f328d2223df7fe9cafc6e7d23792457b625d5b60d2b22b7c'
>>> t.send_transaction({...})  # something that produces a log entry
'0x63f5b381ffd09940ce22c45a3f4e163bd743851cb6b4f43771fbf0b3c14b2f8a'
>>> t.get_only_filter_changes(filter_id)
({'address': '0xd6F084Ee15E38c4f7e091f8DD0FE6Fe4a0E203Ef',
  'block_hash': '0x68c0f318388003b652eae334efbed8bd345c469bd0ca77469183fc9693c23e13',
  'block_number': 11,
  'data': '0x',
  'log_index': 0,
  'topics': ('0xf70fe689e290d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb15',
   '0x0000000000000000000000000000000000000000000000000000000000003039'),
  'transaction_hash': '0x728bf75fc7d23845f328d2223df7fe9cafc6e7d23792457b625d5b60d2b22b7c',
  'transaction_index': 0,
  'type': 'mined'},
 {'address': '0xd6F084Ee15E38c4f7e091f8DD0FE6Fe4a0E203Ef',
  'block_hash': '0x07d7e46be6f9ba53ecd4323fb99ec656e652c4b14f4b8e8a244ee7f997464725',
  'block_number': 12,
  'data': '0x',
  'log_index': 0,
  'topics': ('0xf70fe689e290d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb15',
   '0x0000000000000000000000000000000000000000000000000000000000010932'),
  'transaction_hash': '0x63f5b381ffd09940ce22c45a3f4e163bd743851cb6b4f43771fbf0b3c14b2f8a',
  'transaction_index': 0,
  'type': 'mined'})
```

See [the filtering guide](#guide-filtering) for detailed information on how to use filters.

<a id="api-delete_filter"></a>
#### `EthereumTester.delete_filter(filter_id)`

Removes the filter for the provide `filter_id`.  If no filter is found for the
given `filter_id`, raises [`FilterNotFound`](#errors-FilterNotFound).


<a id="api-get_only_filter_changes"></a>
#### `EthereumTester.get_only_filter_changes(filter_id) -> transaction_hash or block_hash or log_entry`

Returns all new values for the provided `filter_id` that have not previously
been returned through this API.  Raises
[`FilterNotFound`](#errors-FilterNotFound) if no filter is found for the given
`filter_id`.

<a id="api-get_only_filter_changes"></a>
#### `EthereumTester.get_all_filter_logs(filter_id) -> transaction_hash or block_hash or log_entry`

Returns all values for the provided `filter_id`. Raises
[`FilterNotFound`](#errors-FilterNotFound) if no filter is found for the given
`filter_id`.


### Snapshots and Resetting

<a id="api-take_snapshot"></a>
#### `EthereumTester.take_snapshot() -> snapshot_id`

Takes a snapshot of the current chain state and returns the snapshot id.


<a id="api-revert_to_snapshot"></a>
#### `EthereumTester.revert_to_snapshot(snapshot_id)`

Reverts the chain to the chain state associated with the given `snapshot_id`.
Raises [`SnapshotNotFound`](#errors-SnapshotNotFound) if no snapshot is know
for the given id.

### Errors and Exceptions

<a id="errors-TransactionNotFound"></a>
#### `eth_tester.exceptions.TransactionNotFound`

Raised in cases where a transaction cannot be found for the provided transaction hash.


<a id="errors-BlockNotFound"></a>
#### `eth_tester.exceptions.BlockNotFound`

Raised in cases where a block cannot be found for either a provided number or
hash.


<a id="errors-FilterNotFound"></a>
#### `eth_tester.exceptions.FilterNotFound`

Raised in cases where a filter cannot be found for the provided filter id.


<a id="errors-SnapshotNotFound"></a>
#### `eth_tester.exceptions.SnapshotNotFound`

Raised in cases where a snapshot cannot be found for the provided snapshot id.


## Backends

Ethereum tester is written using a pluggable backend system.

### Backend Dependencies

Ethereum tester does not install any of the dependencies needed to use the
various backends by default.  You can however install ethereum tester with the
necessary dependencies using the following method.

```bash
$ pip install eth-tester[<backend-name>]
```

You should replace `<backend-name>` with the name of the desired testing
backend.  Available backends are:

* `pyethereum16`: [PyEthereum v1.6.x](https://pypi.python.org/pypi/ethereum/1.6.1)
* `pyethereum21`: [PyEthereum v2.1.0+](https://pypi.python.org/pypi/ethereum)
* `py-evm`: [PyEVM (alpha)](https://pypi.python.org/pypi/py-evm) **(experimental)**

### Selecting a Backend

You can select which backend in a few different ways.

The most direct way is to manually pass in the backend instance you wish to
use.

```python
>>> from eth_tester import EthereumTester
>>> from eth_tester.backends.pyethereum import PyEthereum16Backend
>>> t = EthereumTester(backend=PyEthereum16Backend())
```

Ethereum tester also supports configuration using the environment variable
`ETHEREUM_TESTER_CHAIN_BACKEND`.  This should be set to the import path for the
backend class you wish to use.

### Available Backends

Ethereum tester can be used with the following backends.

* PyEthereum 1.6.x (default)
* PyEthereum 2.0.0+ (experimental)
* PyEVM (experimental)
* MockBackend

#### MockBackend

This backend has limited functionality.  It cannot perform any VM computations.
It mocks out all of the objects and interactions.

```python
>>> from eth_tester import MockBackend
>>> t = EthereumTester(MockBackend())
```

#### PyEthereum 1.6.x

Uses the PyEthereum library at version `v1.6.x`

```python
>>> from eth_tester import PyEthereum16Backend
>>> t = EthereumTester(PyEthereum16Backend())
```

#### PyEthereum 2.0.0+

Uses the PyEthereum library at version `v2.0.0+`

```python
>>> from eth_tester import PyEthereum21Backend
>>> t = EthereumTester(PyEthereum21Backend())
```

#### PyEVM (experimental)

> **WARNING** Py-EVM is experimental and should not be relied on for mission critical testing at this stage.

Uses the experimental Py-EVM library.

```python
>>> from eth_tester import PyEVMBackend
>>> t = EthereumTester(PyEVMBackend())
```

#### PyEthereum 2.0.x (under development)

> Under development

### Implementing Custom Backends

The base class `eth_tester.backends.base.BaseChainBackend` is the recommended
base class to begin with if you wish to write your own backend.  

Details on implementation are beyond the scope of this document.


## Data Formats

Ethereum tester uses two formats for data.  

* The *normal* format is the data format the is expected as input arguments to all `EthereumTester` methods as well as the return types from all method calls.
* The *canonical* format is the data format that is used internally by the backend class.

Ethereum tester enforces strict validation rules on these formats.

### Canonical Formats

The canonical format is intended for low level handling by backends.

* 32 byte hashes: `bytes` of length 32
* Arbitrary length strings: `bytes`
* Addresses: `bytes` of length 20
* Integers: `int`
* Array Types: `tuple`

### Normal Formats

The normal format is intended for use by end users.

* 32 byte hashes: `0x` prefixed hexidecimal encoded text strings (not byte strings)
* Arbitrary length strings: `0x` prefixed hexidecimal encoded text strings (not byte strings)
* Addresses: `0x` prefixed and EIP55 checksummed hexidecimal encoded text strings (not byte strings)
* Integers: `int`
* Array Types: `tuple`


## Normalization and Validation

> Beware! Here there be dragons...  This section of the documentation is only
> relevant if you intend to build tooling on top of this library.

The ethereum tester provides strong guarantees that backends can be swapped out
seamlessly without effecting the data formats of both the input arguments and
return values.  This is accomplished using a two step process of strict
*normalization* and *validation*.

All inputs to the methods of the `EthereumTester` are first validated then
normalized to a *canonical* format.  Return values are put through this process
as well, first validating the data returned by the backend, and then
normalizing it from the *canonical* format to the *normal* form before being
returned.


<a id="normalization"></a>
### Normalization

The `EthereumTester` delegates normalization to whatever `normalizer` was
passed in during instantiation.  If no value was provided, the default
normalizer will be used from
`eth_tester.normalization.default.DefaultNormalizer`.

The specifics of this object are beyong the scope of this document.

<a id="validation"></a>
### Validation

The `EthereumTester` delegates validation to whatever `validator` was
passed in during instantiation.  If no value was provided, the default
validator will be used from
`eth_tester.validation.default.DefaultValidator`.

The specifics of this object are beyong the scope of this document.


# Use with Web3.py

See the [web3.py documentation](http://web3py.readthedocs.io/en/latest/) for
information on the `EthereumTester` provider which integrates with this
library.


# Development

```sh
pip install -e . -r requirements-dev.txt
```


## Running the tests

You can run the tests with:

```sh
py.test tests
```

Or you can install `tox` to run the full test suite.


## Releasing

Pandoc is required for transforming the markdown README to the proper format to
render correctly on pypi.

For Debian-like systems:

```
apt install pandoc
```

Or on OSX:

```sh
brew install pandoc
```

To release a new version:

```sh
bumpversion $$VERSION_PART_TO_BUMP$$
git push && git push --tags
make release
```


### How to bumpversion

The version format for this repo is `{major}.{minor}.{patch}` for stable, and
`{major}.{minor}.{patch}-{stage}.{devnum}` for unstable (`stage` can be alpha or beta).

To issue the next version in line, use bumpversion and specify which part to bump,
like `bumpversion minor` or `bumpversion devnum`.

If you are in a beta version, `bumpversion stage` will switch to a stable.

To issue an unstable version when the current version is stable, specify the
new version explicitly, like `bumpversion --new-version 4.0.0-alpha.1 devnum`
