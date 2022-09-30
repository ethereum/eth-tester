# Ethereum Tester

[![Join the chat at https://gitter.im/ethereum/eth-tester](https://badges.gitter.im/ethereum/eth-tester.svg)](https://gitter.im/ethereum/eth-tester)
[![Build Status](https://circleci.com/gh/ethereum/eth-tester.svg?style=shield)](https://app.circleci.com/pipelines/github/ethereum/eth-tester)


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
('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
 '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF',
 '0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69',
 '0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718',
 '0xe1AB8145F7E55DC933d51a18c793F901A3A0b276',
 '0xE57bFE9F44b819898F47BF37E5AF72a0783e1141',
 '0xd41c057fd1c78805AAC12B0A94a405c0461A6FBb',
 '0xF1F6619B38A98d6De0800F1DefC0a6399eB6d30C',
 '0xF7Edc8FA1eCc32967F827C9043FcAe6ba73afA5c',
 '0x4CCeBa2d7D2B4fdcE4304d3e09a1fea9fbEb1528')

>>> t.get_balance('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')
1000000000000000000000000

>>> t.send_transaction({
...     'from': '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
...     'to': '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF',
...     'gas': 30000,
...     'value': 1,
...     'max_fee_per_gas': 1000000000,
...     'max_priority_fee_per_gas': 1000000000,
...     'chain_id': 131277322940537,
...     'access_list': (
...         {
...             'address': '0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae',
...             'storage_keys': (
...                 '0x0000000000000000000000000000000000000000000000000000000000000003',
...                 '0x0000000000000000000000000000000000000000000000000000000000000007',
...             )
...         },
...         {
...             'address': '0xbb9bc244d798123fde783fcc1c72d3bb8c189413',
...             'storage_keys': ()
...         },
...     )
... })
'0xc20b90af87bc65c3d748cf0a1fa54f3a86ffc94348e0fd91a70f1c5ba6ef4109'

>>> t.get_transaction_by_hash('0xc20b90af87bc65c3d748cf0a1fa54f3a86ffc94348e0fd91a70f1c5ba6ef4109')
{'type': '0x2',
 'hash': '0xc20b90af87bc65c3d748cf0a1fa54f3a86ffc94348e0fd91a70f1c5ba6ef4109',
 'nonce': 0,
 'block_hash': '0x28b95514984b0abbd91d88f1a542eaeeb810c24e0234e09891b7d6b3f94f47ed',
 'block_number': 1,
 'transaction_index': 0,
 'from': '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
 'to': '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF',
 'value': 1,
 'gas': 30000,
 'data': '0x',
 'r': 60071646517429056848243893841817235885102606421189844318110381014348740252962,
 's': 55731679314783756278323646144996847004593793888590884914350251538533006990589,
 'v': 0,
 'chain_id': 131277322940537,
 'max_fee_per_gas': 1000000000,
 'max_priority_fee_per_gas': 1000000000,
 'access_list': ({'address': '0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe',
   'storage_keys': ('0x0000000000000000000000000000000000000000000000000000000000000003',
    '0x0000000000000000000000000000000000000000000000000000000000000007')},
  {'address': '0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413',
   'storage_keys': ()}),
 'gas_price': 1000000000}


>>> t.get_transaction_receipt('0xc20b90af87bc65c3d748cf0a1fa54f3a86ffc94348e0fd91a70f1c5ba6ef4109')
{'transaction_hash': '0xc20b90af87bc65c3d748cf0a1fa54f3a86ffc94348e0fd91a70f1c5ba6ef4109',
 'transaction_index': 0,
 'block_number': 1,
 'block_hash': '0x28b95514984b0abbd91d88f1a542eaeeb810c24e0234e09891b7d6b3f94f47ed',
 'cumulative_gas_used': 29600,
 'gas_used': 29600,
 'effective_gas_price': 1000000000,
 'contract_address': None,
 'logs': (),
 'type': '0x2',
 'status': 1}
```


## Development

```sh
pip install -e ".[dev]"
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

First, compile and commit the release notes:
```sh
make notes bump={one of: major, minor, patch, devnum}
```

Then, do the actual release:

```sh
make release bump={one of: major, minor, patch, devnum}
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
* 32-byte hashes **must** be hexadecimal encoded.
* Numeric values **must** be in their integer representation.

Similarly, ethereum tester ensures that return values conform to similar rules.

* 32-byte hashes will be returned in their hexadecimal encoded representation.
* Addresses will be returned in their hexadecimal representation and EIP55 checksummed.
* Numeric values will be returned as integers.


## Block Numbers
<a id="block-numbers"></a>

Any `block_number` parameter will accept the following string values.

* `'latest'`: for the latest mined block.
* `'pending'`: for the current un-mined block.
* `'earliest'`: for the genesis block.
* `'safe'`: for the last block that has passed 2/3 of attestations post-merge.
* `'finalized'`: for the last finalized block post-merge.

> Note: These **must** be text strings (not byte stringS)


## `eth_tester.EthereumTester`

### API

### Instantiation

* `eth_tester.EthereumTester(backend=None, validator=None, normalizer=None, auto_mine_transactions=True, fork_blocks=None)`

The `EthereumTester` object is the sole API entrypoint.  Instantiation of this
object accepts the following parameters.

- `backend`: The chain backend being used.  See the [chain backends](#backends)
- `validator`: The validator being used.  See the [validators](#validation)
- `normalizer`: The normalizer being used.  See the [normalizers](#normalization)
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

Ethereum tester uses the Paris (PoS) fork rules, starting at block 0.

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
parameter of these methods **must** be a hexadecimal encoded address.

<a id="api-mine_blocks"></a>

#### `EthereumTester.mine_blocks(num_blocks=1, coinbase=ZERO_ADDRESS)`

Mines `num_blocks` new blocks, returning an iterable of the newly mined block hashes.


<a id="api-mine_block"></a>

#### `EthereumTester.mine_block(coinbase=ZERO_ADDRESS)`

Mines a single new block, returning the mined block's hash.


<a id="api-auto_mine_transactions"></a>

#### Auto-mining transactions

By default, all transactions are mined immediately.  This means that each transaction you send will result in a new block being mined, and that all blocks will only ever have at most a single transaction.  This behavior can be controlled with the following methods.

<a id="api-enable_auto_mine_transactions"></a>

#### `EthereumTester.enable_auto_mine_transactions()`

Turns on auto-mining of transactions.

<a id="api-disable_auto_mine_transactions"></a>

#### `EthereumTester.disable_auto_mine_transactions()`

Turns **off** auto-mining of transactions.


### Accounts

The following API can be used to interact with account data.  The `account`
parameter in these methods **must** be a hexadecimal encode address.

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


<a id="api-lock_account"></a>

#### `EthereumTester.lock_account(account)`

Locks the provided account.

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
>>> t.get_transaction_by_hash('0x21ae665f707e12a5f1bb13ef8c706b65cc5accfd03e7067ce683d831f51122e6')
{'type': '0x2',
 'hash': '0x21ae665f707e12a5f1bb13ef8c706b65cc5accfd03e7067ce683d831f51122e6',
 'nonce': 0,
 'block_hash': '0x810731efeb7498fc0ac3bc7c72a71571b672c9fdbfbfd8b435f483e368e8ef7e',
 'block_number': 1,
 'transaction_index': 0,
 'from': '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF',
 'to': '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
 'value': 1337,
 'gas': 21000,
 'data': '0x',
 'r': 1713666669454033023988006960017431058214051587080823768269189498559514600280,
 's': 32003859822305799628524852194521134173285969678963273753063458725692016415033,
 'v': 0,
 'chain_id': 131277322940537,
 'max_fee_per_gas': 2000000000,
 'max_priority_fee_per_gas': 500000000,
 'access_list': (),
 'gas_price': 1375000000}
```

> Note: For unmined transaction, `transaction_index`, `block_number` and `block_hash` will all be `None`.


<a id="api-get_block_by_number"></a>

#### `EthereumTester.get_block_by_number(block_number, full_transactions=False) -> block-object`

Returns the block for the given `block_number`.  See [block
numbers](#block-numbers) for named block numbers you can use.  If
`full_transactions` is truthy, then the transactions array will be populated
with full transaction objects as opposed to their hashes.

Raises [`BlockNotFound`](#errors-BlockNotFound) if a block for the given number
cannot be found.

```python
>>> t.get_block_by_number(1)
{'number': 1,
 'hash': '0xd481955268d1f3db58ee61685a899a35e33e8fd35b9cc0812f85b9f06757140e',
 'parent_hash': '0x5be984ab842071903ee443a5dee92603bef42de35b4e10928e753f7e88a7163a',
 'nonce': '0x0000000000000000',
 'sha3_uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',
 'logs_bloom': 0,
 'transactions_root': '0xef1e11d99f7db22fd93c6a10d44753d4a93e9f6ecb2f1e5030a0a91f1d3b07ac',
 'receipts_root': '0x611e48488cf80b4c31f01ad45b6ebea533a68255a6d0240d434d9366a3582010',
 'state_root': '0x9ce568dcaa6f130d733b333304f2c26a19334ed328a7eb9bb31707306381ba65',
 'coinbase': '0x0000000000000000000000000000000000000000',
 'difficulty': 0,
 'total_difficulty': 0,
 'mix_hash': '0x0000000000000000000000000000000000000000000000000000000000000000',
 'size': 751,
 'extra_data': '0x0000000000000000000000000000000000000000000000000000000000000000',
 'gas_limit': 3141592,
 'gas_used': 29600,
 'timestamp': 1633669276,
 'transactions': ('0xc20b90af87bc65c3d748cf0a1fa54f3a86ffc94348e0fd91a70f1c5ba6ef4109',),
 'uncles': (),
 'base_fee_per_gas': 875000000}
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
{'number': 1,
 'hash': '0xd481955268d1f3db58ee61685a899a35e33e8fd35b9cc0812f85b9f06757140e',
 'parent_hash': '0x5be984ab842071903ee443a5dee92603bef42de35b4e10928e753f7e88a7163a',
 'nonce': '0x0000000000000000',
 'sha3_uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',
 'logs_bloom': 0,
 'transactions_root': '0xef1e11d99f7db22fd93c6a10d44753d4a93e9f6ecb2f1e5030a0a91f1d3b07ac',
 'receipts_root': '0x611e48488cf80b4c31f01ad45b6ebea533a68255a6d0240d434d9366a3582010',
 'state_root': '0x9ce568dcaa6f130d733b333304f2c26a19334ed328a7eb9bb31707306381ba65',
 'coinbase': '0x0000000000000000000000000000000000000000',
 'difficulty': 0,
 'total_difficulty': 0,
 'mix_hash': '0x0000000000000000000000000000000000000000000000000000000000000000',
 'size': 751,
 'extra_data': '0x0000000000000000000000000000000000000000000000000000000000000000',
 'gas_limit': 3141592,
 'gas_used': 29600,
 'timestamp': 1633669276,
 'transactions': ('0xc20b90af87bc65c3d748cf0a1fa54f3a86ffc94348e0fd91a70f1c5ba6ef4109',),
 'uncles': (),
 'base_fee_per_gas': 875000000}
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

* `from`: The address of the account sending the transaction (hexadecimal string).
* `to`: The address of the account the transaction is being sent to.  Empty string should be used to trigger contract creation (hexadecimal string).
* `gas`: Sets the gas limit for transaction execution (integer).
* `value`: The amount of ether in wei that should be sent with the transaction (integer).
* `data`: The data for the transaction (hexadecimal string).
* `chain_id`: The integer id for the chain the transaction is meant to interact with.


In addition to the above, the following parameters are added based on the type of transaction being sent:

#### Legacy transactions
* `gas_price`: Sets the price per unit of gas in wei that will be paid for transaction execution (integer).

#### Access list transactions (EIP-2930)
* `gas_price`: Sets the price per unit of gas in wei that will be paid for transaction execution (integer).
* `access_list` (optional): Specifies accounts and storage slots expected to be accessed, based on the transaction, in order to
gain a discount on the gas for those executions (see quickstart example for usage).

#### Dynamic fee transactions (EIP-1559)
* `max_fee_per_gas`: Sets the maximum fee per unit of gas in wei that will be paid for transaction execution (integer).
* `max_priority_fee_per_gas`: Sets the fee per unit of gas in wei that is sent to the coinbase address as an incentive for including the transaction (integer).
* `access_list` (optional): Specifies accounts and storage slots expected to be accessed, based on the transaction, in order to
gain a discount on the gas for those executions (see quickstart example for usage).



### Methods

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

* `py-evm`: [PyEVM (alpha)](https://pypi.python.org/pypi/py-evm) **(experimental)**

### Selecting a Backend

You can select which backend in a few different ways.

The most direct way is to manually pass in the backend instance you wish to
use.

```python
>>> from eth_tester import EthereumTester, MockBackend
>>> t = EthereumTester(backend=MockBackend())
```

Ethereum tester also supports configuration using the environment variable
`ETHEREUM_TESTER_CHAIN_BACKEND`.  This should be set to the import path for the
backend class you wish to use.

### Available Backends

Ethereum tester can be used with the following backends.

* PyEVM (experimental)
* MockBackend

#### MockBackend

This backend has limited functionality.  It cannot perform any VM computations.
It mocks out all of the objects and interactions.

```python
>>> from eth_tester import EthereumTester, MockBackend
>>> t = EthereumTester(MockBackend())
```

#### PyEVM (experimental)

> **WARNING** Py-EVM is experimental and should not be relied on for mission critical testing at this stage.

Uses the experimental Py-EVM library.

```python
>>> from eth_tester import EthereumTester, PyEVMBackend
>>> t = EthereumTester(PyEVMBackend())
```


#### PyEVM Genesis Parameters and State

If you need to specify custom genesis parameters and state, you can build your own parameters `dict` to use instead of the default
when initializing a backend.  Only default values can be overridden or a `ValueError` will be raised.

```
# Default Genesis Parameters

default_genesis_params = {
    "coinbase": GENESIS_COINBASE,
    "difficulty": GENESIS_DIFFICULTY,
    "extra_data": GENESIS_EXTRA_DATA,
    "gas_limit": GENESIS_GAS_LIMIT,
    "mix_hash": GENESIS_MIX_HASH,
    "nonce": GENESIS_NONCE,
    "receipt_root": BLANK_ROOT_HASH,
    "timestamp": int(time.time()),
    "transaction_root": BLANK_ROOT_HASH,
}
```

To generate a genesis parameters `dict` with an overridden parameters, pass a `genesis_overrides` `dict` \
to `PyEVM.generate_genesis_params`.

```python
>>> from eth_tester import PyEVMBackend, EthereumTester

>>> genesis_overrides = {'gas_limit': 4500000}
>>> custom_genesis_params = PyEVMBackend.generate_genesis_params(overrides=genesis_overrides)

# Generates the following `dict`:

# custom_genesis_params = {
#     "coinbase": GENESIS_COINBASE,
#     "difficulty": GENESIS_DIFFICULTY,
#     "extra_data": GENESIS_EXTRA_DATA,
#     "gas_limit": 4500000    # <<< Overidden Value <<<
#     "mix_hash": GENESIS_MIX_HASH,
#     "nonce": GENESIS_NONCE,
#     "receipt_root": BLANK_ROOT_HASH,
#     "timestamp": int(time.time()),
#     "transaction_root": BLANK_ROOT_HASH,
# }
```

Then pass the generated `custom_genesis_params` `dict` to the backend's `__init__`
```python
>>> from eth_tester import PyEVMBackend, EthereumTester
>>> pyevm_backend = PyEVMBackend(genesis_parameters=custom_genesis_params)
>>> t = EthereumTester(backend=pyevm_backend)
```

Similarly to `genesis_parameters`, override the genesis state by passing in an `overrides` `dict`
to `PyEVMBackend.generate_genesis_state`. Optionally, provide `num_accounts` to set the number of accounts.

For more control on which accounts the backend generates, use the `from_mnemonic()` classmethod. Give it
a `mnemonic` (and optionally the number of accounts) and it will use that information to generate the accounts.
Optionally, provide a `genesis_state_overrides` `dict` to adjust the `genesis_state`.
```python
>>> from eth_tester import PyEVMBackend, EthereumTester
>>> from eth_utils import to_wei
>>> from hexbytes import HexBytes
>>>
>>> pyevm_backend = PyEVMBackend.from_mnemonic(
>>>    'test test test test test test test test test test test junk',
>>>    genesis_state_overrides={'balance': to_wei(1000000, 'ether')}
>>> )
>>> t = EthereumTester(backend=pyevm_backend)
>>> print(t.get_accounts()[0])  # Outputs 0x1e59ce931B4CFea3fe4B875411e280e173cB7A9C
>>> print(t.get_balance('0x1e59ce931B4CFea3fe4B875411e280e173cB7A9C'))  # Outputs 1000000000000000000000000
```

*NOTE: The same state is applied to all generated test accounts.*

```
# Default Account Genesis State

default_account_state = {
    'balance': to_wei(1000000, 'ether'),
    'storage': {},
    'code': b'',
    'nonce': 0,
}
```

For Example, to create 3 test accounts, each with a balance of 100 ETH each:

```python
>>> from eth_tester import EthereumTester, PyEVMBackend
>>>  from eth_utils import to_wei

>>> state_overrides = {'balance': to_wei(100, 'ether')}
>>> custom_genesis_state = PyEVMBackend.generate_genesis_state(overrides=state_overrides, num_accounts=3)

# Then pass the generated `custom_genesis_state` `dict` to the backend's `__init__`

>>> pyevm_backend = PyEVMBackend(genesis_state=custom_genesis_state)
>>> t = EthereumTester(backend=pyevm_backend)
```


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

* 32 byte hashes: `0x` prefixed hexadecimal encoded text strings (not byte strings)
* Arbitrary length strings: `0x` prefixed hexadecimal encoded text strings (not byte strings)
* Addresses: `0x` prefixed and EIP55 checksummed hexadecimal encoded text strings (not byte strings)
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

The specifics of this object are beyond the scope of this document.

<a id="validation"></a>
### Validation

The `EthereumTester` delegates validation to whatever `validator` was
passed in during instantiation.  If no value was provided, the default
validator will be used from
`eth_tester.validation.default.DefaultValidator`.

The specifics of this object are beyond the scope of this document.


# Use with Web3.py

See the [web3.py documentation](http://web3py.readthedocs.io/en/latest/) for
information on the `EthereumTester` provider which integrates with this
library.
