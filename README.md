# Ethereum Tester

[![Join the chat at https://gitter.im/pipermerriam/ethereum-tester](https://badges.gitter.im/pipermerriam/ethereum-tester.svg)](https://gitter.im/pipermerriam/ethereum-tester?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![Build Status](https://travis-ci.org/pipermerriam/ethereum-tester.png)](https://travis-ci.org/pipermerriam/ethereum-tester)


Tools for testing ethereum based applications.


## Installation

```sh
pip install ethereum-tester
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


## `eth_tester.EthereumTester`

### API

### Instantiation

* `EthereumTester(backend=None, validator=None, normalizer=None, auto_mine_transactions=True, fork_blocks=None)`

The `EthereumTester` object is the sole API entrypoint.  Instantiation of this
object accepts the following parameters.

- `backend`: The chain backend being used.  See the [chain backends](#chain-backends)
- `validator`: The validator to used.  See the [validators](#validators)
- `normalizer`: The normalizer to used.  See the [normalizers](#normalizers)
- `auto_mine_transactions`: If *truthy* transactions will be automatically mined at the time they are submitted.
- `fork_blocks`: configures which block numbers the various network hard fork rules will be activated.  See [fork-rules](#fork-rules)


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

* `EthereumTester.set_fork_block(fork_name, fork_block)`

Sets the fork rules for the fork denoted by `fork_name` to activate at `fork_block`.

* `EthereumTester.get_fork_block(fork_name)`

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
* `EthereumTester.time_travel(timestamp)`

The `timestamp` must be an integer, strictly greater than the current timestamp
of the latest block.  

> Note: Time traveling will result in a new block being mined.


### Mining

Manually mining blocks can be done with the following API.  The `coinbase`
parameter of these methods **must** be a hexidecimal encoded address.

<a id="api-mine_blocks"></a>
* `EthereumTester.mine_blocks(num_blocks=1, coinbase=None)`

Mines `num_blocks` new blocks, returning an iterable of the newly mined block hashes.


<a id="api-mine_block"></a>
* `EthereumTester.mine_block(coinbase=None)`

Mines a single new block, returning the mined block's hash.


### Accounts

The following API can be used to interact with account data.  The `account`
parameter in these methods **must** be a hexidecimal encode address.

<a id="api-get_accounts"></a>
* `get_accounts()`

Returns an iterable of the accounts that the tester knows about.


<a id="api-get_balance"></a>
* `get_balance(account)`

Returns the balance, in wei, for the provided account.

```python
>>> t.get_balance('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1')
1000004999999999999999999
```


<a id="api-get_nonce"></a>
* `get_nonce(account)`

Returns the nonce for the provided account.

```python
>>> t.get_nonce('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1')
1
```

<a id="api-get_code"></a>
* `get_code(account)`

Returns the code for the given account.

```python
>>> t.get_code('0x82A978B3f5962A5b0957d9ee9eEf472EE55B42F1')
"0x"
```


### Blocks, Transactions, and Receipts

<a id="api-get_transaction_by_hash"></a>
* `get_transaction_by_hash(TODO)`

<a id="api-get_block_by_numbera>
* `get_block_by_number(TODO)`

<a id="api-get_block_by_hash"></a>
* `get_block_by_hash(TODO)`

<a id="api-get_transaction_receipt"></a>
* `get_transaction_receipt(TODO)`

### Logs and Filters

* `create_block_filter(TODO)`
* `create_pending_transaction_filter(TODO)`
* `create_log_filter(TODO)`
* `delete_filter(TODO)`
* `get_only_filter_changes(TODO)`
* `get_all_filter_logs(TODO)`


### Configuration

TODO:

* auto-mine-transactions
* auto-mining-interval (TODO)
* fork blocks (homestead, dao, anti-dos, state-clearing)


### Snapshots and Resetting

TODO


### Errors and Exceptions

TODO


## Backends

### PyEthereum 1.6.x

TODO

### PyEthereum 2.0.x (under development)

TODO

### PyEVM (experimental)

TODO

### Implementing Alternative Backends

TODO
