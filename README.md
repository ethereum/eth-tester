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
>>> txn_hash = t.send_transaction({TODO})
TODO
>>> t.get_transaction_by_hash(txn_hash)
TODO
>>> t.get_transaction_receipt(txn_hash)
TODO
```


# Documentation

## Input and output data formats

TODO


## `eth_tester.EthereumTester`

### API

### Configuration

* `configure()`

### Mining

* `mine_blocks(num_blocks=1, coinbase=None)`

### Accounts

* `get_accounts(TODO)`
* `get_balance(TODO)`
* `get_nonce(TODO)`

### Blocks, Transactions, and Receipts

* `get_transaction_by_hash(TODO)`
* `get_block_by_number(TODO)`
* `get_block_by_hash(TODO)`
* `get_transaction_receipt(TODO)`
* `mine_blocks(TODO)`

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
