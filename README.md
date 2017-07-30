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
TODO
>>> t.get_balance(TODO)
TODO
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
