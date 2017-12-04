from __future__ import unicode_literals

import rlp

from eth_tester.utils.encoding import (
    zpad,
    zpad32,
    int_to_32byte_big_endian,
)


def serialize_transaction_receipt(block, transaction, transaction_index, is_pending):
    transaction_receipt = block.get_receipt(transaction_index)
    origin_gas = block.transaction_list[0].startgas

    if transaction.creates is not None:
        contract_addr = transaction.creates
    else:
        contract_addr = None

    return {
        "transaction_hash": transaction.hash,
        "transaction_index": None if is_pending else transaction_index,
        "block_number": None if is_pending else block.number,
        "block_hash": None if is_pending else block.hash,
        "cumulative_gas_used": origin_gas - transaction.startgas + transaction_receipt.gas_used,
        "gas_used": transaction_receipt.gas_used,
        "contract_address": contract_addr,
        "logs": [
            serialize_log(block, transaction, transaction_index, log, log_index, is_pending)
            for log_index, log in enumerate(transaction_receipt.logs)
        ],
    }


def serialize_transaction_hash(block, transaction, transaction_index, is_pending):
    return transaction.hash


def serialize_transaction(block, transaction, transaction_index, is_pending):
    return {
        "hash": transaction.hash,
        "nonce": transaction.nonce,
        "block_hash": None if is_pending else block.hash,
        "block_number": None if is_pending else block.number,
        "transaction_index": None if is_pending else transaction_index,
        "from": transaction.sender,
        "to": transaction.to,
        "value": transaction.value,
        "gas": transaction.startgas,
        "gas_price": transaction.gasprice,
        "data": transaction.data,
        "v": transaction.v,
        "r": transaction.r,
        "s": transaction.s,
    }


def serialize_log(block, transaction, transaction_index, log, log_index, is_pending):
    return {
        "type": "pending" if is_pending else "mined",
        "log_index": log_index,
        "transaction_index": None if is_pending else transaction_index,
        "transaction_hash": transaction.hash,
        "block_hash": None if is_pending else block.hash,
        "block_number": None if is_pending else block.number,
        "address": log.address,
        "data": log.data,
        "topics": [int_to_32byte_big_endian(topic) for topic in log.topics],
    }


def serialize_block(block, transaction_serialize_fn, is_pending):
    transactions = [
        transaction_serialize_fn(block, transaction, transaction_index, is_pending)
        for transaction_index, transaction
        in enumerate(block.transaction_list)
    ]

    return {
        "number": block.number,
        "hash": block.hash,
        "parent_hash": block.prevhash,
        "nonce": zpad(block.nonce, 8),
        "sha3_uncles": block.uncles_hash,
        "logs_bloom": block.bloom,
        "transactions_root": block.tx_list_root,
        "receipts_root": block.receipts_root,
        "state_root": block.state_root,
        "miner": block.coinbase,
        "difficulty": block.difficulty,
        "total_difficulty": block.chain_difficulty(),
        "size": len(rlp.encode(block)),
        "extra_data": zpad32(block.extra_data),
        "gas_limit": block.gas_limit,
        "gas_used": block.gas_used,
        "timestamp": block.timestamp,
        "transactions": transactions,
        "uncles": block.uncles,
    }
