import rlp

from eth_tester.utils.address import (
    generate_contract_address,
)
from eth_tester.utils.encoding import (
    int_to_32byte_big_endian,
)


def pad32(value):
    return value.rjust(32, b'\x00')


def serialize_block(block, full_transaction, is_pending):
    if full_transaction:
        transaction_serializer = serialize_transaction
    else:
        transaction_serializer = serialize_transaction_hash

    transactions = [
        transaction_serializer(block, transaction, index, is_pending)
        for index, transaction
        in enumerate(block.transactions)
    ]

    if block.uncles:
        raise NotImplementedError("Uncle serialization has not been implemented")

    return {
        "number": block.header.block_number,
        "hash": block.header.hash,
        "parent_hash": block.header.parent_hash,
        "nonce": block.header.nonce,
        "sha3_uncles": block.header.uncles_hash,
        "logs_bloom": block.header.bloom,
        "transactions_root": block.header.transaction_root,
        "receipts_root": block.header.receipt_root,
        "state_root": block.header.state_root,
        "miner": block.header.coinbase,
        "difficulty": block.header.difficulty,
        "total_difficulty": block.header.difficulty,  # TODO: actual total difficulty
        "size": len(rlp.encode(block)),
        "extra_data": pad32(block.header.extra_data),
        "gas_limit": block.header.gas_limit,
        "gas_used": block.header.gas_used,
        "timestamp": block.header.timestamp,
        "transactions": transactions,
        "uncles": [uncle.hash for uncle in block.uncles],
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
        "gas": transaction.gas,
        "gas_price": transaction.gas_price,
        "data": transaction.data,
        "v": transaction.v,
        "r": transaction.r,
        "s": transaction.s,
    }


def serialize_transaction_receipt(
    block,
    receipts,
    transaction,
    transaction_index,
    is_pending
):
    receipt = receipts[transaction_index]

    if transaction.to == b'':
        contract_addr = generate_contract_address(
            transaction.sender,
            transaction.nonce,
        )
    else:
        contract_addr = None

    if transaction_index == 0:
        origin_gas = 0
    else:
        origin_gas = receipts[transaction_index - 1].gas_used

    return {
        "transaction_hash": transaction.hash,
        "transaction_index": None if is_pending else transaction_index,
        "block_number": None if is_pending else block.number,
        "block_hash": None if is_pending else block.hash,
        "cumulative_gas_used": receipt.gas_used,
        "gas_used": receipt.gas_used - origin_gas,
        "contract_address": contract_addr,
        "logs": [
            serialize_log(block, transaction, transaction_index, log, log_index, is_pending)
            for log_index, log in enumerate(receipt.logs)
        ],
        'state_root': receipt.state_root,
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
