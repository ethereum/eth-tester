import rlp


def serialize_transaction_receipt(block, transaction, transaction_index):
    transaction_receipt = block.get_receipt(transaction_index)
    origin_gas = block.transaction_list[0].startgas

    if transaction.creates is not None:
        contract_addr = transaction.creates
    else:
        contract_addr = None

    return {
        "transaction_hash": transaction.hash,
        "transaction_index": transaction_index,
        "block_number": block.number,
        "block_hash": block.hash,
        "cumulative_gas_used": origin_gas - transaction.startgas + transaction_receipt.gas_used,
        "gas_used": transaction_receipt.gas_used,
        "contract_address": contract_addr,
        "logs": [
            serialize_log(block, transaction, transaction_index, log, log_index)
            for log_index, log in enumerate(transaction_receipt.logs)
        ],
    }


def serialize_transaction_hash(block, transaction, transaction_index):
    return transaction.hash


def serialize_transaction(block, transaction, transaction_index):
    return {
        "hash": transaction.hash,
        "nonce": transaction.nonce,
        "block_hash": block.hash,
        "block_number": block.number,
        "transaction_index": transaction_index,
        "from": transaction.sender,
        "to": transaction.to,
        "value": transaction.value,
        "gas": transaction.startgas,
        "gas_price": transaction.gasprice,
        "data": transaction.data,
    }


def serialize_log(block, transaction, transaction_index, log, log_index):
    return {
        "type": "mined",
        "log_index": log_index,
        "transaction_index": transaction_index,
        "transaction_hash": transaction.hash,
        "block_hash": block.hash,
        "block_number": block.number,
        "address": log.address,
        "data": log.data,
        "topics": log.topics,
    }


def serialize_block(block, transaction_serialize_fn=serialize_transaction_hash):
    transactions = [
        transaction_serialize_fn(block, transaction, transaction_index)
        for transaction_index, transaction
        in enumerate(block.transaction_list)
    ]

    return {
        "number": block.number,
        "hash": block.hash,
        "parent_hash": block.prevhash,
        "nonce": block.nonce,
        "sha3Uncles": block.uncles_hash,
        "logs_bloom": block.bloom,
        "transactionsRoot": block.tx_list_root,
        "stateRoot": block.state_root,
        "miner": block.coinbase,
        "difficulty": block.difficulty,
        "totalDifficulty": block.chain_difficulty(),
        "size": len(rlp.encode(block)),
        "extraData": block.extra_data,
        "gasLimit": block.gas_limit,
        "gasUsed": block.gas_used,
        "timestamp": block.timestamp,
        "transactions": transactions,
        "uncles": block.uncles
    }
