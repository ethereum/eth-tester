import rlp


def serialize_txn_receipt(block, txn, txn_index):
    txn_receipt = block.get_receipt(txn_index)
    origin_gas = block.transaction_list[0].startgas

    if txn.creates is not None:
        contract_addr = txn.creates
    else:
        contract_addr = None

    return {
        "transaction_hash": txn.hash,
        "transaction_index": txn_index,
        "block_number": block.number,
        "block_hash": block.hash,
        "cumulative_gas_used": origin_gas - txn.startgas + txn_receipt.gas_used,
        "gas_used": txn_receipt.gas_used,
        "contract_address": contract_addr,
        "logs": [
            serialize_log(block, txn, txn_index, log, log_index)
            for log_index, log in enumerate(txn_receipt.logs)
        ],
    }


def serialize_txn_hash(block, txn, txn_index):
    return txn.hash


def serialize_txn(block, txn, txn_index):
    return {
        "hash": txn.hash,
        "nonce": txn.nonce,
        "block_hash": block.hash,
        "block_number": block.number,
        "transaction_index": txn_index,
        "from": txn.sender,
        "to": txn.to,
        "value": txn.value,
        "gas": txn.startgas,
        "gas_price": txn.gasprice,
        "data": txn.data,
    }


def serialize_log(block, txn, txn_index, log, log_index):
    return {
        "type": "mined",
        "log_index": log_index,
        "transaction_index": txn_index,
        "transaction_hash": txn.hash,
        "block_hash": block.hash,
        "block_number": block.number,
        "address": log.address,
        "data": log.data,
        "topics": log.topics,
    }


def serialize_block(block, txn_serialize_fn=_txn_hash_serializer):
    transactions = [
        txn_serialize_fn(block, txn, txn_index)
        for txn_index, txn
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
