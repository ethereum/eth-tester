import rlp


def serialize_block(block):
    return {
        "number": block.header.block_number,
        "hash": block.header.hash,
        "parent_hash": block.header.parent_hash,
        "nonce": block.header.nonce,
        "sha3_uncles": block.header.uncles_hash,
        "logs_bloom": block.header.bloom,
        "transactions_root": block.header.transaction_root,
        "state_root": block.header.state_root,
        "miner": block.header.coinbase,
        "difficulty": block.header.difficulty,
        "total_difficulty": block.header.difficulty,  # TODO
        "size": len(rlp.encode(block)),
        "extra_data": block.header.extra_data,
        "gas_limit": block.header.gas_limit,
        "gas_used": block.header.gas_used,
        "timestamp": block.header.timestamp,
        "transactions": [],  # TODO
        "uncles": [],  # TODO
    }
