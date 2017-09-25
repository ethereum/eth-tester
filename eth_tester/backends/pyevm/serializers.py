import rlp

from cytoolz import (
    partial,
)

from eth_utils import (
    pad_left,
)


pad32 = partial(pad_left, to_size=32, pad_with=b'\x00')


def serialize_block(block, full_transaction=False):
    if full_transaction:
        raise NotImplementedError("Not yet implemented")
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
        "extra_data": pad32(block.header.extra_data),
        "gas_limit": block.header.gas_limit,
        "gas_used": block.header.gas_used,
        "timestamp": block.header.timestamp,
        "transactions": [],  # TODO
        "uncles": [],  # TODO
    }


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
