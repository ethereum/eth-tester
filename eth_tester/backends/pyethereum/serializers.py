from __future__ import unicode_literals

import rlp

from eth_utils import (
    is_bytes,
    is_text,
)

from eth_tester.utils.encoding import (
    zpad,
    zpad32,
    int_to_32byte_big_endian,
)

from eth_tester.backends.pyethereum.utils import (
    is_pyethereum21_available,
)


def serialize_transaction_receipt(block,
                                  transaction,
                                  transaction_receipt,
                                  transaction_index,
                                  is_pending):
    if hasattr(block, 'transaction_list'):
        origin_gas = block.transaction_list[0].startgas
    elif hasattr(block, 'transactions'):
        origin_gas = block.transactions[0].startgas
    else:
        raise Exception('Invariant: failed to match pyethereum16 or pyethereum21 API')

    if transaction.creates is not None:
        contract_addr = transaction.creates
    elif transaction.to == b'\x00' * 20:
        from ethereum.utils import mk_contract_address
        # pyethereum21 doesn't correctly detect this as a create address.
        contract_addr = mk_contract_address(transaction.sender, transaction.nonce)
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


def encode_if_not_bytes(value):
    if is_bytes(value):
        return value
    elif is_text(value):
        return value.encode()
    else:
        raise TypeError("Expected string type: Got {0}".format(type(value)))


def serialize_block(evm, block, transaction_serialize_fn, is_pending):
    transactions = [
        transaction_serialize_fn(block, transaction, transaction_index, is_pending)
        for transaction_index, transaction
        in enumerate(
            block.transactions if is_pyethereum21_available() else block.transaction_list
        )
    ]

    # NOTE: Hack to compute total difficulty for pyethereum 2.0
    #       As far as I could tell, this didn't really do anything in 1.6
    if hasattr(block, 'chain_difficulty'):
        total_difficulty = block.chain_difficulty()
    elif hasattr(evm, 'chain') and hasattr(evm.chain, 'get_score'):
        total_difficulty = evm.chain.get_score(block)
    else:
        raise Exception('Invariant: failed to match pyethereum16 or pyethereum21 API')

    return {
        "number": block.number,
        "hash": block.hash,
        "parent_hash": block.prevhash,
        "nonce": zpad(encode_if_not_bytes(block.nonce), 8),
        "sha3_uncles": block.uncles_hash,
        "logs_bloom": block.bloom,
        "transactions_root": block.tx_list_root,
        "receipts_root": block.receipts_root,
        "state_root": block.state_root,
        "miner": block.coinbase if is_bytes(block.coinbase) else block.coinbase.encode(),
        "difficulty": block.difficulty,
        "total_difficulty": total_difficulty,
        "size": len(rlp.encode(block)),
        "extra_data": zpad32(encode_if_not_bytes(block.extra_data)),
        "gas_limit": block.gas_limit,
        "gas_used": block.gas_used,
        "timestamp": block.timestamp,
        "transactions": transactions,
        "uncles": block.uncles,
    }
