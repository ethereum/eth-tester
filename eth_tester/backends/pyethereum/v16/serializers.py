import rlp

from eth_utils import (
    encode_hex,
)


#def serialize_txn_receipt(block, txn, txn_index):
#    txn_receipt = block.get_receipt(txn_index)
#    origin_gas = block.transaction_list[0].startgas
#
#    if txn.creates is not None:
#        contract_addr = encode_address(txn.creates)
#    else:
#        contract_addr = None
#
#    return {
#        "transactionHash": encode_32bytes(txn.hash),
#        "transactionIndex": encode_number(txn_index),
#        "blockNumber": encode_number(block.number),
#        "blockHash": encode_32bytes(block.hash),
#        "cumulativeGasUsed": encode_number(origin_gas - txn.startgas + txn_receipt.gas_used),
#        "gasUsed": encode_number(txn_receipt.gas_used),
#        "contractAddress": contract_addr,
#        "logs": [
#            serialize_log(block, txn, txn_index, log, log_index)
#            for log_index, log in enumerate(txn_receipt.logs)
#        ],
#    }


def serialize_txn(block, txn, txn_index):
    return {
        "hash": encode_32bytes(txn.hash),
        "nonce": encode_number(txn.nonce),
        "blockHash": encode_32bytes(block.hash),
        "blockNumber": encode_number(block.number),
        "transactionIndex": encode_number(txn_index),
        "from": encode_address(txn.sender),
        "to": encode_address(txn.to),
        "value": encode_number(txn.value),
        "gas": encode_number(txn.startgas),
        "gasPrice": encode_number(txn.gasprice),
        "input": encode_data(txn.data)
    }


def serialize_log(block, txn, txn_index, log, log_index):
    return {
        "type": "mined",
        "logIndex": encode_number(log_index),
        "transactionIndex": encode_number(txn_index),
        "transactionHash": encode_32bytes(txn.hash),
        "blockHash": encode_32bytes(block.hash),
        "blockNumber": encode_number(block.number),
        "address": encode_32bytes(log.address),
        "data": encode_data(log.data),
        "topics": [
            encode_number(topic, 32) for topic in log.topics
        ],
    }


def serialize_block(block, full_transactions):
    if full_transactions:
        transactions = [
            serialize_txn(block, txn, txn_index)
            for txn_index, txn in enumerate(block.transaction_list)
        ]
    else:
        transactions = [encode_32bytes(txn.hash) for txn in block.transaction_list]

    unpadded_logs_bloom = int_to_big_endian(block.bloom)
    logs_bloom = zpad(unpadded_logs_bloom, (256 - len(unpadded_logs_bloom)))

    return {
        "number": encode_number(block.number),
        "hash": encode_32bytes(block.hash),
        "parentHash": encode_32bytes(block.prevhash),
        "nonce": encode_32bytes(block.nonce),
        "sha3Uncles": encode_32bytes(block.uncles_hash),
        # TODO logsBloom / padding
        "logsBloom": logs_bloom,
        "transactionsRoot": encode_32bytes(block.tx_list_root),
        "stateRoot": encode_32bytes(block.state_root),
        "miner": encode_address(block.coinbase),
        "difficulty": encode_number(block.difficulty),
        "totalDifficulty": encode_number(block.chain_difficulty()),
        "size": encode_number(len(rlp.encode(block))),
        "extraData": encode_32bytes(block.extra_data),
        "gasLimit": encode_number(block.gas_limit),
        "gasUsed": encode_number(block.gas_used),
        "timestamp": encode_number(block.timestamp),
        "transactions": transactions,
        "uncles": block.uncles
    }
