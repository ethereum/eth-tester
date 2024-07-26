import time
from typing import (
    Any,
    Dict,
    Union,
)

from eth_tester.constants import (
    BLANK_ROOT_HASH,
    EMPTY_RLP_LIST_HASH,
    ZERO_HASH32,
)

from ethereum.cancun.blocks import (
    Block,
)


def serialize_block(
    backend_instance,
    block: Union[Block, Dict[str, Any]],
    full_transaction: bool = False,
    pending: bool = False,
):
    if pending:
        # still a dict
        serialized_block = {
            "number": block["header"]["number"],
            "hash": ZERO_HASH32,
            "parent_hash": block["header"]["parent_hash"],
            "nonce": block["header"]["nonce"],
            "state_root": BLANK_ROOT_HASH,
            "coinbase": block["header"]["coinbase"],
            "difficulty": block["header"]["difficulty"],
            "mix_hash": ZERO_HASH32,
            "total_difficulty": block["header"]["difficulty"],  # TODO: calculate
            "size": 0,
            "extra_data": block["header"]["extra_data"],
            "gas_limit": block["header"]["gas_limit"],
            "gas_used": 0,
            "timestamp": int(time.time()),
            "transactions": block.get("transactions", []),
            "uncles": block.get("ommers", []),
            "withdrawals": block.get("withdrawals", []),
            # TODO: Pending blocks still calculate these. They are not present
            #  in the dict
            "logs_bloom": 0,
            "sha3_uncles": block["header"].get("ommers_hash", EMPTY_RLP_LIST_HASH),
            "transactions_root": block["header"].get(
                "transactions_root", BLANK_ROOT_HASH
            ),
            "receipts_root": block["header"].get("receipts_root", BLANK_ROOT_HASH),
        }
        for tx in block["transactions"]:
            if full_transaction:
                json_tx = serialize_transaction_for_block(backend_instance, block, tx)
                serialized_block["transactions"].append(json_tx)
            else:
                serialized_block["transactions"].append(
                    backend_instance._get_tx_hash(tx)
                )

    else:
        serialized_block = {
            "number": block.header.number,
            "hash": backend_instance._fork_module.compute_header_hash(block.header),
            "parent_hash": block.header.parent_hash,
            "nonce": block.header.nonce,
            "sha3_uncles": block.header.ommers_hash,
            "logs_bloom": int.from_bytes(block.header.bloom, "big"),
            "transactions_root": block.header.transactions_root,
            "receipts_root": block.header.receipt_root,
            "state_root": block.header.state_root,
            "coinbase": block.header.coinbase,
            "difficulty": block.header.difficulty,
            "mix_hash": block.header.prev_randao,
            "total_difficulty": block.header.difficulty,
            "size": 0,
            "extra_data": block.header.extra_data,
            "gas_limit": block.header.gas_limit,
            "gas_used": block.header.gas_used,
            "timestamp": block.header.timestamp,
            "transactions": [],
            "uncles": [],
            "withdrawals": [],
        }
        for i, tx in enumerate(block.transactions):
            if full_transaction:
                json_tx = serialize_transaction_for_block(
                    backend_instance, serialized_block, tx, i
                )
                serialized_block["transactions"].append(json_tx)
            else:
                serialized_block["transactions"].append(
                    backend_instance._get_tx_hash(tx)
                )

    return serialized_block


def serialize_transaction_for_block(
    backend_instance,
    serialized_block: Dict[str, Any],
    tx,
    index,
):
    json_tx = {
        "hash": backend_instance._get_tx_hash(tx),
        "nonce": tx.nonce,
        "block_hash": serialized_block["hash"],
        "block_number": serialized_block["number"],
        "transaction_index": index,
        "to": tx.to,
        "value": tx.value,
        "gas": tx.gas,
        "data": tx.data,
    }

    if hasattr(tx, "gas_price"):
        json_tx["gas_price"] = tx.gas_price
    if hasattr(tx, "max_fee_per_gas"):
        json_tx["max_fee_per_gas"] = tx.max_fee_per_gas
        json_tx["gas_price"] = tx.max_fee_per_gas
    if hasattr(tx, "max_priority_fee_per_gas"):
        json_tx["max_priority_fee_per_gas"] = tx.max_priority_fee_per_gas
    if hasattr(tx, "access_list"):
        json_tx["access_list"] = tx.access_list
    if hasattr(tx, "blob_versioned_hashes"):
        json_tx["blob_versioned_hashes"] = tx.blob_versioned_hashes
    if hasattr(tx, "max_fee_per_blob_gas"):
        json_tx["max_fee_per_blob_gas"] = tx.max_fee_per_blob_gas
    if hasattr(tx, "chain_id"):
        json_tx["chain_id"] = tx.chain_id
        json_tx["from"] = backend_instance._fork_module.recover_sender(tx.chain_id, tx)
    if hasattr(tx, "v"):
        json_tx["v"] = tx.v
    if hasattr(tx, "r"):
        json_tx["r"] = tx.r
    if hasattr(tx, "s"):
        json_tx["s"] = tx.s
    if hasattr(tx, "y_parity"):
        json_tx["y_parity"] = tx.y_parity
        json_tx["v"] = tx.y_parity

    if isinstance(tx, bytes) or isinstance(
        tx, backend_instance._transactions_module.LegacyTransaction
    ):
        json_tx["type"] = "0x00"
    elif isinstance(tx, backend_instance._transactions_module.AccessListTransaction):
        json_tx["type"] = "0x01"
    elif isinstance(tx, backend_instance._transactions_module.FeeMarketTransaction):
        json_tx["type"] = "0x02"
    elif isinstance(tx, backend_instance._transactions_module.BlobTransaction):
        json_tx["type"] = "0x03"

    return json_tx
