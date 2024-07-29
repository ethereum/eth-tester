import time
from typing import (
    Any,
    Dict,
    Union,
)

from ethereum.cancun.blocks import (
    Block,
)

from eth_tester.constants import (
    BLANK_ROOT_HASH,
    EMPTY_RLP_LIST_HASH,
    ZERO_HASH32,
)
from eth_tester.utils.casing import (
    lower_camel_case_to_snake_case,
)
from eth_tester.utils.transactions import (
    calculate_effective_gas_price,
    extract_transaction_type,
)


def serialize_block(
    backend_instance,
    block: Union[Block, Dict[str, Any]],
    full_transaction: bool = False,
    is_pending: bool = False,
):
    if is_pending:
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
        tx_list = enumerate(block["transactions"])
        serialized_block = _append_txs_to_block(
            backend_instance, serialized_block, tx_list, full_transaction
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
        tx_list = enumerate(block.transactions)
        serialized_block = _append_txs_to_block(
            backend_instance, serialized_block, tx_list, full_transaction
        )

    return serialized_block


def _append_txs_to_block(backend_instance, serialized_block, tx_list, full_transaction):
    for i, tx in tx_list:
        if full_transaction:
            json_tx = serialize_transaction_for_block(
                backend_instance, serialized_block, tx, i
            )
            serialized_block["transactions"].append(json_tx)
        else:
            serialized_block["transactions"].append(backend_instance._get_tx_hash(tx))
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


def serialize_transaction(tx, pending_block: Dict[str, Any] = None):
    if pending_block:
        tx["block_hash"] = ZERO_HASH32
        tx["block_number"] = pending_block["header"]["number"]
        tx["transaction_index"] = len(pending_block["transactions"]) - 1

    serialized = {
        lower_camel_case_to_snake_case(key): value for key, value in tx.items()
    }

    if "gas_limit" in serialized and "gas" not in serialized:
        serialized["gas"] = serialized.pop("gas_limit")

    return serialized


def serialize_receipt(
    backend_instance, tx, process_transaction_return, index, cumulative_gas_used, contract_address=None,
):
    tx_gas_consumed = process_transaction_return[0]
    logs = process_transaction_return[1]
    errors = process_transaction_return[2]
    pending_block = backend_instance._pending_block
    serialized = {
        "block_hash": None,  # updated when block is finalized
        "transaction_hash": backend_instance._get_tx_hash(tx),
        "transaction_index": index,
        "block_number": pending_block["header"]["number"],
        "to": tx.to,
        "from": backend_instance._fork_module.recover_sender(tx.chain_id, tx),
        "gas_used": tx_gas_consumed,
        "cumulative_gas_used": cumulative_gas_used,
        "effective_gas_price": calculate_effective_gas_price(tx, pending_block),
        "contract_address": contract_address,
        "state_root": None,  # updated when block is finalized
        "logs": logs,
        "status": 0 if errors else 1,
        "type": extract_transaction_type(tx),
    }
    return serialized
