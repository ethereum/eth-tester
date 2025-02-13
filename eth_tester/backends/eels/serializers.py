import time
from typing import (
    Any,
    Dict,
    Union,
)

from .utils import (
    eels_is_available,
)

if eels_is_available():
    from ethereum.cancun.blocks import (
        Block,
    )
else:
    Block = None

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


def _serialize_withdrawals_to_block(serialized_block, withdrawals):
    for withdrawal in withdrawals:
        serialized_block["withdrawals"].append(
            {
                "index": int(withdrawal.index),
                "validator_index": int(withdrawal.validator_index),
                "address": withdrawal.address,
                "amount": int(withdrawal.amount),
            }
        )
    return serialized_block


def serialize_block(
    backend_instance,
    block: Union[Block, Dict[str, Any]],
    full_transactions: bool = False,
    is_pending: bool = False,
):
    if is_pending:
        # still a dict
        serialized_block = {
            "number": int(block["header"]["number"]),
            "hash": ZERO_HASH32,
            "parent_hash": block["header"]["parent_hash"],
            "nonce": block["header"]["nonce"],
            "state_root": BLANK_ROOT_HASH,
            "coinbase": block["header"]["coinbase"],
            "difficulty": int(block["header"]["difficulty"]),
            "mix_hash": ZERO_HASH32,
            "total_difficulty": int(block["header"]["difficulty"]),
            "size": 0,
            "extra_data": block["header"]["extra_data"],
            "gas_limit": int(block["header"]["gas_limit"]),
            "gas_used": 0,
            "blob_gas_used": 0,
            "excess_blob_gas": 0,
            "base_fee_per_gas": int(block["header"]["base_fee_per_gas"]),
            "timestamp": block["header"]["timestamp"] or int(time.time()),
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
            "withdrawals_root": block["header"].get(
                "withdrawals_root", BLANK_ROOT_HASH
            ),
        }
        serialized_block = _serialize_txs_to_block(
            backend_instance, serialized_block, block["transactions"], full_transactions
        )
        serialized_block = _serialize_withdrawals_to_block(
            serialized_block, block["withdrawals"]
        )
    else:
        serialized_block = {
            "number": int(block.header.number),
            "hash": backend_instance._fork_module.compute_header_hash(block.header),
            "parent_hash": block.header.parent_hash,
            "nonce": block.header.nonce,
            "state_root": block.header.state_root,
            "coinbase": block.header.coinbase,
            "difficulty": int(block.header.difficulty),
            "mix_hash": block.header.prev_randao,
            "total_difficulty": int(block.header.difficulty),
            "size": 0,
            "extra_data": block.header.extra_data,
            "gas_limit": int(block.header.gas_limit),
            "gas_used": int(block.header.gas_used),
            "blob_gas_used": int(block.header.blob_gas_used),
            "excess_blob_gas": int(block.header.excess_blob_gas),
            "base_fee_per_gas": int(block.header.base_fee_per_gas),
            "parent_beacon_block_root": block.header.parent_beacon_block_root,
            "timestamp": int(block.header.timestamp),
            "transactions": [],  # serialized below
            "uncles": [],  # TODO serialize below
            "withdrawals": [],  # TODO serialize below
            "logs_bloom": int.from_bytes(block.header.bloom, "big"),
            "sha3_uncles": block.header.ommers_hash,
            "transactions_root": block.header.transactions_root,
            "receipts_root": block.header.receipt_root,
            "withdrawals_root": block.header.withdrawals_root,
        }
        serialized_block = _serialize_txs_to_block(
            backend_instance, serialized_block, block.transactions, full_transactions
        )
        serialized_block = _serialize_withdrawals_to_block(
            serialized_block, block.withdrawals
        )

    return serialized_block


def _serialize_txs_to_block(
    backend_instance, serialized_block, tx_list, full_transactions
):
    for i, tx in enumerate(tx_list):
        if full_transactions:
            json_tx = serialize_eels_transaction_for_block(
                backend_instance,
                tx,
                i,
                serialized_block["number"],
                serialized_block["hash"],
            )
            serialized_block["transactions"].append(json_tx)
        else:
            serialized_block["transactions"].append(backend_instance._get_tx_hash(tx))

    return serialized_block


def serialize_eels_transaction_for_block(
    backend_instance,
    tx,
    index,
    block_number,
    # default to pending block with no block hash
    block_hash=None,
):
    json_tx = {
        "hash": backend_instance._get_tx_hash(tx),
        "nonce": int(tx.nonce),
        "block_hash": block_hash,
        "block_number": int(block_number),
        "transaction_index": int(index),
        "to": tx.to,
        "value": int(tx.value),
        "gas": int(tx.gas),
        "data": tx.data,
    }

    if hasattr(tx, "gas_price"):
        json_tx["gas_price"] = int(tx.gas_price)
    if hasattr(tx, "max_fee_per_gas"):
        json_tx["max_fee_per_gas"] = int(tx.max_fee_per_gas)
        json_tx["gas_price"] = int(tx.max_fee_per_gas)
    if hasattr(tx, "max_priority_fee_per_gas"):
        json_tx["max_priority_fee_per_gas"] = int(tx.max_priority_fee_per_gas)
    if hasattr(tx, "access_list"):
        # TODO: properly serialize access list
        json_tx["access_list"] = tx.access_list
    if hasattr(tx, "blob_versioned_hashes"):
        json_tx["blob_versioned_hashes"] = tx.blob_versioned_hashes
    if hasattr(tx, "max_fee_per_blob_gas"):
        json_tx["max_fee_per_blob_gas"] = int(tx.max_fee_per_blob_gas)
    if hasattr(tx, "chain_id"):
        json_tx["chain_id"] = int(tx.chain_id)
    if hasattr(tx, "v"):
        json_tx["v"] = int(tx.v)
    if hasattr(tx, "r"):
        json_tx["r"] = int(tx.r)
    if hasattr(tx, "s"):
        json_tx["s"] = int(tx.s)
    if hasattr(tx, "y_parity"):
        json_tx["y_parity"] = int(tx.y_parity)
        json_tx["v"] = int(tx.y_parity)

    json_tx["from"] = backend_instance._fork_module.recover_sender(
        backend_instance.chain.chain_id, tx
    )

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
        tx["block_number"] = int(pending_block["header"]["number"])
        tx["transaction_index"] = len(pending_block["transactions"]) - 1

    serialized = {
        lower_camel_case_to_snake_case(key): value for key, value in tx.items()
    }

    if "gas_limit" in serialized and "gas" not in serialized:
        serialized["gas"] = serialized.pop("gas_limit")

    return serialized


def serialize_pending_receipt(
    backend_instance,
    tx,
    process_transaction_return,
    index,
    cumulative_gas_used,
    contract_address=None,
):
    tx_hash = backend_instance._get_tx_hash(tx)
    tx_gas_consumed = int(process_transaction_return[0])

    pending_block = backend_instance._pending_block
    block_num = int(pending_block["header"]["number"])

    logs = (
        serialize_pending_logs(process_transaction_return[1])
        if process_transaction_return[1]
        else []
    )
    errors = process_transaction_return[2]

    serialized = {
        "block_hash": None,  # updated when block is finalized
        "transaction_hash": tx_hash,
        "transaction_index": index,
        "block_number": int(block_num),
        "to": tx.to,
        "from": backend_instance._fork_module.recover_sender(
            backend_instance.chain.chain_id, tx
        ),
        "gas_used": tx_gas_consumed,
        "cumulative_gas_used": cumulative_gas_used,
        "effective_gas_price": calculate_effective_gas_price(
            tx, pending_block["header"]
        ),
        "contract_address": contract_address,
        "state_root": None,  # updated when block is finalized
        "logs": logs,
        "status": 0 if errors else 1,
        "type": extract_transaction_type(tx),
    }
    return serialized


def serialize_pending_logs(eels_logs):
    return [
        {
            "address": log.address,
            "topics": log.topics,
            "data": log.data,
            "log_index": int(i),
            "type": "pending",
            # rest of the fields are added when block is finalized
        }
        for i, log in enumerate(eels_logs)
    ]
