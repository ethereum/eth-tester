import time
from typing import (
    Any,
    Dict,
    List,
    Sequence,
    Tuple,
    Union,
)

from ethereum.crypto.hash import (
    keccak256,
)
from ethereum_rlp import (
    rlp,
)

from eth_tester.backends.base import (
    BaseChainBackend,
)

from .utils import (
    eels_is_available,
)

if eels_is_available():
    from ethereum.cancun.blocks import (
        Block,
        Log,
        Transaction,
    )
else:
    Block = None
    Log = None

from eth_tester.constants import (
    BLANK_ROOT_HASH,
    EMPTY_RLP_LIST_HASH,
    ZERO_HASH32,
)
from eth_tester.utils.transactions import (
    calculate_effective_gas_price,
    extract_transaction_type,
)


def _serialize_withdrawals_to_block(serialized_block, withdrawals):
    txn_withdrawals = []
    for withdrawal in withdrawals:
        txn_withdrawals.append(serialize_eels_withdrawal_for_block(withdrawal))

    serialized_block["withdrawals"] = txn_withdrawals
    return serialized_block


def serialize_eels_withdrawal_for_block(withdrawal):
    return {
        "index": int(withdrawal.index),
        "validatorIndex": int(withdrawal.validator_index),
        "address": withdrawal.address,
        "amount": int(withdrawal.amount),
    }


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
            "parentHash": block["header"]["parent_hash"],
            "nonce": block["header"]["nonce"],
            "stateRoot": BLANK_ROOT_HASH,
            "coinbase": block["header"]["coinbase"],
            "difficulty": int(block["header"]["difficulty"]),
            "mixHash": ZERO_HASH32,
            "totalDifficulty": int(block["header"]["difficulty"]),
            "size": 0,
            "extraData": block["header"]["extra_data"],
            "gasLimit": int(block["header"]["gas_limit"]),
            "gasUsed": 0,
            "blobGasUsed": 0,
            "excessBlobGas": 0,
            "baseFeePerGas": int(block["header"]["base_fee_per_gas"]),
            "timestamp": block["header"]["timestamp"] or int(time.time()),
            "transactions": block.get("transactions", []),
            "uncles": block.get("ommers", []),
            "withdrawals": block.get("withdrawals", []),
            # TODO: Pending blocks still calculate these. They are not present
            #  in the dict
            "logsBloom": 0,
            "sha3Uncles": block["header"].get("ommers_hash", EMPTY_RLP_LIST_HASH),
            "transactionsRoot": block["header"].get(
                "transactionsRoot", BLANK_ROOT_HASH
            ),
            "receiptsRoot": block["header"].get("receipts_root", BLANK_ROOT_HASH),
            "withdrawalsRoot": block["header"].get("withdrawalsRoot", BLANK_ROOT_HASH),
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
            "hash": keccak256(rlp.encode(block.header)),
            "parentHash": block.header.parent_hash,
            "nonce": block.header.nonce,
            "stateRoot": block.header.state_root,
            "coinbase": block.header.coinbase,
            "difficulty": int(block.header.difficulty),
            "mixHash": block.header.prev_randao,
            "totalDifficulty": int(block.header.difficulty),
            "size": 0,
            "extraData": block.header.extra_data,
            "gasLimit": int(block.header.gas_limit),
            "gasUsed": int(block.header.gas_used),
            "blobGasUsed": int(block.header.blob_gas_used),
            "excessBlobGas": int(block.header.excess_blob_gas),
            "baseFeePerGas": int(block.header.base_fee_per_gas),
            "parentBeaconBlockRoot": block.header.parent_beacon_block_root,
            "timestamp": int(block.header.timestamp),
            "transactions": [],  # serialized below
            "uncles": [],  # TODO serialize below
            "withdrawals": [],  # TODO serialize below
            "logsBloom": int.from_bytes(block.header.bloom, "big"),
            "sha3Uncles": block.header.ommers_hash,
            "transactionsRoot": block.header.transactions_root,
            "receiptsRoot": block.header.receipt_root,
            "withdrawalsRoot": block.header.withdrawals_root,
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
    txns = []
    for i, tx in enumerate(tx_list):
        if full_transactions:
            json_tx = serialize_eels_transaction_for_block(
                backend_instance,
                tx,
                i,
                serialized_block["number"],
                serialized_block["hash"],
            )
            txns.append(json_tx)
        else:
            txns.append(backend_instance._get_tx_hash(tx))

    serialized_block["transactions"] = txns
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
        "blockHash": block_hash,
        "blockNumber": int(block_number),
        "transactionIndex": int(index),
        "to": tx.to,
        "value": int(tx.value),
        "gas": int(tx.gas),
        "data": tx.data,
    }
    if hasattr(tx, "gas_price"):
        json_tx["gasPrice"] = int(tx.gas_price)
    if hasattr(tx, "max_fee_per_gas"):
        json_tx["maxFeePerGas"] = int(tx.max_fee_per_gas)
        json_tx["gasPrice"] = int(tx.max_fee_per_gas)
    if hasattr(tx, "max_priority_fee_per_gas"):
        json_tx["maxPriorityFeePerGas"] = int(tx.max_priority_fee_per_gas)
    if hasattr(tx, "access_list"):
        # TODO: properly serialize access list
        json_tx["accessList"] = tx.access_list
    if hasattr(tx, "blob_versioned_hashes"):
        json_tx["blobVersionedHashes"] = tx.blob_versioned_hashes
    if hasattr(tx, "max_fee_per_blob_gas"):
        json_tx["maxFeePerBlobGas"] = int(tx.max_fee_per_blob_gas)
    if hasattr(tx, "chain_id"):
        json_tx["chainId"] = int(tx.chain_id)
    if hasattr(tx, "v"):
        json_tx["v"] = int(tx.v)
    if hasattr(tx, "r"):
        json_tx["r"] = int(tx.r)
    if hasattr(tx, "s"):
        json_tx["s"] = int(tx.s)
    if hasattr(tx, "y_parity"):
        json_tx["yParity"] = int(tx.y_parity)
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
        tx["blockHash"] = ZERO_HASH32
        tx["blockNumber"] = int(pending_block["header"]["number"])
        tx["transactionIndex"] = len(pending_block["transactions"]) - 1

    serialized = tx.copy()
    if "gasLimit" in serialized and "gas" not in serialized:
        serialized["gas"] = serialized.pop("gasLimit")

    return serialized


def serialize_pending_receipt(
    backend_instance: BaseChainBackend,
    tx: Transaction,
    process_transaction_return: Tuple[int, List[Log], int],
    index: int,
    cumulative_gas_used: int,
    contract_address=None,
) -> Dict[str, Any]:
    # breakpoint()
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
        "blockHash": None,  # updated when block is finalized
        "transactionHash": tx_hash,
        "transactionIndex": index,
        "blockNumber": int(block_num),
        "to": tx.to,
        "from": backend_instance._fork_module.recover_sender(
            backend_instance.chain.chain_id, tx
        ),
        "gasUsed": tx_gas_consumed,
        "cumulativeGasUsed": cumulative_gas_used,
        "effectiveGasPrice": calculate_effective_gas_price(tx, pending_block["header"]),
        "contractAddress": contract_address,
        "stateRoot": None,  # updated when block is finalized
        "logs": logs,
        "status": 0 if errors else 1,
        "type": extract_transaction_type(tx),
    }

    return serialized


def serialize_pending_logs(eels_logs: Sequence["Log"]) -> Sequence[Dict[str, Any]]:
    return [
        {
            "address": log.address,
            "topics": log.topics,
            "data": log.data,
            "logIndex": int(i),
            "type": "pending",
            # rest of the fields are added when block is finalized
        }
        for i, log in enumerate(eels_logs)
    ]
