from typing import (
    Any,
    Dict,
    Generator,
    Iterator,
    List,
    Optional,
    Tuple,
)

from eth_utils import (
    to_dict,
)
from toolz import (
    dissoc,
    merge,
)

from eth_tester.constants import (
    ACCESS_LIST_TX_TYPE,
    BLOB_TX_TYPE,
    DYNAMIC_FEE_TX_TYPE,
    LEGACY_TX_TYPE,
)
from tests.constants import (
    DEFAULT_GAS_LIMIT,
    ZERO_8BYTES,
    ZERO_32BYTES,
    ZERO_ADDRESS,
)


def yield_key_value_if_value_not_none(
    key: str, value: Any
) -> Iterator[Tuple[str, Any]]:
    if value is not None:
        yield key, value


def make_filter_params(
    from_block: Any = None,
    to_block: Any = None,
    address: Any = None,
    topics: Any = None,
) -> Dict[str, Any]:
    return {
        "from_block": from_block,
        "to_block": to_block,
        "address": address,
        "topics": topics,
    }


@to_dict
def make_transaction(
    blob_versioned_hashes: Any = None,
    chain_id: Any = None,
    _type: Any = None,
    _from: Any = None,
    to: Any = None,
    gas: Any = None,
    gas_price: Any = None,
    max_fee_per_blob_gas: Any = None,
    max_fee_per_gas: Any = None,
    max_priority_fee_per_gas: Any = None,
    value: Any = None,
    data: Any = None,
    nonce: Any = None,
    access_list: Any = None,
    r: Any = None,
    s: Any = None,
    v: Any = None,
) -> Generator[Tuple[str, Any], None, None]:
    yield from yield_key_value_if_value_not_none("type", _type)
    yield from yield_key_value_if_value_not_none("chain_id", chain_id)
    yield from yield_key_value_if_value_not_none("from", _from)
    yield from yield_key_value_if_value_not_none("to", to)
    yield from yield_key_value_if_value_not_none("gas", gas)
    yield from yield_key_value_if_value_not_none("gasPrice", gas_price)
    yield from yield_key_value_if_value_not_none("maxFeePerGas", max_fee_per_gas)
    yield from yield_key_value_if_value_not_none(
        "maxPriorityFeePerGas", max_priority_fee_per_gas
    )
    yield from yield_key_value_if_value_not_none("value", value)
    yield from yield_key_value_if_value_not_none("data", data)
    yield from yield_key_value_if_value_not_none("nonce", nonce)
    yield from yield_key_value_if_value_not_none("accessList", access_list)
    yield from yield_key_value_if_value_not_none("r", r)
    yield from yield_key_value_if_value_not_none("s", s)
    yield from yield_key_value_if_value_not_none("v", v)
    yield from yield_key_value_if_value_not_none(
        "blob_versioned_hashes", blob_versioned_hashes
    )
    yield from yield_key_value_if_value_not_none(
        "maxFeePerBlobGas", max_fee_per_blob_gas
    )


def make_legacy_txn(
    hash: Any = ZERO_32BYTES,
    nonce: Any = 0,
    block_hash: Optional[Any] = ZERO_32BYTES,
    block_number: Optional[Any] = 0,
    transaction_index: Optional[int] = 0,
    _from: Any = ZERO_ADDRESS,
    to: Any = ZERO_ADDRESS,
    value: Any = 0,
    gas: Any = DEFAULT_GAS_LIMIT,
    gas_price: Any = 1,
    data: Any = b"",
    v: Any = 0,
    r: Any = 0,
    s: Any = 0,
) -> Dict[str, Any]:
    return {
        "type": LEGACY_TX_TYPE,
        "hash": hash,
        "nonce": nonce,
        "blockHash": block_hash,
        "blockNumber": block_number,
        "transactionIndex": transaction_index,
        "from": _from,
        "to": to,
        "value": value,
        "gas": gas,
        "gasPrice": gas_price,
        "data": data,
        "s": s,
        "r": r,
        "v": v,
    }


def make_access_list_txn(
    chain_id: Any = 131277322940537,
    access_list: Tuple[Any, ...] = (),
    **kwargs: Any,
) -> Dict[str, Any]:
    legacy_kwargs = dissoc(dict(**kwargs), "chain_id", "access_list")
    return dict(
        merge(
            make_legacy_txn(**legacy_kwargs),
            {
                "type": ACCESS_LIST_TX_TYPE,
                "chainId": chain_id,
                "accessList": list(access_list),
                "yParity": legacy_kwargs.get("v", 0),
            },
        )
    )


# This is an outbound transaction so we still keep the gasPrice for now since the
# gasPrice is the min(maxFeePerGas, baseFeePerGas + maxPriorityFeePerGas).
# TODO: Sometime in 2022 the inclusion of gasPrice may be removed from dynamic fee
#  transactions and we can get rid of this behavior.
#  https://github.com/ethereum/execution-specs/pull/251
def make_dynamic_fee_txn(
    chain_id: Any = 131277322940537,
    max_fee_per_gas: Any = 2000000000,
    max_priority_fee_per_gas: Any = 1000000000,
    access_list: Tuple[Any, ...] = (),
    **kwargs: Any,
) -> Dict[str, Any]:
    legacy_kwargs = dissoc(
        dict(**kwargs),
        "chainId",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "accessList",
    )
    return dict(
        merge(
            make_access_list_txn(
                chain_id=chain_id, access_list=access_list, **legacy_kwargs
            ),
            {
                "type": DYNAMIC_FEE_TX_TYPE,
                "maxFeePerGas": max_fee_per_gas,
                "maxPriorityFeePerGas": max_priority_fee_per_gas,
            },
        )
    )


def make_blob_txn(
    chain_id: Any = 131277322940537,
    max_fee_per_gas: Any = 2000000000,
    max_priority_fee_per_gas: Any = 1000000000,
    access_list: Tuple[Any, ...] = (),
    max_fee_per_blob_gas: Any = 1000000000,
    blob_versioned_hashes: Tuple[Any, ...] = (),
    **kwargs: Any,
) -> Dict[str, Any]:
    legacy_kwargs = dissoc(
        dict(**kwargs),
        "chainId",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "accessList",
        "maxFeePerBlobGas",
        "blobVersionedHashes",
    )
    return dict(
        merge(
            make_dynamic_fee_txn(
                chain_id=chain_id,
                access_list=access_list,
                max_fee_per_gas=max_fee_per_gas,
                max_priority_fee_per_gas=max_priority_fee_per_gas,
                **legacy_kwargs,
            ),
            {
                "type": BLOB_TX_TYPE,
                "maxFeePerBlobGas": max_fee_per_blob_gas,
                "blobVersionedHashes": list(blob_versioned_hashes),
            },
        )
    )


def make_log(
    _type: Any = "mined",
    log_index: Any = 0,
    transaction_index: Any = 0,
    transaction_hash: Any = ZERO_32BYTES,
    block_hash: Any = ZERO_32BYTES,
    block_number: Any = 0,
    address: Any = ZERO_ADDRESS,
    data: Any = b"",
    topics: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    return {
        "type": _type,
        "logIndex": log_index,
        "transactionIndex": transaction_index,
        "transactionHash": transaction_hash,
        "blockHash": block_hash,
        "blockNumber": block_number,
        "address": address,
        "data": data,
        "topics": topics or [],
    }


def make_block(
    number: Any = 0,
    hash: Any = ZERO_32BYTES,
    parent_hash: Any = ZERO_32BYTES,
    nonce: Any = ZERO_8BYTES,
    sha3_uncles: Any = ZERO_32BYTES,
    logs_bloom: Any = 0,
    transactions_root: Any = ZERO_32BYTES,
    receipts_root: Any = ZERO_32BYTES,
    state_root: Any = ZERO_32BYTES,
    coinbase: Any = ZERO_ADDRESS,
    difficulty: Any = 0,
    mix_hash: Any = ZERO_32BYTES,
    total_difficulty: Any = 0,
    size: Any = 0,
    extra_data: Any = ZERO_32BYTES,
    gas_limit: Any = 30029122,  # gas limit at London fork block 12965000 on mainnet
    gas_used: Any = 21000,
    timestamp: Any = 4000000,
    transactions: Optional[List[Any]] = None,
    uncles: Optional[List[Any]] = None,
    base_fee_per_gas: Any = 1000000000,
    withdrawals: Optional[List[Any]] = None,
    withdrawals_root: Any = ZERO_32BYTES,
) -> Dict[str, Any]:
    block = {
        "number": number,
        "hash": hash,
        "parentHash": parent_hash,
        "nonce": nonce,
        "sha3Uncles": sha3_uncles,
        "logsBloom": logs_bloom,
        "transactionsRoot": transactions_root,
        "receiptsRoot": receipts_root,
        "stateRoot": state_root,
        "coinbase": coinbase,
        "difficulty": difficulty,
        "mixHash": mix_hash,
        "totalDifficulty": total_difficulty,
        "size": size,
        "extraData": extra_data,
        "gasLimit": gas_limit,
        "gasUsed": gas_used,
        "timestamp": timestamp,
        "transactions": transactions or [],
        "uncles": uncles or [],
        "baseFeePerGas": base_fee_per_gas,
        "withdrawals": withdrawals or [],
        "withdrawalsRoot": withdrawals_root,
    }
    return block


def make_withdrawal(
    index: Any = 2**64 - 1,
    validator_index: Any = 2**64 - 1,
    address: Any = ZERO_ADDRESS,
    amount: Any = 2**64 - 1,
) -> Dict[str, Any]:
    return {
        "index": index,
        "validatorIndex": validator_index,
        "address": address,
        "amount": amount,
    }


@to_dict
def make_receipt(
    transaction_hash: Any = ZERO_32BYTES,
    transaction_index: Any = 0,
    block_number: Any = 0,
    block_hash: Any = ZERO_32BYTES,
    cumulative_gas_used: Any = 0,
    blob_gas_used: Any = None,
    blob_gas_price: Any = None,
    _from: Any = ZERO_ADDRESS,
    gas_used: Any = 21000,
    effective_gas_price: Any = 1000000000,
    contract_address: Any = ZERO_ADDRESS,
    logs: Any = None,
    state_root: Any = b"\x00",
    status: Any = 0,
    to: Any = ZERO_ADDRESS,
    _type: Any = "0x0",
) -> Iterator[Tuple[str, Any]]:
    yield from yield_key_value_if_value_not_none("transactionHash", transaction_hash)
    yield from yield_key_value_if_value_not_none("transactionIndex", transaction_index)
    yield from yield_key_value_if_value_not_none("blockNumber", block_number)
    yield from yield_key_value_if_value_not_none("blockHash", block_hash)
    yield from yield_key_value_if_value_not_none(
        "cumulativeGasUsed", cumulative_gas_used
    )
    yield from yield_key_value_if_value_not_none("gasUsed", gas_used)
    yield from yield_key_value_if_value_not_none(
        "effectiveGasPrice", effective_gas_price
    )
    yield from yield_key_value_if_value_not_none("from", _from)
    yield from yield_key_value_if_value_not_none("to", to)
    yield from yield_key_value_if_value_not_none("type", _type)
    yield from yield_key_value_if_value_not_none("stateRoot", state_root)
    yield from yield_key_value_if_value_not_none("status", status)
    yield from yield_key_value_if_value_not_none("logs", logs or [])
    yield from yield_key_value_if_value_not_none("contractAddress", contract_address)
    yield from yield_key_value_if_value_not_none("blobGasUsed", blob_gas_used)
    yield from yield_key_value_if_value_not_none("blobGasPrice", blob_gas_price)
