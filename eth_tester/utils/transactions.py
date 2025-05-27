from typing import (
    Any,
    Dict,
)

from eth_utils import (
    to_dict,
    to_list,
)

from eth_tester.constants import (
    DYNAMIC_FEE_TRANSACTION_PARAMS,
    DYNAMIC_FEE_TX_TYPE,
)

VALID_TRANSACTION_PARAMS = [
    "type",
    "chainId",
    "from",
    "to",
    "gas",
    "gasPrice",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "value",
    "data",
    "nonce",
    "accessList",
    "r",
    "s",
    "v",
]


def extract_valid_transaction_params(transaction_params):
    return {
        key: transaction_params[key]
        for key in VALID_TRANSACTION_PARAMS
        if key in transaction_params
    }


def extract_transaction_type(transaction):
    if isinstance(transaction, dict):
        return (
            "0x2"
            if "maxFeePerGas" in transaction
            else (
                "0x1"
                if "maxFeePerGas" not in transaction and "accessList" in transaction
                else "0x0"
            )
        )
    else:
        # Typed transactions
        return (
            "0x2"
            if hasattr(transaction, "max_fee_per_gas")
            else (
                "0x1"
                if not hasattr(transaction, "max_fee_per_gas")
                and hasattr(transaction, "access_list")
                else "0x0"
            )
        )


@to_dict
def normalize_transaction_fields(
    transaction: Dict[str, Any],
    chain_id: int,
    from_nonce: int,
    base_fee_per_gas: int,
):
    is_dynamic_fee_transaction = (
        any(_ in transaction for _ in DYNAMIC_FEE_TRANSACTION_PARAMS)
        or
        # if no fee params exist, default to dynamic fee transaction:
        not any(
            _ in transaction for _ in DYNAMIC_FEE_TRANSACTION_PARAMS + ("gasPrice",)
        )
    )
    is_typed_transaction = is_dynamic_fee_transaction or "accessList" in transaction

    for key in transaction:
        if key in ("from", "type"):
            continue
        if key == "v" and is_typed_transaction:
            yield "yParity", transaction["v"]  # use y_parity for typed txns, internally
            continue
        yield key, transaction[key]

    if "nonce" not in transaction:
        yield "nonce", from_nonce or 0
    if "data" not in transaction:
        yield "data", b""
    if "value" not in transaction:
        yield "value", 0
    if "to" not in transaction:
        yield "to", b""

    if is_dynamic_fee_transaction:
        if not any(_ in transaction for _ in DYNAMIC_FEE_TRANSACTION_PARAMS):
            yield "maxFeePerGas", 1 * 10**9
            yield "maxPriorityFeePerGas", 1 * 10**9
        elif (
            "maxPriorityFeePerGas" in transaction and "maxFeePerGas" not in transaction
        ):
            yield (
                "maxFeePerGas",
                transaction["maxPriorityFeePerGas"] + 2 * base_fee_per_gas,
            )
    else:
        yield "gasPrice", transaction.get("gasPrice", 1 * 10**9)

    if is_typed_transaction:
        # typed transaction
        if "accessList" not in transaction:
            yield "accessList", ()
        if "chainId" not in transaction:
            yield "chainId", chain_id


@to_list
def remove_matching_transaction_from_list(transaction_list, transaction):
    for tx in transaction_list:
        nonce_equal = transaction["nonce"] == tx["nonce"]
        from_equal = transaction["from"] == tx["from"]
        match = nonce_equal and from_equal
        if not match:
            yield tx


def calculate_effective_gas_price(
    transaction: Dict[str, Any], block_header: Dict[str, Any]
):
    transaction_type = int(extract_transaction_type(transaction), 16)

    if transaction_type < DYNAMIC_FEE_TX_TYPE:
        return int(
            transaction["gasPrice"]
            if isinstance(transaction, dict)
            else transaction.gas_price
        )
    else:
        if isinstance(transaction, dict):
            max_fee = int(transaction["maxFeePerGas"])
            max_priority_fee = int(transaction["maxPriorityFeePerGas"])
        else:
            max_fee = int(transaction.max_fee_per_gas)
            max_priority_fee = int(transaction.max_priority_fee_per_gas)

        base_fee = int(
            block_header["base_fee_per_gas"]
            if isinstance(block_header, dict)
            else block_header.base_fee_per_gas
        )
        return min(max_fee, max_priority_fee + base_fee)
