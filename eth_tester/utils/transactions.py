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
    "chain_id",
    "from",
    "to",
    "gas",
    "gas_price",
    "max_fee_per_gas",
    "max_priority_fee_per_gas",
    "value",
    "data",
    "nonce",
    "access_list",
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
            if "max_fee_per_gas" in transaction
            else (
                "0x1"
                if "max_fee_per_gas" not in transaction and "access_list" in transaction
                # legacy transactions being '0x0' taken from current geth version v1.10.10
                else "0x0"
            )
        )
    else:
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
            _ in transaction for _ in DYNAMIC_FEE_TRANSACTION_PARAMS + ("gas_price",)
        )
    )
    is_typed_transaction = is_dynamic_fee_transaction or "access_list" in transaction

    for key in transaction:
        if key in ("from", "type"):
            continue
        if key == "v" and is_typed_transaction:
            yield "y_parity", transaction[
                "v"
            ]  # use y_parity for typed txns, internally
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
            yield "max_fee_per_gas", 1 * 10**9
            yield "max_priority_fee_per_gas", 1 * 10**9
        elif (
            "max_priority_fee_per_gas" in transaction
            and "max_fee_per_gas" not in transaction
        ):
            yield (
                "max_fee_per_gas",
                transaction["max_priority_fee_per_gas"] + 2 * base_fee_per_gas,
            )

    if is_typed_transaction:
        # typed transaction
        if "access_list" not in transaction:
            yield "access_list", ()
        if "chain_id" not in transaction:
            yield "chain_id", chain_id


@to_list
def remove_matching_transaction_from_list(transaction_list, transaction):
    for tx in transaction_list:
        nonce_equal = transaction["nonce"] == tx["nonce"]
        from_equal = transaction["from"] == tx["from"]
        match = nonce_equal and from_equal
        if not match:
            yield tx


def calculate_effective_gas_price(transaction, block):
    transaction_type = int(extract_transaction_type(transaction), 16)
    if isinstance(transaction, dict):
        max_fee = transaction["max_fee_per_gas"]
        max_priority_fee = transaction["max_priority_fee_per_gas"]
    else:
        max_fee = transaction.max_fee_per_gas
        max_priority_fee = transaction.max_priority_fee_per_gas

    if isinstance(block, dict):
        base_fee = block["header"]["base_fee_per_gas"]
    else:
        base_fee = block.header.base_fee_per_gas

    return (
        min(max_fee, max_priority_fee + base_fee)
        if transaction_type >= DYNAMIC_FEE_TX_TYPE
        else transaction.gas_price
    )
