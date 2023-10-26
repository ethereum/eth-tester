# TODO: Should this be moved to a common package like eth-utils?
from eth_utils import (
    to_list,
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
    return (
        "0x2"
        if "max_fee_per_gas" in transaction
        else "0x1"
        if "max_fee_per_gas" not in transaction and "access_list" in transaction
        # legacy transactions being '0x0' taken from current geth version v1.10.10
        else "0x0"
    )


@to_list
def remove_matching_transaction_from_list(transaction_list, transaction):
    for tx in transaction_list:
        nonce_equal = transaction["nonce"] == tx["nonce"]
        from_equal = transaction["from"] == tx["from"]
        match = nonce_equal and from_equal
        if not match:
            yield tx
