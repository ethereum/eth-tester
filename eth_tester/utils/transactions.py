# TODO: Should this be moved to a common package like eth-utils?
from eth_utils import (
    to_list,
)


VALID_TRANSACTION_PARAMS = [
    'from',
    'to',
    'gas',
    'gas_price',
    'value',
    'data',
    'nonce',
    'r',
    's',
    'v',
]


def extract_valid_transaction_params(transaction_params):
    return {key: transaction_params[key]
            for key in VALID_TRANSACTION_PARAMS if key in transaction_params}


@to_list
def remove_matching_transaction_from_list(transaction_list, transaction):
    for tx in transaction_list:
        nonce_equal = transaction['nonce'] == tx['nonce']
        from_equal = transaction['from'] == tx['from']
        match = nonce_equal and from_equal
        if not match:
            yield tx
