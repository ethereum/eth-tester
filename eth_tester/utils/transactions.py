# TODO: Should this be moved to a common package like eth-utils?

VALID_TRANSACTION_PARAMS = [
    'from',
    'to',
    'gas',
    'gasPrice',
    'value',
    'data',
    'nonce',
    'chainId',
]


def extract_valid_transaction_params(transaction_params):
    return {key: transaction_params[key]
            for key in VALID_TRANSACTION_PARAMS if key in transaction_params}
