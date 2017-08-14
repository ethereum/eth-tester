from cytoolz.functoolz import (
    complement,
    curry,
)

from eth_utils import (
    to_dict,
)

from web3.middleware import (
    BaseFormatterMiddleware,
)
from web3.utils.formatters import (
    hex_to_integer,
    apply_formatter_at_index,
    apply_formatter_if,
    apply_formatters_to_dict,
)


@curry
@to_dict
def apply_key_map(key_mappings, value):
    for key, item in value.items():
        if key in key_mappings:
            yield key_mappings[key], item
        else:
            yield key, item


def is_named_block(value):
    return value in {"latest", "earliest", "pending"}


is_not_named_block = complement(is_named_block)


TRANSACTION_PARAMS_FORMATTERS = {
    'value': hex_to_integer,
    'gas': hex_to_integer,
}

transaction_params_formatter = apply_formatters_to_dict(TRANSACTION_PARAMS_FORMATTERS)


TRANSACTION_KEY_MAPPINGS = {
    'transaction_hash': 'transactionHash',
}

transaction_key_remapper = apply_key_map(TRANSACTION_KEY_MAPPINGS)


class EthereumTesterFormatterMiddleware(BaseFormatterMiddleware):
    request_formatters = {
        'eth_getBlockByNumber': apply_formatter_at_index(
            apply_formatter_if(hex_to_integer, is_not_named_block),
            0,
        ),
        'eth_sendTransaction': apply_formatter_at_index(
            transaction_params_formatter,
            0,
        ),
    }
    result_formatters = {
        'eth_blockNumber': hex,
        'eth_getTransactionCount': hex,
        'eth_getTransactionReceipt': transaction_key_remapper,
    }
