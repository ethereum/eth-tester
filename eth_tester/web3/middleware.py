from cytoolz.functoolz import (
    complement,
    curry,
)

from eth_utils import (
    to_dict,
    is_string,
)

from web3.middleware import (
    construct_formatting_middleware,
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


to_integer_if_hex = apply_formatter_if(hex_to_integer, is_string)


is_not_named_block = complement(is_named_block)


TRANSACTION_KEY_MAPPINGS = {
    'transaction_hash': 'transactionHash',
}

transaction_key_remapper = apply_key_map(TRANSACTION_KEY_MAPPINGS)


ethereum_tester_middleware = construct_formatting_middleware(
    request_formatters={
        'eth_getBlockByNumber': apply_formatter_at_index(
            apply_formatter_if(to_integer_if_hex, is_not_named_block),
            0,
        ),
    },
    result_formatters={
        'eth_getTransactionReceipt': transaction_key_remapper,
    },
)
