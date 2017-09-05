from __future__ import absolute_import

from cytoolz.functoolz import (
    complement,
)

from eth_utils import (
    is_dict,
    is_string,
)

from web3.middleware import (
    construct_formatting_middleware,
)

from eth_tester.utils.formatting import (
    hex_to_integer,
    apply_formatter_at_index,
    apply_formatter_if,
    apply_key_map,
)


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
        'eth_getFilterChanges': apply_formatter_at_index(
            to_integer_if_hex,
            0,
        ),
        'eth_getFilterLogs': apply_formatter_at_index(
            to_integer_if_hex,
            0,
        ),
    },
    result_formatters={
        'eth_getTransactionReceipt': apply_formatter_if(transaction_key_remapper, is_dict),
    },
)
