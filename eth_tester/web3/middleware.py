from cytoolz.functoolz import (
    complement,
)
from eth_utils import (
    is_string,
)

from web3.middleware import (
    BaseFormatterMiddleware,
)
from web3.utils.formatters import (
    hex_to_integer,
    apply_formatter_at_index,
    apply_formatter_if,
)


def is_named_block(value):
    return value in {"latest", "earliest", "pending"}


is_not_named_block = complement(is_named_block)


class EthereumTesterFormatterMiddleware(BaseFormatterMiddleware):
    request_formatters = {
        'eth_getBlockByNumber': apply_formatter_at_index(
            apply_formatter_if(hex_to_integer, is_not_named_block),
            0,
        ),
    }
    result_formatters = {
        'eth_blockNumber': hex,
        'eth_getTransactionCount': hex,
    }
