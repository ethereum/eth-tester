from __future__ import absolute_import

from cytoolz.functoolz import (
    identity,
    partial,
)

from eth_utils import (
    is_address,
    is_list_like,
    is_text,
    is_hex,
    to_tuple,
    decode_hex,
    to_canonical_address,
    remove_0x_prefix,
)

from .common import (
    normalize_dict,
)


def is_32byte_hex_string(value):
    return is_text(value) and is_hex(value) and len(remove_0x_prefix(value)) == 64


def _is_flat_topic_array(value):
    if not is_list_like(value):
        return False
    return all(is_32byte_hex_string(item) for item in value)


@to_tuple
def normalize_filter_params(from_block, to_block, address, topics):
    yield from_block
    yield to_block

    if address is None:
        yield address
    elif is_address(address):
        yield to_canonical_address(address)
    elif is_list_like(address):
        yield tuple(
            to_canonical_address(item)
            for item
            in address
        )
    else:
        raise TypeError("Address is not in a recognized format: {0}".format(address))

    if topics is None:
        yield topics
    elif _is_flat_topic_array(topics):
        yield tuple(
            decode_hex(item)
            for item
            in topics
        )
    elif all(_is_flat_topic_array(item) for item in topics):
        yield tuple(
            tuple(decode_hex(sub_item) for sub_item in item)
            for item
            in topics
        )
    else:
        raise TypeError("Topics are not in a recognized format: {0}".format(address))


TRANSACTION_NORMALIZERS = {
    'from': to_canonical_address,
    'to': to_canonical_address,
    'gas': identity,
    'gas_price': identity,
    'value': identity,
    'data': decode_hex,
}


normalize_transaction = partial(normalize_dict, normalizers=TRANSACTION_NORMALIZERS)
