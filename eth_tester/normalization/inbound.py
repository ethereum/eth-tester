from __future__ import absolute_import

from cytoolz.functoolz import (
    identity,
    partial,
)

from eth_utils import (
    decode_hex,
    is_address,
    is_hex,
    is_list_like,
    is_string,
    is_text,
    remove_0x_prefix,
    to_canonical_address,
    to_tuple,
)

from .common import (
    normalize_array,
    normalize_dict,
    normalize_if,
)

from eth_tester.validation.inbound import (
    is_flat_topic_array,
)


def is_32byte_hex_string(value):
    return is_text(value) and is_hex(value) and len(remove_0x_prefix(value)) == 64


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
    elif is_flat_topic_array(topics):
        yield tuple(
            decode_hex(item)
            for item
            in topics
        )
    elif all(is_flat_topic_array(item) for item in topics):
        yield tuple(
            tuple(decode_hex(sub_item) for sub_item in item)
            for item
            in topics
        )
    else:
        raise TypeError("Topics are not in a recognized format: {0}".format(address))


def normalize_private_key(value):
    return decode_hex(value)


TRANSACTION_NORMALIZERS = {
    'from': to_canonical_address,
    'to': to_canonical_address,
    'gas': identity,
    'gas_price': identity,
    'value': identity,
    'data': decode_hex,
}


normalize_transaction = partial(normalize_dict, normalizers=TRANSACTION_NORMALIZERS)


LOG_ENTRY_NORMALIZERS = {
    'type': identity,
    'log_index': identity,
    'transaction_index': identity,
    'transaction_hash': decode_hex,
    'block_hash': partial(normalize_if, conditional_fn=is_string, normalizer=decode_hex),
    'block_number': identity,
    'address': to_canonical_address,
    'data': decode_hex,
    'topics': partial(normalize_array, normalizer=decode_hex),
}


normalize_log_entry = partial(normalize_dict, normalizers=LOG_ENTRY_NORMALIZERS)
