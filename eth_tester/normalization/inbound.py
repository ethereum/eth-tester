from __future__ import absolute_import

from eth_utils.curried import (
    apply_one_of_formatters,
    decode_hex,
    is_address,
    is_list_like,
    is_hex,
    is_string,
    to_canonical_address,
    to_tuple,
)

from eth_utils.toolz import (
    identity,
    partial,
)

from .common import (
    normalize_array,
    normalize_dict,
    normalize_if,
)

from eth_tester.validation.inbound import (
    is_valid_topic_array,
)


def normalize_topic(topic):
    if topic is None:
        return None
    else:
        return decode_hex(topic)


@to_tuple
def normalize_topic_list(topics):
    for topic in topics:
        yield normalize_topic(topic)


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
        raise TypeError(f"Address is not in a recognized format: {address}")

    if topics is None:
        yield topics
    elif is_valid_topic_array(topics):
        yield tuple(
            normalize_topic_list(item)
            if is_list_like(item) else
            normalize_topic(item)
            for item
            in topics
        )
    else:
        raise TypeError(f"Topics are not in a recognized format: {address}")


def normalize_private_key(value):
    return decode_hex(value)


to_empty_or_canonical_address = apply_one_of_formatters((
    (lambda addr: addr == '', lambda addr: b''),
    (is_hex, to_canonical_address),
))

TRANSACTION_NORMALIZERS = {
    'from': to_canonical_address,
    'to': to_empty_or_canonical_address,
    'gas': identity,
    'gas_price': identity,
    'nonce': identity,
    'value': identity,
    'data': decode_hex,
    'r': identity,
    's': identity,
    'v': identity,
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


def normalize_raw_transaction(raw_transaction_hex):
    return decode_hex(raw_transaction_hex)
