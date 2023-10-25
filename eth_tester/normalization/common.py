from eth_utils import (
    encode_hex,
    is_hex,
    to_dict,
    to_tuple,
)
from eth_utils.toolz import (
    curry,
)

from eth_tester.utils.encoding import (
    int_to_32byte_big_endian,
)


@curry
@to_dict
def normalize_dict(value, normalizers):
    for key, item in value.items():
        normalizer = normalizers[key]
        yield key, normalizer(item)


@curry
@to_tuple
def normalize_array(value, normalizer):
    """
    Just `map` but it's nice to have it return a consistent type
    (tuple).
    """
    for item in value:
        yield normalizer(item)


@curry
def normalize_if(value, conditional_fn, normalizer):
    if conditional_fn(value):
        return normalizer(value)
    else:
        return value


def to_integer_if_hex(value):
    if is_hex(value):
        return int(value, 16)
    return value


def int_to_32byte_hex(value):
    return encode_hex(int_to_32byte_big_endian(value))
