from eth_utils import (
    encode_hex,
    is_hex,
    to_dict,
    to_list,
)
from eth_utils.toolz import (
    curry,
)

from eth_tester.utils.encoding import (
    int_to_32byte_big_endian,
)


def to_lower_camel_case(value: str) -> str:
    """
    Convert a string to lower camel case.
    """
    return "".join(
        word.capitalize() if i else word for i, word in enumerate(value.split("_"))
    )


@curry
@to_dict
def normalize_dict_keys_recursive(value):
    """
    Normalize the keys of a dictionary using the provided normalizer.
    """
    for key, item in value.items():
        if isinstance(item, dict):
            # Recursively normalize nested dictionary keys
            yield normalize_dict_keys_recursive(item)
        elif isinstance(item, (list, tuple)):
            # Recursively normalize nested list items
            # and normalize the keys of dictionaries within the list
            checked_items = []
            for sub_item in item:
                if not isinstance(sub_item, dict):
                    checked_items.append(sub_item)
                else:
                    checked_items.append(normalize_dict_keys_recursive(sub_item))
            yield to_lower_camel_case(key), tuple(checked_items)
        else:
            yield to_lower_camel_case(key), item


@curry
@to_dict
def normalize_dict(value, normalizers):
    for key, item in value.items():
        normalizer = normalizers[key]
        yield key, normalizer(item)


@curry
@to_list
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
