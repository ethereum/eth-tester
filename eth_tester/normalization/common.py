from eth_utils import (
    to_dict,
    to_tuple,
)


@to_dict
def normalize_dict(value, normalizers):
    for key, item in value.items():
        normalizer = normalizers[key]
        yield key, normalizer(item)


@to_tuple
def normalize_array(value, normalizer):
    """
    This is just `map` but it's nice to have it return a consisten type
    (tuple).
    """
    for item in value:
        yield normalizer(item)


def normalize_if(value, conditional_fn, normalizer):
    if conditional_fn(value):
        return normalizer(value)
    else:
        return value
