from __future__ import unicode_literals

from cytoolz.functoolz import (
    compose,
    partial,
)

from eth_utils import (
    int_to_big_endian,
    pad_left,
)


zpad = partial(pad_left, pad_with=b'\x00')
zpad32 = partial(pad_left, to_size=32, pad_with=b'\x00')


int_to_32byte_big_endian = compose(
    zpad32,
    int_to_big_endian,
)
