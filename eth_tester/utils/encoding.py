from __future__ import unicode_literals

from cytoolz.functoolz import (
    compose,
    curry,
)

from eth_utils import (
    int_to_big_endian,
)


@curry
def zpad(value, length):
    return value.rjust(length, b'\x00')


zpad32 = zpad(length=32)


int_to_32byte_big_endian = compose(
    zpad32,
    int_to_big_endian,
)
