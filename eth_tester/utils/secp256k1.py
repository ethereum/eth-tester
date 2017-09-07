"""
Functions lifted from https://github.com/vbuterin/pybitcointools
"""
from eth_utils import (
    big_endian_to_int,
    int_to_big_endian,
    is_bytes,
    pad_left,
)

from eth_tester.constants import (
    SECPK1_G,
    SECPK1_N,
)

from .jacobian import (
    fast_multiply,
)


def _pad32(value):
    return pad_left(value, 32, b'\x00')


def _encode_raw_public_key(raw_public_key):
    left, right = raw_public_key
    return b''.join((
        _pad32(int_to_big_endian(left)),
        _pad32(int_to_big_endian(right)),
    ))


def private_key_to_public_key(private_key):
    if not is_bytes(private_key) or len(private_key) != 32:
        raise TypeError("`private_key` must be of type `bytes` and of lenght 32")
    private_key_as_num = big_endian_to_int(private_key)

    if private_key_as_num >= SECPK1_N:
        raise Exception("Invalid privkey")

    raw_public_key = fast_multiply(SECPK1_G, private_key_as_num)
    public_key = _encode_raw_public_key(raw_public_key)
    return public_key
