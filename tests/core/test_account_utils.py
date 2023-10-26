from eth_utils import (
    decode_hex,
)
import pytest

from eth_tester.utils.accounts import (
    private_key_to_address,
)

PK_A = decode_hex("0x58d23b55bc9cdce1f18c2500f40ff4ab7245df9a89505e9b1fa4851f623d241d")
PK_A_ADDRESS = decode_hex("0xdc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd")


@pytest.mark.parametrize(
    "private_key,expected",
    ((PK_A, PK_A_ADDRESS),),
)
def test_private_key_to_address(private_key, expected):
    actual = private_key_to_address(private_key)
    assert actual == expected
