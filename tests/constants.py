"""Constants used in the validation tests."""

from eth_utils import (
    encode_hex,
)

ZERO_32BYTES = b"\x00" * 32
ZERO_8BYTES = b"\x00" * 8
ZERO_ADDRESS = b"\x00" * 20


ADDRESS_A = b"\x00" * 19 + b"\x01"
TOPIC_A = b"\x00" * 31 + b"\x01"
TOPIC_B = b"\x00" * 31 + b"\x02"
HASH32_AS_TEXT = "\x00" * 32
HASH31 = b"\x00" * 31

DEFAULT_GAS_LIMIT = 21000

ADDRESS_A_HEX = encode_hex(b"\x00" * 19 + b"\x01")
ADDRESS_B_HEX = encode_hex(b"\x00" * 19 + b"\x02")
TOPIC_A_HEX = encode_hex(b"\x00" * 31 + b"\x01")
TOPIC_B_HEX = encode_hex(b"\x00" * 31 + b"\x02")
TOPIC_C_HEX = encode_hex(b"\x00" * 30 + b"\x01")
TOPIC_D_HEX = encode_hex(b"\x00" * 32 + b"\x01")
