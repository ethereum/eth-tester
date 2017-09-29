import rlp

from eth_utils import (
    keccak,
)


def generate_contract_address(address, nonce):
    return keccak(rlp.encode([address, nonce]))[-20:]
