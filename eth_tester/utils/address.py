import rlp

from eth_utils import (
    keccak,
    to_canonical_address,
)


def generate_contract_address(address, nonce):
    return to_canonical_address(keccak(rlp.encode([address, nonce]))[-20:])
