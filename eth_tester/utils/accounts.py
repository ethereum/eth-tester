import rlp

from eth_utils import (
    to_canonical_address,
    keccak,
)


def generate_contract_address(address, nonce):
    return keccak(rlp.encode([to_canonical_address(address), nonce]))[-20:]
