import rlp

from eth_utils import (
    keccak,
    to_canonical_address,
)


def generate_contract_address(address, nonce):
    next_account_hash = keccak(rlp.encode([address, nonce]))
    return to_canonical_address(next_account_hash[-20:])
