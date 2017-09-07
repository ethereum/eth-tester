import rlp

from eth_utils import (
    to_canonical_address,
    keccak,
)

from .secp256k1 import (
    private_key_to_public_key,
)


def generate_contract_address(address, nonce):
    return keccak(rlp.encode([to_canonical_address(address), nonce]))[-20:]


def private_key_to_address(private_key):
    public_key = private_key_to_public_key(private_key)

    account = keccak(public_key)[12:]
    return account
