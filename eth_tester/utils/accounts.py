from eth_keys import (
    keys,
)


def private_key_to_address(private_key):
    return keys.PrivateKey(private_key).public_key.to_canonical_address()
