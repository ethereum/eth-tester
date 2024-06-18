from eth_account.hdaccount import (
    HDPath,
    seed_from_mnemonic,
)
from eth_keys import (
    KeyAPI,
    keys,
)
from eth_utils import (
    int_to_big_endian,
    to_tuple,
)


def private_key_to_address(private_key):
    return keys.PrivateKey(private_key).public_key.to_canonical_address()


@to_tuple
def get_default_account_keys(quantity=None):
    keys = KeyAPI()
    quantity = quantity or 10
    for i in range(1, quantity + 1):
        pk_bytes = int_to_big_endian(i).rjust(32, b"\x00")
        private_key = keys.PrivateKey(pk_bytes)
        yield private_key


@to_tuple
def get_account_keys_from_mnemonic(mnemonic, quantity=None, hd_path=None):
    keys = KeyAPI()
    seed = seed_from_mnemonic(mnemonic, "")
    quantity = quantity or 10

    if hd_path is None:
        # default HD path
        hd_path = "m/44'/60'/0'"

    for i in range(0, quantity):
        # create unique HDPath to derive the private key for each account
        key = HDPath(f"{hd_path}/{i}").derive(seed)
        private_key = keys.PrivateKey(key)
        yield private_key
