from typing import (
    Any,
    Dict,
)

from eth_account.typed_transactions import (
    BlobTransaction,
)

from .utils import (
    eels_is_available,
)

if eels_is_available():
    from ethereum_types.bytes import (
        Bytes32,
    )
    from ethereum_types.numeric import (
        U64,
        U256,
        Uint,
    )
else:
    U64 = None
    U256 = None
    Bytes32 = None
    Uint = None

from hexbytes import (
    HexBytes,
)

from eth_tester.utils.casing import (
    lower_camel_case_to_snake_case,
    snake_case_to_lower_camel_case,
)


def eels_normalize_transaction(transaction: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {}
    for key, value in transaction.items():
        if key == "gas":
            key = "gas_limit"
            value = hex(value)
        elif isinstance(value, bytes):
            value = value.hex()
        elif isinstance(value, int):
            value = hex(value)
        elif key == "access_list":
            # turn back to dict
            value = [
                {
                    "address": entry[0].hex(),
                    "storageKeys": [hex(key) for key in entry[1]],
                }
                for entry in value
            ]

        if key in ("y_parity",):
            # for some reason, y_parity is not camelCased :/
            normalized[key] = value
        else:
            normalized[snake_case_to_lower_camel_case(key)] = value

    return normalized


def eels_normalize_inbound_raw_blob_transaction(
    backend_instance, raw_transaction: bytes
) -> Dict[str, Any]:
    blob_tx = BlobTransaction.from_bytes(HexBytes(raw_transaction))
    tx_dict = {
        lower_camel_case_to_snake_case(key): value
        for key, value in blob_tx.as_dict().items()
    }
    tx_dict.pop("type")

    # convert to expected EELS types for encoding
    """
    chain_id: U64
    nonce: U256
    max_priority_fee_per_gas: Uint
    max_fee_per_gas: Uint
    gas: Uint
    to: Address
    value: U256
    data: Bytes
    access_list: Tuple[Tuple[Address, Tuple[Bytes32, ...]], ...]
    max_fee_per_blob_gas: U256
    blob_versioned_hashes: Tuple[VersionedHash, ...]
    y_parity: U256
    r: U256
    s: U256
    """
    tx_dict["chain_id"] = U64(tx_dict.pop("chain_id"))
    tx_dict["nonce"] = U256(tx_dict.pop("nonce"))
    tx_dict["max_priority_fee_per_gas"] = Uint(tx_dict.pop("max_priority_fee_per_gas"))
    tx_dict["max_fee_per_gas"] = Uint(tx_dict.pop("max_fee_per_gas"))
    tx_dict["gas"] = Uint(tx_dict.pop("gas"))
    tx_dict["to"] = backend_instance._fork_types.Address(tx_dict.pop("to"))
    tx_dict["value"] = U256(tx_dict.pop("value"))
    tx_dict["data"] = tx_dict.pop("data")
    # here
    tx_dict["access_list"] = (
        (
            backend_instance._fork_types.Address(address),
            tuple(Bytes32(hash) for hash in hashes),
        )
        for address, hashes in tx_dict.pop("access_list")
    )
    tx_dict["max_fee_per_blob_gas"] = U256(tx_dict.pop("max_fee_per_blob_gas"))
    tx_dict["y_parity"] = U256(tx_dict.pop("v"))
    tx_dict["r"] = U256(tx_dict.pop("r"))
    tx_dict["s"] = U256(tx_dict.pop("s"))
    return tx_dict
