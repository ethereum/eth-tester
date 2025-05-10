from eth_utils import (
    is_integer,
)
from eth_utils.curried import (
    apply_formatter_if,
    apply_one_of_formatters,
    encode_hex,
    is_address,
    is_bytes,
    is_canonical_address,
    is_dict,
    to_checksum_address,
)
from eth_utils.toolz import (
    compose,
    identity,
    partial,
)
from toolz import (
    assoc,
    dissoc,
)

from ..utils.encoding import (
    int_to_32byte_big_endian,
)
from .common import (
    normalize_array,
    normalize_dict,
    normalize_if,
)

normalize_account = to_checksum_address
normalize_account_list = partial(normalize_array, normalizer=normalize_account)

to_empty_or_checksum_address = apply_one_of_formatters(
    (
        (lambda addr: addr == b"", lambda addr: ""),
        (is_canonical_address, to_checksum_address),
    )
)
to_hex_if_integer = apply_formatter_if(is_integer, hex)


def _normalize_outbound_access_list(access_list):
    return tuple(
        [
            {
                "address": to_checksum_address(entry[0]),
                "storageKeys": tuple(
                    [encode_hex(int_to_32byte_big_endian(k)) for k in entry[1]]
                ),
            }
            for entry in access_list
        ]
    )


TRANSACTION_NORMALIZERS = {
    "type": to_hex_if_integer,
    "blobVersionedHashes": partial(
        normalize_array,
        normalizer=partial(
            normalize_if, conditional_fn=is_bytes, normalizer=encode_hex
        ),
    ),
    "chainId": identity,
    "hash": encode_hex,
    "nonce": identity,
    "blockHash": partial(normalize_if, conditional_fn=is_bytes, normalizer=encode_hex),
    "blockNumber": identity,
    "transactionIndex": identity,
    "from": to_checksum_address,
    "to": to_empty_or_checksum_address,
    "value": identity,
    "gas": identity,
    "gasPrice": identity,
    "maxFeePerBlobGas": identity,
    "maxFeePerGas": identity,
    "maxPriorityFeePerGas": identity,
    "data": encode_hex,
    "accessList": _normalize_outbound_access_list,
    "r": identity,
    "s": identity,
    "v": identity,
    "yParity": identity,
}
normalize_transaction = partial(normalize_dict, normalizers=TRANSACTION_NORMALIZERS)


WITHDRAWAL_NORMALIZERS = {
    "index": identity,
    "validatorIndex": identity,
    "address": to_checksum_address,
    "amount": identity,
}
normalize_withdrawal = partial(normalize_dict, normalizers=WITHDRAWAL_NORMALIZERS)


def is_transaction_hash_list(value):
    return all(is_bytes(item) for item in value)


def is_transaction_object_list(value):
    return all(is_dict(item) for item in value)


def _remove_fork_specific_fields_if_none(block):
    """
    A `None` value is set for keys if they are not present during outbound block
    validation. This means we are in a VM that has not yet been exposed to this new
    field. Pop this value out here to normalize these older VM blocks.
    """
    for key, value in list(block.items()):
        if value is None:
            block = dissoc(block, key)
    return block


BLOCK_NORMALIZERS = {
    "number": identity,
    "hash": encode_hex,
    "parentHash": encode_hex,
    "nonce": encode_hex,
    "baseFeePerGas": identity,
    "sha3Uncles": encode_hex,
    "logsBloom": identity,
    "transactionsRoot": encode_hex,
    "receiptsRoot": encode_hex,
    "stateRoot": encode_hex,
    "coinbase": to_checksum_address,
    "difficulty": identity,
    "mixHash": encode_hex,
    "totalDifficulty": identity,
    "size": identity,
    "extraData": encode_hex,
    "gasLimit": identity,
    "gasUsed": identity,
    "timestamp": identity,
    "transactions": compose(
        partial(
            normalize_if,
            conditional_fn=is_transaction_hash_list,
            normalizer=partial(normalize_array, normalizer=encode_hex),
        ),
        partial(
            normalize_if,
            conditional_fn=is_transaction_object_list,
            normalizer=partial(normalize_array, normalizer=normalize_transaction),
        ),
    ),
    "uncles": partial(normalize_array, normalizer=encode_hex),
    "withdrawals": partial(normalize_array, normalizer=normalize_withdrawal),
    "withdrawalsRoot": encode_hex,
    "parentBeaconBlockRoot": encode_hex,
    "blobGasUsed": identity,
    "excessBlobGas": identity,
}
normalize_block = compose(
    partial(normalize_dict, normalizers=BLOCK_NORMALIZERS),
    _remove_fork_specific_fields_if_none,
)


LOG_ENTRY_NORMALIZERS = {
    "type": identity,
    "logIndex": identity,
    "transactionIndex": partial(
        normalize_if,
        conditional_fn=is_bytes,
        normalizer=encode_hex,
    ),
    "transactionHash": encode_hex,
    "blockHash": partial(
        normalize_if,
        conditional_fn=is_bytes,
        normalizer=encode_hex,
    ),
    "blockNumber": identity,
    "address": to_checksum_address,
    "data": encode_hex,
    "topics": partial(normalize_array, normalizer=encode_hex),
}
normalize_log_entry = partial(normalize_dict, normalizers=LOG_ENTRY_NORMALIZERS)


def _normalize_contract_address(receipt):
    if receipt["status"] == 0:
        return assoc(receipt, "contractAddress", None)
    elif is_address(receipt["contractAddress"]):
        return assoc(
            receipt,
            "contractAddress",
            to_checksum_address(receipt["contractAddress"]),
        )
    else:
        return receipt


RECEIPT_NORMALIZERS = {
    "transactionHash": encode_hex,
    "transactionIndex": identity,
    "blockNumber": identity,
    "blockHash": partial(
        normalize_if,
        conditional_fn=is_bytes,
        normalizer=encode_hex,
    ),
    "cumulativeGasUsed": identity,
    "effectiveGasPrice": identity,
    "from": to_checksum_address,
    "gasUsed": identity,
    "contractAddress": identity,  # special case, see ``_normalize_contract_address()``
    "logs": partial(normalize_array, normalizer=normalize_log_entry),
    "stateRoot": identity,
    "status": identity,
    "to": to_empty_or_checksum_address,
    "type": to_hex_if_integer,
    "baseFeePerGas": identity,
    "blobGasUsed": identity,
    "blobGasPrice": identity,
}
normalize_receipt = compose(
    partial(normalize_dict, normalizers=RECEIPT_NORMALIZERS),
    _normalize_contract_address,
)
