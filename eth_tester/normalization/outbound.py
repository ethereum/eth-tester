from __future__ import absolute_import

from toolz import assoc, curry

from eth_utils.curried import (
    apply_formatters_to_dict,
    apply_one_of_formatters,
    to_checksum_address,
    encode_hex,
    is_address,
    is_bytes,
    is_canonical_address,
    is_dict,
)

from eth_utils.toolz import (
    compose,
    identity,
    partial,
)

from .common import (
    normalize_if,
    normalize_dict,
    normalize_array,
)
from ..utils.encoding import int_to_32byte_big_endian


normalize_account = to_checksum_address
normalize_account_list = partial(normalize_array, normalizer=normalize_account)

to_empty_or_checksum_address = apply_one_of_formatters((
    (lambda addr: addr == b'', lambda addr: ''),
    (is_canonical_address, to_checksum_address),
))


@curry
def fill_gas_price_if_dynamic_fee_transaction(txn_dict):
    if all(_ in txn_dict for _ in ('max_fee_per_gas', 'max_priority_fee_per_gas')):
        return assoc(txn_dict, 'gas_price', txn_dict.get('max_fee_per_gas'))
    else:
        return txn_dict


def _normalize_outbound_access_list(access_list):
    return tuple([
        {
            'address': to_checksum_address(entry[0]),
            'storage_keys': tuple(
                [encode_hex(int_to_32byte_big_endian(k)) for k in entry[1]]
            )
        }
        for entry in access_list
    ])


TRANSACTION_NORMALIZERS = {
    "chain_id": identity,
    "hash": encode_hex,
    "nonce": identity,
    "block_hash": partial(normalize_if, conditional_fn=is_bytes, normalizer=encode_hex),
    "block_number": identity,
    "transaction_index": identity,
    "from": to_checksum_address,
    "to": to_empty_or_checksum_address,
    "value": identity,
    "gas": identity,
    "gas_price": identity,
    "max_fee_per_gas": identity,
    "max_priority_fee_per_gas": identity,
    "data": encode_hex,
    "access_list": _normalize_outbound_access_list,
    "r": identity,
    "s": identity,
    "v": identity,
    "y_parity": identity,
}
normalize_transaction = compose(
    # TODO: At some point (the merge?), the inclusion of gas_price==max_fee_per_gas will be removed
    #  from dynamic fee transactions and we can get rid of this behavior.
    #  https://github.com/ethereum/execution-specs/pull/251
    fill_gas_price_if_dynamic_fee_transaction,
    apply_formatters_to_dict(TRANSACTION_NORMALIZERS),
)


def is_transaction_hash_list(value):
    return all(is_bytes(item) for item in value)


def is_transaction_object_list(value):
    return all(is_dict(item) for item in value)


BLOCK_NORMALIZERS = {
    "number": identity,
    "hash": encode_hex,
    "parent_hash": encode_hex,
    "nonce": encode_hex,
    "base_fee_per_gas": identity,
    "sha3_uncles": encode_hex,
    "logs_bloom": identity,
    "transactions_root": encode_hex,
    "receipts_root": encode_hex,
    "state_root": encode_hex,
    "miner": to_checksum_address,
    "difficulty": identity,
    "total_difficulty": identity,
    "size": identity,
    "extra_data": encode_hex,
    "gas_limit": identity,
    "gas_used": identity,
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
}


normalize_block = partial(normalize_dict, normalizers=BLOCK_NORMALIZERS)


LOG_ENTRY_NORMALIZERS = {
    "type": identity,
    "log_index": identity,
    "transaction_index": partial(
        normalize_if,
        conditional_fn=is_bytes,
        normalizer=encode_hex,
    ),
    "transaction_hash": encode_hex,
    "block_hash": partial(
        normalize_if,
        conditional_fn=is_bytes,
        normalizer=encode_hex,
    ),
    "block_number": identity,
    "address": to_checksum_address,
    "data": encode_hex,
    "topics": partial(normalize_array, normalizer=encode_hex),
}


normalize_log_entry = partial(normalize_dict, normalizers=LOG_ENTRY_NORMALIZERS)


RECEIPT_NORMALIZERS = {
    "transaction_hash": encode_hex,
    "transaction_index": identity,
    "block_number": identity,
    "block_hash": partial(
        normalize_if,
        conditional_fn=is_bytes,
        normalizer=encode_hex,
    ),
    "cumulative_gas_used": identity,
    "gas_used": identity,
    "contract_address": partial(
        normalize_if,
        conditional_fn=is_address,
        normalizer=to_checksum_address,
    ),
    "logs": partial(normalize_array, normalizer=normalize_log_entry),
    "state_root": identity,
}


normalize_receipt = partial(normalize_dict, normalizers=RECEIPT_NORMALIZERS)
