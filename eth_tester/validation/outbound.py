from __future__ import unicode_literals

from eth_utils import (
    is_canonical_address,
)

from eth_utils.toolz import (
    partial,
)

from eth_tester.constants import (
    UINT256_MAX,
    UINT2048_MAX,
)
from eth_tester.exceptions import (
    ValidationError,
)

from .common import (
    if_not_null,
    if_not_create_address,
    validate_any,
    validate_array,
    validate_bytes,
    validate_positive_integer,
    validate_dict,
    validate_uint256,
)


def validate_32_byte_string(value):
    validate_bytes(value)
    if len(value) != 32:
        raise ValidationError(
            "Must be of length 32.  Got: {} of length {}".format(value, len(value))
        )


validate_block_hash = validate_32_byte_string


def validate_nonce(value):
    validate_bytes(value)
    if len(value) != 8:
        raise ValidationError(
            "Must be of length 8.  Got: {} of lenght {}".format(value, len(value))
        )


def validate_logs_bloom(value):
    validate_positive_integer(value)
    if value > UINT2048_MAX:
        raise ValidationError(f"Value exceeds 2048 bit integer size: {value}")


def validate_canonical_address(value):
    validate_bytes(value)
    if not is_canonical_address(value):
        raise ValidationError("Value must be a 20 byte string")


def validate_log_entry_type(value):
    if value not in {"pending", "mined"}:
        raise ValidationError("Log entry type must be one of 'pending' or 'mined'")


LOG_ENTRY_VALIDATORS = {
    "type": validate_log_entry_type,
    "log_index": validate_positive_integer,
    "transaction_index": if_not_null(validate_positive_integer),
    "transaction_hash": validate_32_byte_string,
    "block_hash": if_not_null(validate_32_byte_string),
    "block_number": if_not_null(validate_positive_integer),
    "address": validate_canonical_address,
    "data": validate_bytes,
    "topics": partial(validate_array, validator=validate_32_byte_string),
}


validate_log_entry = partial(validate_dict, key_validators=LOG_ENTRY_VALIDATORS)


def validate_signature_v(value):
    validate_positive_integer(value)

    if value not in [0, 1, 27, 28] and value not in range(35, UINT256_MAX + 1):
        raise ValidationError("The `v` portion of the signature must be 0, 1, 27, 28 or >= 35")


TRANSACTION_VALIDATORS = {
    "hash": validate_32_byte_string,
    "nonce": validate_uint256,
    "block_hash": if_not_null(validate_32_byte_string),
    "block_number": if_not_null(validate_positive_integer),
    "transaction_index": if_not_null(validate_positive_integer),
    "from": validate_canonical_address,
    "to": if_not_create_address(validate_canonical_address),
    "value": validate_uint256,
    "gas": validate_uint256,
    "gas_price": validate_uint256,
    "data": validate_bytes,
    "v": validate_signature_v,
    "r": validate_uint256,
    "s": validate_uint256,
}


validate_transaction = partial(validate_dict, key_validators=TRANSACTION_VALIDATORS)


RECEIPT_VALIDATORS = {
    "transaction_hash": validate_32_byte_string,
    "transaction_index": if_not_null(validate_positive_integer),
    "block_number": if_not_null(validate_positive_integer),
    "block_hash": if_not_null(validate_32_byte_string),
    "cumulative_gas_used": validate_positive_integer,
    "gas_used": validate_positive_integer,
    "contract_address": if_not_null(validate_canonical_address),
    "logs": partial(validate_array, validator=validate_log_entry),
    "state_root": validate_bytes,
}


validate_receipt = partial(validate_dict, key_validators=RECEIPT_VALIDATORS)


BLOCK_VALIDATORS = {
    "number": validate_positive_integer,
    "hash": validate_block_hash,
    "parent_hash": validate_block_hash,
    "nonce": validate_nonce,
    "sha3_uncles": validate_32_byte_string,
    "logs_bloom": validate_logs_bloom,
    "transactions_root": validate_32_byte_string,
    "receipts_root": validate_32_byte_string,
    "state_root": validate_32_byte_string,
    "miner": validate_canonical_address,
    "difficulty": validate_positive_integer,
    "total_difficulty": validate_positive_integer,
    "size": validate_positive_integer,
    "extra_data": validate_32_byte_string,
    "gas_limit": validate_positive_integer,
    "gas_used": validate_positive_integer,
    "timestamp": validate_positive_integer,
    "transactions": partial(
        validate_any,
        validators=(
            partial(validate_array, validator=validate_32_byte_string),
            partial(validate_array, validator=validate_transaction),
        ),
    ),
    "uncles": partial(validate_array, validator=validate_32_byte_string),
}


validate_block = partial(validate_dict, key_validators=BLOCK_VALIDATORS)


validate_accounts = partial(validate_array, validator=validate_canonical_address)
