from __future__ import (
    unicode_literals,
)

from eth_utils import (
    is_bytes,
    is_canonical_address,
    is_integer,
    is_list_like,
)
from eth_utils.toolz import (
    compose,
    merge,
    partial,
)
from toolz import (
    identity,
)

from eth_tester.constants import (
    UINT256_MAX,
    UINT2048_MAX,
)
from eth_tester.exceptions import (
    ValidationError,
)

from .common import (
    if_not_create_address,
    if_not_null,
    validate_any,
    validate_array,
    validate_bytes,
    validate_dict,
    validate_positive_integer,
    validate_transaction_type,
    validate_uint64,
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
            "Must be of length 8.  Got: {} of length {}".format(value, len(value))
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
        raise ValidationError(
            "The `v` portion of the signature must be 0, 1, 27, 28 or >= 35"
        )


def validate_y_parity(value):
    validate_positive_integer(value)
    if value not in (0, 1):
        raise ValidationError(
            "The 'v' portion (y_parity) of the signature must be either 0 or 1 for "
            "typed transactions."
        )


def _validate_outbound_access_list(access_list):
    if not is_list_like(access_list):
        raise ValidationError("access_list is not list-like.")
    for entry in access_list:
        if not is_list_like(entry) and len(entry) != 2:
            raise ValidationError(f"access_list entry not properly formatted: {entry}")
        address = entry[0]
        storage_keys = entry[1]
        if not (is_bytes(address) and len(address) == 20):
            raise ValidationError(
                f"access_list address not properly formatted: {address}"
            )
        if not is_list_like(storage_keys):
            raise ValidationError(
                f"access_list storage keys are not list-like: {storage_keys}"
            )
        if len(storage_keys) > 0 and (not all(is_integer(k) for k in storage_keys)):
            raise ValidationError(
                "one or more access list storage keys not formatted "
                f"properly: {storage_keys}"
            )


LEGACY_TRANSACTION_VALIDATORS = {
    "type": validate_transaction_type,
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
validate_legacy_transaction = partial(
    validate_dict, key_validators=LEGACY_TRANSACTION_VALIDATORS
)


ACCESS_LIST_TRANSACTION_VALIDATORS = merge(
    LEGACY_TRANSACTION_VALIDATORS,
    {
        "v": validate_y_parity,
        "chain_id": validate_uint256,
        "access_list": _validate_outbound_access_list,
    },
)
validate_access_list_transaction = partial(
    validate_dict, key_validators=ACCESS_LIST_TRANSACTION_VALIDATORS
)


DYNAMIC_FEE_TRANSACTION_VALIDATORS = merge(
    ACCESS_LIST_TRANSACTION_VALIDATORS,
    {
        "max_fee_per_gas": validate_uint256,
        "max_priority_fee_per_gas": validate_uint256,
    },
)
validate_dynamic_fee_transaction = partial(
    validate_dict, key_validators=DYNAMIC_FEE_TRANSACTION_VALIDATORS
)


validate_transaction = partial(
    validate_any,
    validators=(
        partial(validate_dict, key_validators=LEGACY_TRANSACTION_VALIDATORS),
        partial(validate_dict, key_validators=ACCESS_LIST_TRANSACTION_VALIDATORS),
        partial(validate_dict, key_validators=DYNAMIC_FEE_TRANSACTION_VALIDATORS),
    ),
)


WITHDRAWAL_VALIDATORS = {
    "index": validate_uint64,
    "validator_index": validate_uint64,
    "address": validate_canonical_address,
    "amount": validate_uint64,
}
validate_withdrawal = partial(validate_dict, key_validators=WITHDRAWAL_VALIDATORS)


def validate_status(value):
    validate_positive_integer(value)
    if value > 1:
        raise ValidationError(f"Invalid status value '{value}', only 0 or 1 allowed.")


RECEIPT_VALIDATORS = {
    "transaction_hash": validate_32_byte_string,
    "transaction_index": if_not_null(validate_positive_integer),
    "block_number": if_not_null(validate_positive_integer),
    "block_hash": if_not_null(validate_32_byte_string),
    "cumulative_gas_used": validate_positive_integer,
    "effective_gas_price": if_not_null(validate_positive_integer),
    "from": validate_canonical_address,
    "gas_used": validate_positive_integer,
    "contract_address": if_not_null(validate_canonical_address),
    "logs": partial(validate_array, validator=validate_log_entry),
    "state_root": validate_bytes,
    "status": validate_status,
    "to": if_not_create_address(validate_canonical_address),
    "type": validate_transaction_type,
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
    "coinbase": validate_canonical_address,
    "difficulty": validate_positive_integer,
    "mix_hash": validate_32_byte_string,
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
            partial(validate_array, validator=validate_legacy_transaction),
            partial(validate_array, validator=validate_access_list_transaction),
            partial(validate_array, validator=validate_dynamic_fee_transaction),
        ),
    ),
    "uncles": partial(validate_array, validator=validate_32_byte_string),
    # fork-specific fields, validated separately in `_validate_fork_specific_fields()`
    "base_fee_per_gas": identity,
    "withdrawals": identity,
    "withdrawals_root": identity,
}


def _validate_fork_specific_fields(block):
    """
    If a fork-specific key is present, validate the value appropriately. For
    blocks that are missing this key (before it was introduced via a fork), set the
    value to `None` during validation and pop it back out during normalization.
    """
    # London fork
    if "base_fee_per_gas" not in block:
        block["base_fee_per_gas"] = None
    else:
        validate_positive_integer(block["base_fee_per_gas"])

    # Shanghai fork
    if all(_ not in block for _ in ("withdrawals", "withdrawals_root")):
        block["withdrawals"] = None
        block["withdrawals_root"] = None
    else:
        partial(validate_array, validator=validate_withdrawal)(block["withdrawals"])
        validate_32_byte_string(block["withdrawals_root"])

    return block


validate_block = compose(
    partial(validate_dict, key_validators=BLOCK_VALIDATORS),
    _validate_fork_specific_fields,
)


validate_accounts = partial(validate_array, validator=validate_canonical_address)
