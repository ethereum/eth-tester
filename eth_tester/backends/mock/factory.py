import functools
import time

from eth_typing import (
    Hash32,
)
from eth_utils import (
    apply_to_return_value,
    is_bytes,
    is_dict,
    is_integer,
    is_list_like,
    is_null,
    is_text,
    keccak,
    to_bytes,
    to_dict,
    to_tuple,
)
from eth_utils.toolz import (
    assoc,
)

from eth_tester.backends.common import (
    merge_genesis_overrides,
)
from eth_tester.backends.mock.common import (
    calculate_effective_gas_price,
)
from eth_tester.constants import (
    DYNAMIC_FEE_TRANSACTION_PARAMS,
)
from eth_tester.utils.address import (
    generate_contract_address,
)
from eth_tester.utils.transactions import (
    extract_transaction_type,
)

ZERO_32BYTES = b"\x00" * 32
ZERO_8BYTES = b"\x00" * 8
ZERO_ADDRESS = b"\x00" * 20
BLOCK_ELASTICITY_MULTIPLIER = 2
BASE_FEE_MAX_CHANGE_DENOMINATOR = 8


@apply_to_return_value(b"|".join)
@to_tuple
def bytes_repr(value):
    if is_bytes(value):
        yield value
    elif is_text(value):
        yield to_bytes(text=value)
    elif is_list_like(value):
        yield b"".join(
            (
                b"(",
                b",".join(bytes_repr(item) for item in value),
                b")",
            )
        )
    elif is_dict(value):
        yield b"".join(
            (
                b"{",
                b",".join(
                    (
                        b":".join((bytes_repr(key), bytes_repr(item)))
                        for key, item in value.items()
                    )
                ),
                b"}",
            )
        )
    elif is_integer(value):
        yield to_bytes(value)
    elif is_null(value):
        yield f"None@{id(value)}"
    else:
        raise TypeError(f"Unsupported type for bytes_repr: {type(value)}")


def fake_rlp_hash(value):
    return keccak(bytes_repr(value))


def add_hash(fn):
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        value = fn(*args, **kwargs)
        if "hash" in value:
            return value
        else:
            return assoc(value, "hash", keccak(bytes_repr(value)))

    return inner


def create_transaction(
    transaction, block, transaction_index, is_pending, overrides=None
):
    filled_txn = _fill_transaction(
        transaction, block, transaction_index, is_pending, overrides
    )
    if "hash" in filled_txn:
        return filled_txn
    else:
        return assoc(filled_txn, "hash", fake_rlp_hash(filled_txn))


@to_dict
def _fill_transaction(
    transaction, block, transaction_index, is_pending, overrides=None
):
    is_dynamic_fee_transaction = any(
        _ in transaction for _ in DYNAMIC_FEE_TRANSACTION_PARAMS
    ) or not any(
        _ in transaction for _ in DYNAMIC_FEE_TRANSACTION_PARAMS + ("gas_price",)
    )

    if overrides is None:
        overrides = {}

    if "hash" in overrides:  # else calculate hash after all fields are filled
        yield "hash", overrides["hash"]

    # Here, we yield the key with the overrides value if it exists, else either
    # the transaction value if it exists or a default value
    yield "nonce", overrides.get("nonce", 0)
    yield "from", overrides.get("from", transaction.get("from"))
    yield "to", overrides.get("to", transaction.get("to", b""))
    yield "data", overrides.get("data", transaction.get("data", b""))
    yield "value", overrides.get("value", transaction.get("value", 0))
    yield "gas", overrides.get("gas", transaction.get("gas"))
    yield "r", overrides.get("r", transaction.get("r", 12345))
    yield "s", overrides.get("s", transaction.get("s", 67890))
    yield "v", overrides.get("v", transaction.get("v", 0))

    if is_dynamic_fee_transaction:
        # dynamic fee transaction (type = 2)
        yield "max_fee_per_gas", overrides.get(
            "max_fee_per_gas", transaction.get("max_fee_per_gas", 1000000000)
        )
        yield "max_priority_fee_per_gas", overrides.get(
            "max_priority_fee_per_gas",
            transaction.get("max_priority_fee_per_gas", 1000000000),
        )
        yield from _yield_typed_transaction_fields(overrides, transaction)

    else:
        yield "gas_price", overrides.get("gas_price", transaction.get("gas_price"))
        if "access_list" in transaction:
            # access list transaction (type = 1)
            yield from _yield_typed_transaction_fields(overrides, transaction)


def _yield_typed_transaction_fields(overrides, transaction):
    yield "chain_id", overrides.get(
        "chain_id", transaction.get("chain_id", 131277322940537)
    )
    yield "access_list", overrides.get(
        "access_list", transaction.get("access_list", ())
    )


@to_dict
def make_log(transaction, block, transaction_index, log_index, overrides=None):
    if overrides is None:
        overrides = {}

    is_pending = transaction["block_number"] is None

    defaults = {
        "type": "pending" if is_pending else "mined",
        "transaction_index": None if is_pending else transaction_index,
        "block_number": None if is_pending else block["number"],
        "block_hash": None if is_pending else block["hash"],
        "log_index": log_index,
        "address": transaction.get("to", b""),
        "data": b"",
        "topics": [],
    }
    result = {key: overrides.get(key, default) for key, default in defaults.items()}
    yield from result.items()


@to_dict
def make_receipt(transaction, block, _transaction_index, overrides=None):
    if overrides is None:
        overrides = {}

    gas_used = overrides.get("gas_used", 21000)
    yield "gas_used", gas_used
    yield "logs", overrides.get("logs", [])
    yield "transaction_hash", overrides.get("transaction_hash", transaction.get("hash"))
    yield (
        "cumulative_gas_used",
        overrides.get("cumulative_gas_used", block.get("gas_used") + gas_used),
    )
    yield (
        "effective_gas_price",
        overrides.get(
            "effective_gas_price", calculate_effective_gas_price(transaction, block)
        ),
    )
    yield (
        "type",
        overrides.get(
            "type", transaction.get("type", extract_transaction_type(transaction))
        ),
    )
    yield (
        "contract_address",
        overrides.get(
            "contract_address",
            generate_contract_address(transaction["from"], transaction["nonce"]),
        ),
    )


GENESIS_NONCE = b"\x00\x00\x00\x00\x00\x00\x00*"  # 42 encoded as big-endian-integer
BLANK_ROOT_HASH = b"V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n\x5bH\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!"  # noqa: E501
EMPTY_UNCLE_HASH = b"\x1d\xccM\xe8\xde\xc7]z\xab\x85\xb5g\xb6\xcc\xd4\x1a\xd3\x12E\x1b\x94\x8at\x13\xf0\xa1B\xfd@\xd4\x93G"  # noqa: E501
POST_MERGE_DIFFICULTY = 0
POST_MERGE_MIX_HASH = Hash32(32 * b"\x00")
POST_MERGE_NONCE = b"\x00\x00\x00\x00\x00\x00\x00\x00"


def make_genesis_block(overrides=None):
    default_genesis_block = {
        "number": 0,
        "hash": ZERO_32BYTES,
        "parent_hash": ZERO_32BYTES,
        "nonce": POST_MERGE_NONCE,
        "sha3_uncles": EMPTY_UNCLE_HASH,
        "logs_bloom": 0,
        "transactions_root": BLANK_ROOT_HASH,
        "receipts_root": BLANK_ROOT_HASH,
        "state_root": BLANK_ROOT_HASH,
        "coinbase": ZERO_ADDRESS,
        "difficulty": POST_MERGE_DIFFICULTY,
        "mix_hash": POST_MERGE_MIX_HASH,
        "total_difficulty": 131072,
        "size": 0,
        "extra_data": ZERO_32BYTES,
        # gas limit at London fork block 12965000 on mainnet
        "gas_limit": 30029122,
        "gas_used": 0,
        "timestamp": int(time.time()),
        "transactions": [],
        "uncles": [],
        # base fee at London fork block 12965000 on mainnet
        "base_fee_per_gas": 1000000000,
        "withdrawals": [],
        "withdrawals_root": BLANK_ROOT_HASH,
        "parent_beacon_block_root": BLANK_ROOT_HASH,
        "blob_gas_used": 0,
        "excess_blob_gas": 0,
    }
    if overrides is not None:
        genesis_block = merge_genesis_overrides(
            defaults=default_genesis_block, overrides=overrides
        )
    else:
        genesis_block = default_genesis_block
    return genesis_block


@add_hash
@to_dict
def make_block_from_parent(parent_block, overrides=None):
    if overrides is None:
        overrides = {}

    defaults = {
        "number": parent_block["number"] + 1,
        "hash": keccak(parent_block["hash"]),
        "parent_hash": parent_block["hash"],
        "nonce": parent_block["nonce"],
        "sha3_uncles": EMPTY_UNCLE_HASH,
        "logs_bloom": 0,
        "transactions_root": BLANK_ROOT_HASH,
        "receipts_root": BLANK_ROOT_HASH,
        "state_root": BLANK_ROOT_HASH,
        "coinbase": ZERO_ADDRESS,
        "difficulty": POST_MERGE_DIFFICULTY,
        "mix_hash": POST_MERGE_MIX_HASH,
        "total_difficulty": parent_block["difficulty"] + POST_MERGE_DIFFICULTY,
        "size": 0,
        "extra_data": ZERO_32BYTES,
        "gas_limit": parent_block["gas_limit"],
        "gas_used": 0,
        "timestamp": parent_block["timestamp"] + 1,
        "transactions": [],
        "uncles": [],
        "base_fee_per_gas": _calculate_expected_base_fee_per_gas(parent_block),
        "withdrawals": [],
        "withdrawals_root": BLANK_ROOT_HASH,
    }
    result = {key: overrides.get(key, default) for key, default in defaults.items()}
    yield from result.items()


def _calculate_expected_base_fee_per_gas(parent_block) -> int:
    """py-evm logic for calculating the base fee from parent header"""
    parent_base_fee_per_gas = parent_block["base_fee_per_gas"]

    parent_gas_target = parent_block["gas_limit"] // BLOCK_ELASTICITY_MULTIPLIER
    parent_gas_used = parent_block["gas_used"]

    if parent_gas_used == parent_gas_target:
        return parent_base_fee_per_gas

    elif parent_gas_used > parent_gas_target:
        gas_used_delta = parent_gas_used - parent_gas_target
        overburnt_wei = parent_base_fee_per_gas * gas_used_delta
        base_fee_per_gas_delta = max(
            overburnt_wei // parent_gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR,
            1,
        )
        return parent_base_fee_per_gas + base_fee_per_gas_delta

    else:
        gas_used_delta = parent_gas_target - parent_gas_used
        underburnt_wei = parent_base_fee_per_gas * gas_used_delta
        base_fee_per_gas_delta = (
            underburnt_wei // parent_gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR
        )
        return max(parent_base_fee_per_gas - base_fee_per_gas_delta, 0)
