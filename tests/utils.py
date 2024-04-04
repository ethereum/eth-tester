from eth_utils import (
    to_dict,
)

ZERO_32BYTES = b"\x00" * 32
ZERO_ADDRESS = b"\x00" * 20


def yield_key_value_if_value_not_none(key, value):
    if value is not None:
        yield key, value


@to_dict
def make_receipt(
    transaction_hash=ZERO_32BYTES,
    transaction_index=0,
    block_number=0,
    block_hash=ZERO_32BYTES,
    cumulative_gas_used=0,
    blob_gas_used=None,
    blob_gas_price=None,
    _from=ZERO_ADDRESS,
    gas_used=21000,
    effective_gas_price=1000000000,
    contract_address=ZERO_ADDRESS,
    logs=None,
    state_root=b"\x00",
    status=0,
    to=ZERO_ADDRESS,
    _type="0x0",
):
    yield from yield_key_value_if_value_not_none("transaction_hash", transaction_hash)
    yield from yield_key_value_if_value_not_none("transaction_index", transaction_index)
    yield from yield_key_value_if_value_not_none("block_number", block_number)
    yield from yield_key_value_if_value_not_none("block_hash", block_hash)
    yield from yield_key_value_if_value_not_none(
        "cumulative_gas_used", cumulative_gas_used
    )
    yield from yield_key_value_if_value_not_none("gas_used", gas_used)
    yield from yield_key_value_if_value_not_none(
        "effective_gas_price", effective_gas_price
    )
    yield from yield_key_value_if_value_not_none("from", _from)
    yield from yield_key_value_if_value_not_none("to", to)
    yield from yield_key_value_if_value_not_none("type", _type)
    yield from yield_key_value_if_value_not_none("state_root", state_root)
    yield from yield_key_value_if_value_not_none("status", status)
    yield from yield_key_value_if_value_not_none("logs", logs or [])
    yield from yield_key_value_if_value_not_none("contract_address", contract_address)
    yield from yield_key_value_if_value_not_none("blob_gas_used", blob_gas_used)
    yield from yield_key_value_if_value_not_none("blob_gas_price", blob_gas_price)
