from typing import (
    Any,
    Iterator,
    Tuple,
)

from eth_utils import (
    to_dict,
)

from .constants import (
    ZERO_32BYTES,
    ZERO_ADDRESS,
)


def yield_key_value_if_value_not_none(
    key: str, value: Any
) -> Iterator[Tuple[str, Any]]:
    if value is not None:
        yield key, value


@to_dict
def make_receipt(
    transaction_hash: Any = ZERO_32BYTES,
    transaction_index: Any = 0,
    block_number: Any = 0,
    block_hash: Any = ZERO_32BYTES,
    cumulative_gas_used: Any = 0,
    blob_gas_used: Any = None,
    blob_gas_price: Any = None,
    _from: Any = ZERO_ADDRESS,
    gas_used: Any = 21000,
    effective_gas_price: Any = 1000000000,
    contract_address: Any = ZERO_ADDRESS,
    logs: Any = None,
    state_root: Any = b"\x00",
    status: Any = 0,
    to: Any = ZERO_ADDRESS,
    _type: Any = "0x0",
) -> Iterator[Tuple[str, Any]]:
    yield from yield_key_value_if_value_not_none("transactionHash", transaction_hash)
    yield from yield_key_value_if_value_not_none("transactionIndex", transaction_index)
    yield from yield_key_value_if_value_not_none("blockNumber", block_number)
    yield from yield_key_value_if_value_not_none("blockHash", block_hash)
    yield from yield_key_value_if_value_not_none(
        "cumulativeGasUsed", cumulative_gas_used
    )
    yield from yield_key_value_if_value_not_none("gasUsed", gas_used)
    yield from yield_key_value_if_value_not_none(
        "effectiveGasPrice", effective_gas_price
    )
    yield from yield_key_value_if_value_not_none("from", _from)
    yield from yield_key_value_if_value_not_none("to", to)
    yield from yield_key_value_if_value_not_none("type", _type)
    yield from yield_key_value_if_value_not_none("stateRoot", state_root)
    yield from yield_key_value_if_value_not_none("status", status)
    yield from yield_key_value_if_value_not_none("logs", logs or [])
    yield from yield_key_value_if_value_not_none("contractAddress", contract_address)
    yield from yield_key_value_if_value_not_none("blobGasUsed", blob_gas_used)
    yield from yield_key_value_if_value_not_none("blobGasPrice", blob_gas_price)
