from typing import (
    Any,
    Dict,
    Generator,
    Tuple,
)

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


class Transaction:
    """
    Transaction class to represent a transaction object for use in testing.
    """

    def __init__(
        self,
        _type: int = 0,
        blob_versioned_hashes: tuple[bytes, ...] = (),
        chain_id: int = 131277322940537,
        hash: bytes = b"",
        nonce: int = 0,
        block_hash: bytes = b"",
        block_number: int = 0,
        transaction_index: int = 0,
        _from: bytes = ZERO_ADDRESS,
        to: bytes = ZERO_ADDRESS,
        value: int = 0,
        gas: int = 21000,
        gas_price: int = 1,
        max_fee_per_blob_gas: int = 1,
        max_fee_per_gas: int = 2000000000,
        max_priority_fee_per_gas: int = 1000000000,
        data: bytes = b"",
        access_list: tuple[tuple[bytes, ...], ...] = (),
        r: int = 0,
        s: int = 0,
        v: int = 0,
        y_parity: int = 0,
    ):
        self.type = _type
        self.blob_versioned_hashes = blob_versioned_hashes
        self.chain_id = chain_id
        self.hash = hash
        self.nonce = nonce
        self.block_hash = block_hash
        self.block_number = block_number
        self.transaction_index = transaction_index
        self._from = _from
        self.to = to
        self.value = value
        self.gas = gas
        self.gas_price = gas_price
        self.max_fee_per_blob_gas = max_fee_per_blob_gas
        self.max_fee_per_gas = max_fee_per_gas
        self.max_priority_fee_per_gas = max_priority_fee_per_gas
        self.data = data
        self.access_list = access_list
        self.r = r
        self.s = s
        self.v = v
        self.y_parity = y_parity

    def __iter__(self) -> Generator[Tuple[str, Any], None, None]:
        """
        Yield key, value pairs of the Transaction object attributes
        """
        yield from (
            (
                "from" if key == "_from" else key,
                value,
            )
            for key, value in self.__dict__.items()
            if value is not None
        )


class Block:
    """
    Block class to represent a block object for use in testing.
    """

    def __init__(
        self,
        number: int = 0,
        hash: bytes = b"",
        parent_hash: bytes = b"",
        nonce: bytes = b"",
        base_fee_per_gas: int = 0,
        sha3_uncles: bytes = b"",
        logs_bloom: bytes = b"",
        transactions_root: bytes = b"",
        receipts_root: bytes = b"",
        state_root: bytes = b"",
        coinbase: bytes = ZERO_ADDRESS,
        difficulty: int = 0,
        mix_hash: bytes = b"",
        total_difficulty: int = 0,
        size: int = 0,
        extra_data: bytes = b"",
        gas_limit: int = 0,
        gas_used: int = 0,
        timestamp: int = 0,
        transactions: tuple[bytes | dict[str, Any], ...] = (),
        uncles: tuple[bytes, ...] = (),
        withdrawals: tuple[Dict[str, Any], ...] = (),
        withdrawals_root: bytes = b"",
        parent_beacon_block_root: bytes = b"",
        blob_gas_used: int = 0,
        excess_blob_gas: int = 0,
    ):
        self.number = number
        self.hash = hash
        self.parent_hash = parent_hash
        self.nonce = nonce
        self.base_fee_per_gas = base_fee_per_gas
        self.sha3_uncles = sha3_uncles
        self.logs_bloom = logs_bloom
        self.transactions_root = transactions_root
        self.receipts_root = receipts_root
        self.state_root = state_root
        self.coinbase = coinbase
        self.difficulty = difficulty
        self.mix_hash = mix_hash
        self.total_difficulty = total_difficulty
        self.size = size
        self.extra_data = extra_data
        self.gas_limit = gas_limit
        self.gas_used = gas_used
        self.timestamp = timestamp
        self.transactions = transactions
        self.uncles = uncles
        self.withdrawals = withdrawals
        self.withdrawals_root = withdrawals_root
        self.parent_beacon_block_root = parent_beacon_block_root
        self.blob_gas_used = blob_gas_used
        self.excess_blob_gas = excess_blob_gas

    def __iter__(self) -> Generator[Tuple[str, Any], None, None]:
        """
        Yield key, value pairs of the Block object attributes
        """
        yield from (
            (key, value) for key, value in self.__dict__.items() if value is not None
        )


class LogEntry:
    """
    LogEntry class to represent a log entry object for use in testing.
    """

    def __init__(
        self,
        _type: int = 0,
        log_index: int = 0,
        transaction_index: int = 0,
        transaction_hash: bytes = b"",
        block_hash: bytes = b"",
        block_number: int = 0,
        address: bytes = ZERO_ADDRESS,
        data: bytes = b"",
        topics: tuple[bytes, ...] = (),
    ):
        self.type = _type
        self.log_index = log_index
        self.transaction_index = transaction_index
        self.transaction_hash = transaction_hash
        self.block_hash = block_hash
        self.block_number = block_number
        self.address = address
        self.data = data
        self.topics = topics

    def __iter__(self) -> Generator[Tuple[str, Any], None, None]:
        """
        Yield key, value pairs of the LogEntry object attributes
        """
        yield from (
            (key, value) for key, value in self.__dict__.items() if value is not None
        )


class Receipt:
    """
    Receipt class to represent a receipt object for use in testing.
    """

    def __init__(
        self,
        transaction_hash: bytes = b"",
        transaction_index: int = 0,
        block_number: int = 0,
        block_hash: bytes = b"",
        cumulative_gas_used: int = 0,
        effective_gas_price: int = 0,
        _from: bytes = ZERO_ADDRESS,
        gas_used: int = 0,
        contract_address: bytes = ZERO_ADDRESS,
        logs: tuple[Dict[str, Any], ...] = (),
        state_root: bytes = b"",
        status: int = 1,
        to: bytes = ZERO_ADDRESS,
        _type: int = 0,
        base_fee_per_gas: int = 0,
        blob_gas_used: int = 0,
        blob_gas_price: int = 0,
    ):
        self.transaction_hash = transaction_hash
        self.transaction_index = transaction_index
        self.block_number = block_number
        self.block_hash = block_hash
        self.cumulative_gas_used = cumulative_gas_used
        self.effective_gas_price = effective_gas_price
        self._from = _from
        self.gas_used = gas_used
        self.contract_address = contract_address
        self.logs = logs
        self.state_root = state_root
        self.status = status
        self.to = to
        self._type = _type
        self.base_fee_per_gas = base_fee_per_gas
        self.blob_gas_used = blob_gas_used
        self.blob_gas_price = blob_gas_price

    def __iter__(self) -> Generator[Tuple[str, Any], None, None]:
        """
        Yield key, value pairs of the Receipt object attributes
        """
        yield from (
            (
                "from" if key == "_from" else "type" if key == "_type" else key,
                value,
            )
            for key, value in self.__dict__.items()
            if value is not None
        )
