import pytest
from typing import (
    Any,
    Dict,
    Hashable,
    List,
    Optional,
    Sequence,
    Tuple,
)

from eth.vm.forks.cancun.transactions import (
    TypedTransaction,
)
from eth_typing import (
    Address,
)

from eth_tester import (
    EthereumTester,
    PyEVMBackend,
)
from eth_tester.backends.pyevm.utils import (
    is_supported_pyevm_version_available,
)
from eth_tester.constants import (
    ZERO_ADDRESS,
    ZERO_HASH32,
)

if is_supported_pyevm_version_available():
    from eth.abc import (
        BlockAPI,
        BlockHeaderAPI,
        BlockNumber,
        Hash32,
        LogAPI,
        ReceiptAPI,
        WithdrawalAPI,
    )
else:

    class BlockAPI:
        pass

    class BlockHeaderAPI:
        pass

    class BlockNumber:
        pass

    class Hash32:
        pass

    class LogAPI:
        pass

    class ReceiptAPI:
        pass

    class WithdrawalAPI:
        pass


DEFAULT_ZERO_ADDRESS = Address(ZERO_ADDRESS)
DEFAULT_ZERO_HASH32 = Hash32(ZERO_HASH32)
DEFAULT_BLOCK_NUMBER = BlockNumber(0)


class FakeState:
    def __init__(self, blob_base_fee: int = 1) -> None:
        self.blob_base_fee = blob_base_fee


class FakeVM:
    def __init__(self, state: FakeState) -> None:
        self.state = state if state else FakeState(1)


class FakeWithdrawal(WithdrawalAPI):
    def __init__(
        self,
        index: int = 0,
        validator_index: int = 0,
        address: Address = DEFAULT_ZERO_ADDRESS,
        amount: int = 0,
    ) -> None:
        self._index = index
        self._validator_index = validator_index
        self._address = address
        self._amount = amount

    # These are the abstract properties required by WithdrawalAPI
    @property
    def index(self) -> int:
        return self._index

    @property
    def validator_index(self) -> int:
        return self._validator_index

    @property
    def address(self) -> Address:
        return self._address

    @property
    def amount(self) -> int:
        return self._amount

    @property
    def hash(self) -> Hash32:
        return Hash32(b"\x00" * 32)

    def validate(self) -> None:
        pass

    def encode(self) -> bytes:
        return b""


@pytest.fixture
def withdrawal() -> FakeWithdrawal:
    return FakeWithdrawal(
        index=0,
        validator_index=0,
        address=DEFAULT_ZERO_ADDRESS,
        amount=0,
    )


class FakeBlockHeader(BlockHeaderAPI):
    def __init__(
        self,
        block_number: BlockNumber = DEFAULT_BLOCK_NUMBER,
        hash: bytes = b"",
        parent_hash: Hash32 = DEFAULT_ZERO_HASH32,
        uncles_hash: Hash32 = DEFAULT_ZERO_HASH32,
        mix_hash: Hash32 = DEFAULT_ZERO_HASH32,
        coinbase: Address = DEFAULT_ZERO_ADDRESS,
        transaction_root: Hash32 = DEFAULT_ZERO_HASH32,
        receipt_root: Hash32 = DEFAULT_ZERO_HASH32,
        state_root: Hash32 = DEFAULT_ZERO_HASH32,
        nonce: bytes = b"",
        bloom: int = 0,
        difficulty: int = 0,
        extra_data: bytes = b"",
        gas_limit: int = 0,
        gas_used: int = 0,
        timestamp: int = 0,
        blob_gas_used: int = 0,
        excess_blob_gas: int = 0,
        base_fee_per_gas: int = 1,
        withdrawals_root: Optional[Hash32] = None,
        parent_beacon_block_root: Optional[Hash32] = None,
    ) -> None:
        self.block_number = block_number
        self._hash = hash
        self.parent_hash = parent_hash
        self.uncles_hash = uncles_hash
        self.mix_hash = mix_hash
        self.coinbase = coinbase
        self.transaction_root = transaction_root
        self.receipt_root = receipt_root
        self.state_root = state_root
        self.nonce = nonce
        self.bloom = bloom
        self.difficulty = difficulty
        self.extra_data = extra_data
        self.gas_limit = gas_limit
        self.gas_used = gas_used
        self.timestamp = timestamp
        self._withdrawals_root = withdrawals_root
        self._parent_beacon_block_root = parent_beacon_block_root
        self._blob_gas_used = blob_gas_used
        self._excess_blob_gas = excess_blob_gas
        self._base_fee_per_gas = base_fee_per_gas

    @property
    def hash(self) -> Hash32:
        return Hash32(self._hash if self._hash else ZERO_HASH32)

    @property
    def mining_hash(self) -> Hash32:
        return Hash32(self._hash if self._hash else ZERO_HASH32)

    @property
    def base_fee_per_gas(self) -> Optional[int]:
        return self._base_fee_per_gas

    @property
    def withdrawals_root(self) -> Optional[Hash32]:
        return self._withdrawals_root

    @property
    def parent_beacon_block_root(self) -> Optional[Hash32]:
        return self._parent_beacon_block_root

    @property
    def blob_gas_used(self) -> int:
        return self._blob_gas_used

    @property
    def excess_blob_gas(self) -> int:
        return self._excess_blob_gas

    @property
    def hex_hash(self) -> str:
        return self.hash.hex()

    @property
    def is_genesis(self) -> bool:
        return self.block_number == 0

    def as_dict(self) -> Dict[Hashable, Any]:
        return {
            "block_number": self.block_number,
            "hash": self.hash,
            "parent_hash": self.parent_hash,
            "uncles_hash": self.uncles_hash,
            "mix_hash": self.mix_hash,
            "coinbase": self.coinbase,
            "transaction_root": self.transaction_root,
            "receipt_root": self.receipt_root,
            "state_root": self.state_root,
            "nonce": self.nonce,
            "bloom": self.bloom,
            "difficulty": self.difficulty,
            "extra_data": self.extra_data,
            "gas_limit": self.gas_limit,
            "gas_used": self.gas_used,
            "timestamp": self.timestamp,
        }

    def build_changeset(self, *args: Any, **kwargs: Any) -> Any:
        return None

    def copy(self, *args: Any, **kwargs: Any) -> "BlockHeaderAPI":
        return FakeBlockHeader()

    @classmethod
    def deserialize(cls, encoded: List[bytes]) -> "BlockHeaderAPI":
        return FakeBlockHeader()

    @classmethod
    def serialize(cls, obj: "BlockHeaderAPI") -> List[bytes]:
        return []


class FakeLog(LogAPI):
    def __init__(
        self,
        address: Address = DEFAULT_ZERO_ADDRESS,
        data: bytes = b"",
        topics: Sequence[int] = (),
    ) -> None:
        self.address = address
        self.data = data
        self.topics = topics

    @property
    def bloomables(self) -> Tuple[bytes, ...]:
        return ()


class FakeReceipt(ReceiptAPI):
    def __init__(
        self,
        state_root: bytes = b"",
        gas_used: int = 0,
        logs: Sequence[FakeLog] = (),
        bloom: int = 0,
        bloom_filter: int = 0,
    ) -> None:
        self._gas_used = gas_used
        self._logs = logs
        self._state_root = state_root
        self._bloom = bloom
        self._bloom_filter = bloom_filter
        self._logs = logs

    @property
    def gas_used(self) -> int:
        return self._gas_used

    @property
    def state_root(self) -> bytes:
        return self._state_root

    @property
    def logs(self) -> Sequence[FakeLog]:
        return self._logs

    @property
    def bloom(self) -> int:
        return self._bloom

    @property
    def bloom_filter(self) -> Any:
        return self._bloom_filter

    def copy(self, *args: Any, **kwargs: Any) -> "FakeReceipt":
        return FakeReceipt(
            state_root=self._state_root,
            gas_used=self._gas_used,
            logs=self._logs,
            bloom=self._bloom,
            bloom_filter=self._bloom_filter,
        )

    def encode(self) -> bytes:
        return b""


class FakeSetCodeAuthorization:
    def __init__(
        self,
        chain_id: int = 0,
        address: Address = DEFAULT_ZERO_ADDRESS,
        nonce: int = 0,
        y_parity: int = 0,
        s: int = 0,
        r: int = 0,
    ) -> None:
        self.chain_id = chain_id
        self.nonce = nonce
        self.address = address
        self.y_parity = y_parity
        self.s = s
        self.r = r

    def validate_for_transaction(self) -> None:
        return

    def validate(self, chain_id: int) -> None:
        return


DEFAULT_AUTHORIZATION_LIST = FakeSetCodeAuthorization()


class FakeTransaction(TypedTransaction):
    def __init__(
        self,
        type_id: Optional[int] = 0,
        hash: Hash32 = DEFAULT_ZERO_HASH32,
        nonce: int = 0,
        to: Address = DEFAULT_ZERO_ADDRESS,
        _from: Address = DEFAULT_ZERO_ADDRESS,
        sender: Address = DEFAULT_ZERO_ADDRESS,
        value: int = 0,
        gas: int = 0,
        data: bytes = b"",
        s: int = 0,
        r: int = 0,
        v: int = 0,
        authorization_list: Sequence[FakeSetCodeAuthorization] = (
            DEFAULT_AUTHORIZATION_LIST,
        ),
        y_parity: int = 0,
        chain_id: Optional[int] = None,
        access_list: Optional[Sequence[Tuple[Address, Sequence[int]]]] = None,
        gas_price: Optional[int] = None,
        max_fee_per_gas: Optional[int] = None,
        max_priority_fee_per_gas: Optional[int] = None,
        max_fee_per_blob_gas: Optional[int] = None,
        blob_versioned_hashes: Optional[Sequence[Hash32]] = None,
    ) -> None:
        self.type_id = type_id
        self._hash = hash
        self._nonce = nonce
        self._to = to
        self._from = _from
        self._sender = sender
        self._value = value
        self._gas = gas
        self._data = data
        self._s = s
        self._r = r
        self._v = v
        self._authorization_list = authorization_list
        self._y_parity = y_parity

        if chain_id is not None:
            self._chain_id = chain_id

        if access_list is not None:
            self._access_list = access_list

        if gas_price is not None:
            self._gas_price = gas_price

        if max_fee_per_gas is not None:
            self._max_fee_per_gas = max_fee_per_gas

        if max_priority_fee_per_gas is not None:
            self._max_priority_fee_per_gas = max_priority_fee_per_gas

        if max_fee_per_blob_gas is not None:
            self._max_fee_per_blob_gas = max_fee_per_blob_gas

        if blob_versioned_hashes is not None:
            self._blob_versioned_hashes = blob_versioned_hashes

    @property
    def to(self) -> Address:
        return self._to

    @property
    def from_(self) -> Address:
        return self._from

    @property
    def gas_price(self) -> int:
        return getattr(self, "_gas_price", 0)

    @property
    def max_fee_per_gas(self) -> int:
        return getattr(self, "_max_fee_per_gas", 0)

    @property
    def max_priority_fee_per_gas(self) -> int:
        return getattr(self, "_max_priority_fee_per_gas", 0)

    @property
    def max_fee_per_blob_gas(self) -> int:
        return getattr(self, "_max_fee_per_blob_gas", 0)

    @property
    def sender(self) -> Address:
        return self._sender

    @property
    def nonce(self) -> int:
        return self._nonce

    @property
    def value(self) -> int:
        return self._value

    @property
    def gas(self) -> int:
        return self._gas

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def y_parity(self) -> int:
        return self._y_parity

    @property
    def r(self) -> int:
        return self._r

    @property
    def s(self) -> int:
        return self._s

    @property
    def hash(self) -> Hash32:
        return Hash32(self._hash if self._hash else ZERO_HASH32)

    @property
    def v(self) -> int:
        return self._v

    @property
    def intrinsic_gas(self) -> int:
        return 0

    @property
    def access_list(self) -> Sequence[Tuple[Address, Sequence[int]]]:
        return getattr(self, "_access_list", ())

    @property
    def authorization_list(self) -> Sequence[Any]:
        return self._authorization_list

    @property
    def blob_versioned_hashes(self) -> Sequence[Hash32]:  # type: ignore
        # Type ignored, mismatch in parent classes
        return getattr(self, "_blob_versioned_hashes", ())

    @property
    def chain_id(self) -> int:
        return getattr(self, "_chain_id", 0)

    @property
    def is_signature_valid(self) -> bool:
        return True

    def check_signature_validity(self) -> None:
        return None

    def make_receipt(
        self,
        status: bytes,
        gas_used: int,
        log_entries: Tuple[Tuple[bytes, Tuple[int, ...], bytes], ...],
    ) -> FakeReceipt:
        return FakeReceipt()

    def get_sender(self) -> Address:
        return self._sender

    def get_message_for_signing(self) -> bytes:
        return b""

    def get_intrinsic_gas(self) -> int:
        return 0

    def gas_used_by(self, computation: Any) -> int:
        return 0

    def validate(self) -> None:
        return

    def encode(self) -> bytes:
        return b""

    def copy(self, **overrides: Any) -> "FakeTransaction":
        return FakeTransaction()


DEFAULT_BLOCK_HEADER = FakeBlockHeader()


class FakeBlock(BlockAPI):
    def __init__(
        self,
        header: FakeBlockHeader = DEFAULT_BLOCK_HEADER,
        transactions: Tuple[TypedTransaction, ...] = (),
        uncles: Tuple[FakeBlockHeader, ...] = (),
        withdrawals: Tuple[FakeWithdrawal, ...] = (),
    ) -> None:
        self.header = header
        self.transactions = transactions
        self.uncles = uncles

        if getattr(self.header, "withdrawals_root", None) is not None:
            self.withdrawals = withdrawals
        else:
            self.withdrawals = tuple()

    @property
    def hash(self) -> Hash32:
        return Hash32(self.header.hash if self.header.hash else ZERO_HASH32)

    @property
    def number(self) -> BlockNumber:
        return self.header.block_number

    @property
    def is_genesis(self) -> bool:
        return self.header.is_genesis

    def from_header(self, header):  # type: ignore
        pass

    def get_transaction_builder(cls):  # type: ignore
        pass

    def get_receipt_builder(cls):  # type: ignore
        pass

    def get_receipts(self, chaindb):  # type: ignore
        pass

    def serialize(self) -> bytes:
        return b""

    def deserialize(self, data: bytes) -> "FakeBlock":
        return FakeBlock()


@pytest.fixture
def eth_tester() -> EthereumTester:
    if not is_supported_pyevm_version_available():
        pytest.skip("PyEVM is not available")
    backend = PyEVMBackend()
    return EthereumTester(backend=backend)


@pytest.fixture
def accounts_from_mnemonic() -> List[str]:
    return [
        "0x1e59ce931B4CFea3fe4B875411e280e173cB7A9C",
        "0xc89D42189f0450C2b2c3c61f58Ec5d628176A1E7",
        "0x318b469BBa396AEc2C60342F9441be36A1945174",
    ]


# Transaction fixtures


@pytest.fixture(
    params=[
        "legacy_transactions",
        "blob_transactions",
        "dynamic_fee_transactions",
        "access_list_transactions",
    ]
)
def transaction(
    request: pytest.FixtureRequest,
) -> FakeTransaction:
    if request.param == "access_list_transactions":
        return FakeTransaction(type_id=1, hash=DEFAULT_ZERO_HASH32)
    elif request.param == "dynamic_fee_transactions":
        return FakeTransaction(type_id=2, hash=DEFAULT_ZERO_HASH32)
    elif request.param == "blob_transactions":
        return FakeTransaction(type_id=3, hash=DEFAULT_ZERO_HASH32)

    return FakeTransaction(type_id=0, hash=DEFAULT_ZERO_HASH32)


# Block fixtures


@pytest.fixture(params=["zero", "one"], ids=["zero_withdrawals", "one_withdrawal"])
def withdrawals(request: pytest.FixtureRequest) -> Tuple[FakeWithdrawal, ...]:
    if request.param == "one":
        return (FakeWithdrawal(),)
    else:
        return ()


@pytest.fixture(
    params=[
        "no_transactions",
        "legacy_transactions",
        "blob_transactions",
        "dynamic_fee_transactions",
        "access_list_transactions",
    ]
)
def block_transactions(
    request: pytest.FixtureRequest,
) -> Tuple[FakeTransaction, ...]:
    if request.param == "legacy_transactions":
        return tuple(
            [FakeTransaction(type_id=0, hash=DEFAULT_ZERO_HASH32) for _ in range(3)]
        )
    elif request.param == "access_list_transactions":
        return tuple(
            [FakeTransaction(type_id=1, hash=DEFAULT_ZERO_HASH32) for _ in range(3)]
        )
    elif request.param == "dynamic_fee_transactions":
        return tuple(
            [FakeTransaction(type_id=2, hash=DEFAULT_ZERO_HASH32) for _ in range(3)]
        )
    elif request.param == "blob_transactions":
        return tuple(
            [FakeTransaction(type_id=3, hash=DEFAULT_ZERO_HASH32) for _ in range(3)]
        )

    return ()


@pytest.fixture(
    params=[
        {},
        {"base_fee_per_gas": 1},
        {"withdrawals_root": DEFAULT_ZERO_HASH32},
        {
            "base_fee_per_gas": 1,
            "withdrawals_root": DEFAULT_ZERO_HASH32,
            "parent_beacon_block_root": DEFAULT_ZERO_HASH32,
        },
    ],
    ids=[
        "legacy_block_header",
        "london_block_header",
        "shanghai_block_header",
        "cancun_block_header",
    ],
)
def block_header(request: pytest.FixtureRequest) -> FakeBlockHeader:
    kwargs = request.param
    return FakeBlockHeader(
        **kwargs,
    )


@pytest.fixture
def block(
    block_header: FakeBlockHeader,
    block_transactions: Tuple[FakeTransaction, ...],
    withdrawals: Tuple[FakeWithdrawal, ...],
) -> FakeBlock:
    return FakeBlock(
        header=block_header,
        transactions=block_transactions,
        uncles=(),
        withdrawals=withdrawals,
    )


# Transaction receipt fixtures


@pytest.fixture
def transaction_receipts() -> List[FakeReceipt]:
    return [
        FakeReceipt(
            state_root=DEFAULT_ZERO_HASH32,
            gas_used=0,
            logs=[FakeLog(DEFAULT_ZERO_ADDRESS, b"", ())],
        )
    ]
