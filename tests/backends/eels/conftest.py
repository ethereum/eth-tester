import pytest
from typing import (
    Any,
    Dict,
    List,
    Sequence,
    Tuple,
    Union,
)

from ethereum.cancun.blocks import (
    Block,
    Header,
    Log,
    Withdrawal,
)
from ethereum.cancun.fork_types import (
    Bloom,
    Root,
)
from ethereum.cancun.transactions import (
    AccessListTransaction,
    BlobTransaction,
    FeeMarketTransaction,
    LegacyTransaction,
)
from ethereum_types.bytes import (
    Bytes,
    Bytes8,
    Bytes20,
    Bytes32,
)
from ethereum_types.numeric import (
    U64,
    U256,
    Uint,
)

from eth_tester.constants import (
    ZERO_ADDRESS,
    ZERO_HASH32,
)

AnyTransaction = Union[
    Bytes,
    LegacyTransaction,
    BlobTransaction,
    FeeMarketTransaction,
    AccessListTransaction,
]


@pytest.fixture()
def block_keys() -> List[str]:
    """
    Returns a list of keys that are expected to be present in a block.
    This is used to validate the serialization of blocks.
    """
    return [
        "number",
        "hash",
        "parentHash",
        "nonce",
        "stateRoot",
        "coinbase",
        "transactionsRoot",
        "receiptsRoot",
        "logsBloom",
        "gasLimit",
        "gasUsed",
        "timestamp",
        "withdrawalsRoot",
        "baseFeePerGas",
        "blobGasUsed",
        "excessBlobGas",
        "transactions",
        "uncles",
        "withdrawals",
        "sha3Uncles",
        "difficulty",
        "totalDifficulty",
        "mixHash",
        "size",
        "extraData",
    ]


@pytest.fixture
def finalized_block_keys(block_keys: List[str]) -> List[str]:
    """
    Returns a list of keys that are expected to be present in a finalized block.
    This is used to validate the serialization of finalized blocks.
    """
    return block_keys + ["parentBeaconBlockRoot"]


@pytest.fixture
def block_transaction_keys() -> List[str]:
    return [
        "type",
        "hash",
        "nonce",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "gas",
        "to",
        "from",
        "value",
        "data",
        "r",
        "s",
        "v",
        "gasPrice",
        "chainId",
        "maxPriorityFeePerGas",
        "maxFeePerGas",
        "accessList",
        "maxFeePerBlobGas",
        "blobVersionedHashes",
        "yParity",
    ]


@pytest.fixture
def transaction() -> LegacyTransaction:
    return LegacyTransaction(
        nonce=U256(0),
        gas_price=Uint(0),
        gas=Uint(0),
        to=Bytes20(ZERO_ADDRESS),
        value=U256(0),
        data=b"",
        v=U256(38),
        r=U256(1),
        s=U256(2),
    )


@pytest.fixture
def transaction_dict() -> Dict[str, Any]:
    return {
        "nonce": 0,
        "gas_price": 0,
        "gas": 0,
        "to": b"\x00" * 20,
        "value": 0,
        "data": b"",
        "v": 38,
        "r": 1,
        "s": 2,
    }


@pytest.fixture
def block_header(request: pytest.FixtureRequest) -> Header:
    return Header(
        parent_hash=Bytes32(b"\x00" * 32),
        ommers_hash=Bytes32(b"\x00" * 32),
        coinbase=Bytes20(ZERO_ADDRESS),
        state_root=Root(ZERO_HASH32),
        transactions_root=Root(ZERO_HASH32),
        receipt_root=Root(ZERO_HASH32),
        bloom=Bloom(b"\x00" * 256),
        difficulty=Uint(0),
        number=Uint(0),
        gas_limit=Uint(0),
        gas_used=Uint(0),
        timestamp=U256(0),
        extra_data=Bytes(b""),
        prev_randao=Bytes32(b"\x00" * 32),
        nonce=Bytes8(b"\x00" * 8),
        base_fee_per_gas=Uint(0),
        withdrawals_root=Root(ZERO_HASH32),
        blob_gas_used=U64(0),
        excess_blob_gas=U64(0),
        parent_beacon_block_root=Root(ZERO_HASH32),
    )


@pytest.fixture(params=[True, False], ids=["pending", "finalized"])
def block(
    request: pytest.FixtureRequest,
    pending_block: Dict[str, Any],
    finalized_block: Block,
) -> Union[Block, Dict[str, Any]]:
    is_pending = request.param
    if is_pending:
        return pending_block
    else:
        return finalized_block


@pytest.fixture(
    params=[
        "no_pending_block",
        "empty_pending_block",
        "pending_block",
    ],
)
def parameterized_pending_block(
    request: pytest.FixtureRequest,
    pending_block_header: Dict[str, Any],
    block_transactions: Sequence[AnyTransaction],
    withdrawals: Tuple[Withdrawal, ...],
) -> Union[None, Dict[str, Any]]:
    if request.param == "pending_block":
        return {
            "header": pending_block_header,
            "transactions": block_transactions,
            "ommers": (),
            "withdrawals": withdrawals,
        }
    elif request.param == "empty":
        return {}
    return None


@pytest.fixture
def pending_block(
    pending_block_header: Dict[str, Any],
    block_transactions: Sequence[AnyTransaction],
    withdrawals: Tuple[Withdrawal, ...],
) -> Dict[str, Any]:
    return {
        "header": pending_block_header,
        "transactions": block_transactions,
        "ommers": (),
        "withdrawals": withdrawals,
    }


@pytest.fixture
def finalized_block(
    block_header: Header,
    block_transactions: Tuple[Union[Bytes, LegacyTransaction], ...],
    withdrawals: Tuple[Withdrawal],
) -> Block:
    return Block(
        header=block_header,
        transactions=block_transactions,
        ommers=(),
        withdrawals=withdrawals,
    )


@pytest.fixture
def pending_block_header() -> Dict[str, Any]:
    return {
        "parent_hash": b"\x00" * 32,
        "ommers_hash": b"\x00" * 32,
        "coinbase": b"\x00" * 20,
        "state_root": ZERO_HASH32,
        "transactions_root": ZERO_HASH32,
        "receipt_root": ZERO_HASH32,
        "bloom": b"\x00" * 256,
        "difficulty": 0,
        "number": 0,
        "gas_limit": 0,
        "gas_used": 0,
        "timestamp": 0,
        "extra_data": b"",
        "prev_randao": b"\x00" * 32,
        "nonce": b"\x00" * 8,
        "base_fee_per_gas": 0,
        "withdrawals_root": ZERO_HASH32,
        "blob_gas_used": 0,
        "excess_blob_gas": 0,
    }


@pytest.fixture(
    params=(
        "no_transactions",
        "legacy_transactions",
        "blob_transactions",
        "dynamic_fee_transactions",
        "access_list_transactions",
    )
)
def block_transactions(
    request: pytest.FixtureRequest,
) -> Sequence[AnyTransaction]:
    if request.param == "legacy_transactions":
        return [
            LegacyTransaction(
                nonce=U256(0),
                gas_price=Uint(0),
                gas=Uint(0),
                to=Bytes20(ZERO_ADDRESS),
                value=U256(0),
                data=b"",
                v=U256(38),
                r=U256(1),
                s=U256(2),
            ),
        ]
    elif request.param == "blob_transactions":
        return [
            BlobTransaction(
                chain_id=U64(0),
                nonce=U256(0),
                max_priority_fee_per_gas=Uint(0),
                max_fee_per_gas=Uint(0),
                gas=Uint(0),
                to=Bytes20(ZERO_ADDRESS),
                value=U256(0),
                data=b"",
                access_list=(),
                max_fee_per_blob_gas=U256(0),
                blob_versioned_hashes=(Bytes32(b"\x00" * 32),),
                y_parity=U256(0),
                r=U256(1),
                s=U256(2),
            ),
        ]
    elif request.param == "dynamic_fee_transactions":
        return [
            FeeMarketTransaction(
                chain_id=U64(0),
                nonce=U256(0),
                max_priority_fee_per_gas=Uint(0),
                max_fee_per_gas=Uint(0),
                gas=Uint(0),
                to=Bytes20(ZERO_ADDRESS),
                value=U256(0),
                data=b"",
                access_list=(),
                y_parity=U256(0),
                r=U256(1),
                s=U256(2),
            ),
        ]

    return []


@pytest.fixture(
    params=(
        (),
        (
            Withdrawal(
                index=U64(0),
                validator_index=U64(0),
                address=Bytes20(ZERO_ADDRESS),
                amount=U256(100),
            ),
        ),
    ),
    ids=["no_withdrawals", "one_withdrawal"],
)
def withdrawals(request: pytest.FixtureRequest) -> List[Withdrawal]:
    return list(request.param)


@pytest.fixture(
    params=[
        (1, (), 0),
        (1, (), 1),
        (
            3,
            (
                Log(
                    address=Bytes20(ZERO_ADDRESS),
                    topics=(Bytes32(b"\x00" * 32), Bytes32(b"\x01" * 32)),
                    data=b"\x02" * 32,
                ),
            ),
            1,
        ),
    ],
    ids=[
        "empty_logs_with_no_error",
        "empty_logs_with_error",
        "one_log_with_error",
    ],
)
def process_transaction_return(request: pytest.FixtureRequest) -> Tuple[int, Log, int]:
    return tuple(request.param)


@pytest.fixture
def log() -> Log:
    return Log(
        address=Bytes20(ZERO_ADDRESS),
        topics=(Bytes32(b"\x00" * 32), Bytes32(b"\x01" * 32)),
        data=b"\x02" * 32,
    )
