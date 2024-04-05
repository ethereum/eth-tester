from eth_utils import (
    to_bytes,
)
from eth_utils.toolz import (
    assoc,
    partial,
    pipe,
)

from eth_tester.backends.mock.common import (
    calculate_effective_gas_price,
)
from eth_tester.constants import (
    LEGACY_TX_TYPE,
)
from eth_tester.utils.transactions import (
    extract_transaction_type,
)


def serialize_block(block, transaction_serializer, is_pending):
    serialized_transactions = tuple(
        transaction_serializer(
            transaction, block, transaction_index, is_pending=is_pending
        )
        for transaction_index, transaction in enumerate(block["transactions"])
    )
    block_with_transactions = assoc(block, "transactions", serialized_transactions)
    block_with_withdrawals = assoc(
        block_with_transactions,
        "withdrawals",
        block["withdrawals"],
    )
    return block_with_withdrawals


def serialize_transaction_as_hash(transaction, block, transaction_index, is_pending):
    return transaction["hash"]


def serialize_full_transaction(transaction, block, transaction_index, is_pending):
    if is_pending:
        block_number = None
        block_hash = None
        transaction_index = None
    else:
        block_number = block["number"]
        block_hash = block["hash"]

    serialized_transaction = pipe(
        transaction,
        partial(assoc, key="block_number", value=block_number),
        partial(assoc, key="block_hash", value=block_hash),
        partial(assoc, key="transaction_index", value=transaction_index),
        partial(assoc, key="type", value=extract_transaction_type(transaction)),
    )

    if int(serialized_transaction["type"], 16) > LEGACY_TX_TYPE:
        # if the transaction is not a legacy (type=0) transaction, `y_parity` is
        # the correct signature field but clients commonly return both `v` and
        # `y_parity`.
        serialized_transaction = assoc(
            serialized_transaction,
            "y_parity",
            transaction["v"],
        )

    if "gas_price" in transaction:
        return serialized_transaction
    else:
        # TODO: Sometime in 2022 the inclusion of gas_price may be removed from
        #  dynamic fee transactions and we can get rid of this behavior.
        #  https://github.com/ethereum/execution-specs/pull/251
        gas_price = (
            transaction["max_fee_per_gas"]
            if is_pending
            else calculate_effective_gas_price(transaction, block)
        )
        return assoc(serialized_transaction, "gas_price", gas_price)


def serialize_receipt(receipt, transaction, block, transaction_index, is_pending):
    if is_pending:
        block_number = None
        block_hash = None
        transaction_index = None
    else:
        block_number = block["number"]
        block_hash = block["hash"]

    return pipe(
        receipt,
        partial(assoc, key="block_number", value=block_number),
        partial(assoc, key="block_hash", value=block_hash),
        partial(
            assoc,
            key="effective_gas_price",
            value=(calculate_effective_gas_price(transaction, block)),
        ),
        partial(assoc, key="from", value=to_bytes(transaction["from"])),
        partial(assoc, key="state_root", value=b"\x00"),
        partial(assoc, key="status", value=0),
        partial(assoc, key="to", value=transaction["to"]),
        partial(assoc, key="transaction_index", value=transaction_index),
        partial(assoc, key="type", value=extract_transaction_type(transaction)),
    )
