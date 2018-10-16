from eth_utils.toolz import (
    assoc,
    partial,
    pipe,
)


def serialize_block(block, transaction_serializer, is_pending):
    serialized_transactions = tuple(
        transaction_serializer(transaction, block, transaction_index, is_pending=is_pending)
        for transaction_index, transaction
        in enumerate(block['transactions'])
    )
    return assoc(block, 'transactions', serialized_transactions)


def serialize_transaction_as_hash(transaction, block, transaction_index, is_pending):
    return transaction['hash']


def serialize_full_transaction(transaction, block, transaction_index, is_pending):
    if is_pending:
        block_number = None
        block_hash = None
        transaction_index = None
    else:
        block_number = block['number']
        block_hash = block['hash']

    return pipe(
        transaction,
        partial(assoc, key='block_number', value=block_number),
        partial(assoc, key='block_hash', value=block_hash),
        partial(assoc, key='transaction_index', value=transaction_index),
    )


def serialize_receipt(transaction, block, transaction_index, is_pending):
    if is_pending:
        block_number = None
        block_hash = None
        transaction_index = None
    else:
        block_number = block['number']
        block_hash = block['hash']

    return pipe(
        transaction,
        partial(assoc, key='block_number', value=block_number),
        partial(assoc, key='block_hash', value=block_hash),
        partial(assoc, key='transaction_index', value=transaction_index),
        partial(assoc, key='state_root', value=b'\x00'),
    )
