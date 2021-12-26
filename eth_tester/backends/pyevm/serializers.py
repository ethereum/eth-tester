from eth_utils import to_int

import rlp

from toolz import (
    merge,
)

from .utils import is_supported_pyevm_version_available


if is_supported_pyevm_version_available():
    from eth.rlp.transactions import BaseTransaction
    from eth.vm.forks.berlin.transactions import TypedTransaction
    from eth.vm.forks.london.blocks import LondonBlock
else:
    BaseTransaction = None
    TypedTransaction = None

from eth_tester.exceptions import ValidationError
from eth_tester.utils.address import (
    generate_contract_address,
)
from eth_tester.utils.encoding import (
    int_to_32byte_big_endian,
)


def pad32(value):
    return value.rjust(32, b'\x00')


def serialize_block(block, full_transaction, is_pending):
    if full_transaction:
        transaction_serializer = serialize_transaction
    else:
        transaction_serializer = serialize_transaction_hash

    transactions = [
        transaction_serializer(block, transaction, index, is_pending)
        for index, transaction
        in enumerate(block.transactions)
    ]

    if block.uncles:
        raise NotImplementedError("Uncle serialization has not been implemented")

    block_info = {
        "number": block.header.block_number,
        "hash": block.header.hash,
        "parent_hash": block.header.parent_hash,
        "nonce": block.header.nonce,
        "sha3_uncles": block.header.uncles_hash,
        "logs_bloom": block.header.bloom,
        "transactions_root": block.header.transaction_root,
        "receipts_root": block.header.receipt_root,
        "state_root": block.header.state_root,
        "miner": block.header.coinbase,
        "difficulty": block.header.difficulty,
        "total_difficulty": block.header.difficulty,  # TODO: actual total difficulty
        "size": len(rlp.encode(block)),
        "extra_data": pad32(block.header.extra_data),
        "gas_limit": block.header.gas_limit,
        "gas_used": block.header.gas_used,
        "timestamp": block.header.timestamp,
        "transactions": transactions,
        "uncles": [uncle.hash for uncle in block.uncles],
    }

    # blocks after London should inherit from LondonBlock,
    # so this should also work for future hard forks
    if isinstance(block, LondonBlock):
        base_fee = block.header.base_fee_per_gas
        block_info.update({"base_fee_per_gas": base_fee})

    return block_info


def serialize_transaction_hash(block, transaction, transaction_index, is_pending):
    return transaction.hash


def serialize_transaction(block, transaction, transaction_index, is_pending):
    txn_type = _extract_transaction_type(transaction)

    common_transaction_params = {
        "type": txn_type,
        "hash": transaction.hash,
        "nonce": transaction.nonce,
        "block_hash": None if is_pending else block.hash,
        "block_number": None if is_pending else block.number,
        "transaction_index": None if is_pending else transaction_index,
        "from": transaction.sender,
        "to": transaction.to,
        "value": transaction.value,
        "gas": transaction.gas,
        "data": transaction.data,
        "r": transaction.r,
        "s": transaction.s,
        "v": transaction.v if _field_in_transaction(transaction, 'v') else transaction.y_parity,
    }
    if _field_in_transaction(transaction, 'gas_price'):
        type_specific_params = {'gas_price': transaction.gas_price}

        if _field_in_transaction(transaction, 'access_list'):
            # access list transaction
            type_specific_params = merge(
                type_specific_params,
                {
                    'chain_id': transaction.chain_id,
                    'access_list': transaction.access_list or (),
                }
            )
    elif any(_field_in_transaction(transaction, _) for _ in (
        'max_fee_per_gas' and 'max_priority_fee_per_gas'
    )):
        # dynamic fee transaction
        type_specific_params = {
            'chain_id': transaction.chain_id,
            'max_fee_per_gas': transaction.max_fee_per_gas,
            'max_priority_fee_per_gas': transaction.max_priority_fee_per_gas,
            'access_list': transaction.access_list or (),

            # TODO: Sometime in 2022 the inclusion of gas_price may be removed from dynamic fee
            #  transactions and we can get rid of this behavior.
            #  https://github.com/ethereum/execution-specs/pull/251
            'gas_price': (
                transaction.max_fee_per_gas if is_pending
                else _calculate_effective_gas_price(transaction, block, txn_type)
            ),
        }
    else:
        raise ValidationError('Invariant: code path should be unreachable')

    return merge(common_transaction_params, type_specific_params)


def _field_in_transaction(transaction, field):
    """
    There are many different classes of transactions, we have to be able to search for a
    particular field depending on the type of transaction - from dict, to legacy transaction
    classes, to *TypedTransaction classes.
    """
    if isinstance(transaction, dict):
        return field in transaction
    elif isinstance(transaction, BaseTransaction):
        # all legacy transactions inherit from BaseTransaction
        return field in transaction.as_dict()
    elif isinstance(transaction, TypedTransaction):
        # all typed transactions inherit from TypedTransaction
        return hasattr(transaction, field)


def serialize_transaction_receipt(
    block,
    receipts,
    transaction,
    transaction_index,
    is_pending
):
    receipt = receipts[transaction_index]
    _txn_type = _extract_transaction_type(transaction)
    state_root = receipt.state_root

    if transaction.to == b'':
        contract_addr = generate_contract_address(
            transaction.sender,
            transaction.nonce,
        )
    else:
        contract_addr = None

    if transaction_index == 0:
        origin_gas = 0
    else:
        origin_gas = receipts[transaction_index - 1].gas_used

    return {
        "block_hash": None if is_pending else block.hash,
        "block_number": None if is_pending else block.number,
        "contract_address": contract_addr,
        "cumulative_gas_used": receipt.gas_used,
        "effective_gas_price": _calculate_effective_gas_price(transaction, block, _txn_type),
        "from": transaction.sender,
        "gas_used": receipt.gas_used - origin_gas,
        "logs": [
            serialize_log(block, transaction, transaction_index, log, log_index, is_pending)
            for log_index, log in enumerate(receipt.logs)
        ],
        'state_root': state_root,
        "status": to_int(state_root),
        "to": transaction.to,
        "transaction_hash": transaction.hash,
        "transaction_index": None if is_pending else transaction_index,
        'type': _txn_type,
    }


def serialize_log(block, transaction, transaction_index, log, log_index, is_pending):
    return {
        "type": "pending" if is_pending else "mined",
        "log_index": log_index,
        "transaction_index": None if is_pending else transaction_index,
        "transaction_hash": transaction.hash,
        "block_hash": None if is_pending else block.hash,
        "block_number": None if is_pending else block.number,
        "address": log.address,
        "data": log.data,
        "topics": [int_to_32byte_big_endian(topic) for topic in log.topics],
    }


def _extract_transaction_type(transaction):
    if isinstance(transaction, TypedTransaction):
        try:
            transaction.gas_price  # noqa: 201
            return '0x1'
        except AttributeError:
            return '0x2'
    return '0x0'  # legacy transactions being '0x0' taken from current geth version v1.10.10


def _calculate_effective_gas_price(transaction, block, transaction_type):
    return (
        min(
            transaction.max_fee_per_gas,
            transaction.max_priority_fee_per_gas + block.header.base_fee_per_gas
        )
        if transaction_type == '0x2'
        else transaction.gas_price
    )
