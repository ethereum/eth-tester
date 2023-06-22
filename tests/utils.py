ZERO_32BYTES = b"\x00" * 32
ZERO_ADDRESS = b"\x00" * 20


def make_receipt(
    transaction_hash=ZERO_32BYTES,
    transaction_index=0,
    block_number=0,
    block_hash=ZERO_32BYTES,
    cumulative_gas_used=0,
    _from=ZERO_ADDRESS,
    gas_used=21000,
    effective_gas_price=1000000000,
    contract_address=None,
    logs=None,
    state_root=b"\x00",
    status=0,
    to=ZERO_ADDRESS,
    _type="0x0",
):
    return {
        "transaction_hash": transaction_hash,
        "transaction_index": transaction_index,
        "block_number": block_number,
        "block_hash": block_hash,
        "cumulative_gas_used": cumulative_gas_used,
        "from": _from,
        "gas_used": gas_used,
        "effective_gas_price": effective_gas_price,
        "contract_address": contract_address,
        "logs": logs or [],
        "state_root": state_root,
        "status": status,
        "to": to,
        "type": _type,
    }
