def _make_transaction(hash=ZERO_32BYTES,
                      nonce=0,
                      block_hash=ZERO_32BYTES,
                      block_number=0,
                      transaction_index=0,
                      _from=ZERO_ADDRESS,
                      to=ZERO_ADDRESS,
                      value=0,
                      gas=21000,
                      gas_price=1,
                      data=b'',
                      v=0,
                      r=0,
                      s=0):
    return {
        "hash": hash,
        "nonce": nonce,
        "block_hash": block_hash,
        "block_number": block_number,
        "transaction_index": transaction_index,
        "from": _from,
        "to": to,
        "value": value,
        "gas": gas,
        "gas_price": gas_price,
        "data": data,
        "v": v,
        "r": r,
        "s": s,
    }




def _make_log(_type="mined",
              log_index=0,
              transaction_index=0,
              transaction_hash=ZERO_32BYTES,
              block_hash=ZERO_32BYTES,
              block_number=0,
              address=ZERO_ADDRESS,
              data=b'',
              topics=None):
    return {
        "type": _type,
        "log_index": log_index,
        "transaction_index": transaction_index,
        "transaction_hash": transaction_hash,
        "block_hash": block_hash,
        "block_number": block_number,
        "address": address,
        "data": data,
        "topics": topics or [],
    }




def _make_receipt(transaction_hash=ZERO_32BYTES,
                  transaction_index=0,
                  block_number=0,
                  block_hash=ZERO_32BYTES,
                  cumulative_gas_used=0,
                  gas_used=21000,
                  contract_address=None,
                  logs=None):
    return {
        "transaction_hash": transaction_hash,
        "transaction_index": transaction_index,
        "block_number": block_number,
        "block_hash": block_hash,
        "cumulative_gas_used": cumulative_gas_used,
        "gas_used": gas_used,
        "contract_address": contract_address,
        "logs": logs or [],
    }


GENESIS_NONCE = b'\x00\x00\x00\x00\x00\x00\x00*'  # 42 encoded as big-endian-integer
BLANK_ROOT_HASH = b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n\x5bH\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!'  # noqa: E501
EMPTY_UNCLE_HASH = b'\x1d\xccM\xe8\xde\xc7]z\xab\x85\xb5g\xb6\xcc\xd4\x1a\xd3\x12E\x1b\x94\x8at\x13\xf0\xa1B\xfd@\xd4\x93G'  # noqa: E501


def make_genesis_block():
    return {
        "number": 0,
        "hash": ZERO_32BYTES,
        "parent_hash": ZERO_32BYTES,
        "nonce": GENESIS_NONCE,
        "sha3_uncles": EMPTY_UNCLE_HASH,
        "logs_bloom": 0,
        "transactions_root": BLANK_ROOT_HASH,
        "state_root": BLANK_ROOT_HASH,
        "miner": ZERO_ADDRESS,
        "difficulty": 131072,
        "total_difficulty": 131072,
        "size": 0,
        "extra_data": ZERO_32BYTES,
        "gas_limit": 3141592,
        "gas_used": 0,
        "timestamp": int(time.time()),
        "transactions": [],
        "uncles": [],
    }


@to_dict
def make_block_from_parent(parent_block, **overrides):
    if 'number' in overrides:
        yield 'number', overrides['number']
    else:
        yield 'number', parent_block['number'] + 1

    if 'hash' in overrides:
        yield 'hash', overrides['hash']
    else:
        yield 'hash', keccak(parent_block['hash'])

    if 'parent_hash' in overrides:
        yield 'parent_hash', overrides['parent_hash']
    else:
        yield 'parent_hash', parent_block['hash']

    if 'nonce' in overrides:
        yield 'nonce', overrides['nonce']
    else:
        yield 'nonce', parent_block['nonce']

    if 'sha3_uncles' in overrides:
        yield 'sha3_uncles', overrides['sha3_uncles']
    else:
        yield 'sha3_uncles', EMPTY_UNCLE_HASH

    if 'logs_bloom' in overrides:
        yield 'logs_bloom', overrides['logs_bloom']
    else:
        yield 'logs_bloom', 0

    if 'transaction_root' in overrides:
        yield 'transaction_root', overrides['transaction_root']
    else:
        yield 'transaction_root', BLANK_ROOT_HASH

    if 'state_root' in overrides:
        yield 'state_root', overrides['state_root']
    else:
        yield 'state_root', BLANK_ROOT_HASH

    if 'miner' in overrides:
        yield 'miner', overrides['miner']
    else:
        yield 'miner', ZERO_ADDRESS

    if 'difficulty' in overrides:
        difficulty = overrides['difficulty']
    else:
        difficulty = 131072
    yield 'difficulty', difficulty

    if 'total_difficulty' in overrides:
        yield 'total_difficulty', overrides['total_difficulty']
    else:
        yield 'total_difficulty', parent_block['difficulty'] + difficulty

    if 'size' in overrides:
        yield 'size', overrides['size']
    else:
        yield 'size', 0

    if 'extra_data' in overrides:
        yield 'extra_data', overrides['extra_data']
    else:
        yield 'extra_data', ZERO_32BYTES

    if 'gas_limit' in overrides:
        yield 'gas_limit', overrides['gas_limit']
    else:
        yield 'gas_limit', parent_block['gas_limit']

    if 'gas_used' in overrides:
        yield 'gas_used', overrides['gas_used']
    else:
        yield 'gas_used', 0

    if 'timestamp' in overrides:
        yield 'timestamp', overrides['timestamp']
    else:
        yield 'timestamp', parent_block['timestamp'] + 15

    if 'transactions' in overrides:
        yield 'transactions', overrides['transactions']
    else:
        yield 'transactions', []

    if 'uncles' in overrides:
        yield 'uncles', overrides['uncles']
    else:
        yield 'uncles', []
