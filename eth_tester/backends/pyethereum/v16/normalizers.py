from toolz.itertoolz import (
    concatv,
)
from toolz.functoolz import (
    identity,
)

from eth_utils import (
    to_dict,
    to_canonical_address,
    decode_hex,
)


TRANSACTION_NORMALIZERS = {
    'from': to_canonical_address,
    'to': to_canonical_address,
    'data': decode_hex,
}


@to_dict
def normalize_transaction(transaction, **defaults):
    for key in set(concatv(transaction.keys(), defaults.keys())):
        try:
            value = transaction[key]
        except KeyError:
            value = defaults[key]

        normalize_fn = TRANSACTION_NORMALIZERS.get(key, identity)
        yield key, normalize_fn(value)
