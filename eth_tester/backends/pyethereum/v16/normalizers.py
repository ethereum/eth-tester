from toolz.itertoolz import (
    concatv,
)
from toolz.functoolz import (
    identity,
)

from eth_utils import (
    force_bytes,
    to_dict,
    to_canonical_address,
)


TRANSACTION_NORMALIZERS = {
    'from': to_canonical_address,
    'to': to_canonical_address,
    'data': force_bytes,
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
