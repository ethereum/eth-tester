from eth_utils import (
    is_address,
)

from eth_tester.exceptions import (
    ValidationError,
)


TRANSACTION_KEYS = {
    'from',
    'to',
    'gas',
    'gas_price',
    'value',
    'data',
}


def validate_transaction(transaction):
    # TODO: refactor this so that it's not gross.
    if 'from' not in transaction:
        raise ValidationError("Transactions must specify a 'from' address")
    elif not is_address(transaction['from']):
        raise ValidationError("transaction[from]: Unrecognized address format: {0}".format(
            transaction['from'],
        ))
    elif 'to' in transaction and not is_address(transaction['to']):
        raise ValidationError("transaction[to]: Unrecognized address format: {0}".format(
            transaction['to'],
        ))

    extra_keys = set(transaction.keys()).difference(TRANSACTION_KEYS)
    if extra_keys:
        raise ValidationError(
            "Transactions may only include the keys {0}.  The following extra "
            "keys were found: {1}".format(
                ",".join(sorted(TRANSACTION_KEYS)),
                ",".join(sorted(extra_keys)),
            )
        )
