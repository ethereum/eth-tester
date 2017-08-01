from cytoolz import (
    identity,
)

from eth_utils import (
    to_tuple,
    encode_hex,
    to_checksum_address,
)

from .base import (
    BaseNormalizer,
)


class PythonicNormalizer(BaseNormalizer):
    normalize_block_hash = staticmethod(encode_hex)

    def normalize_block(self, block):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_log_entry(self, log_entry):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_transaction(self, transaction):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_receipt(self, receipt):
        raise NotImplementedError("must be implemented by subclasses")

    @to_tuple
    def normalize_accounts(self, accounts):
        for account in accounts:
            yield to_checksum_address(account)

    normalize_balance = staticmethod(identity)
    normalize_code = staticmethod(identity)
    normalize_nonce = staticmethod(identity)
    normalize_return_data = staticmethod(encode_hex)
    normalize_gas_estimate = staticmethod(identity)
