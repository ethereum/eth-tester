from cytoolz import (
    identity,
)

from eth_utils import (
    decode_hex,
    encode_hex,
    to_canonical_address,
)

from .base import (
    BaseNormalizer,
)
from .inbound import (
    normalize_filter_params as normalize_inbound_filter_params,
    normalize_log_entry as normalize_inbound_log_entry,
    normalize_transaction as normalize_inbound_transaction,
)
from .outbound import (
    normalize_accounts as normalize_outbound_accounts,
    normalize_block as normalize_outbound_block,
    normalize_log_entry as normalize_outbound_log_entry,
    normalize_receipt as normalize_outbound_receipt,
    normalize_transaction as normalize_outbound_transaction,
)


class DefaultNormalizer(BaseNormalizer):
    #
    # Inbound
    #
    normalize_inbound_account = staticmethod(to_canonical_address)
    normalize_inbound_block_hash = staticmethod(decode_hex)
    normalize_inbound_block_number = staticmethod(identity)
    normalize_inbound_filter_id = staticmethod(identity)
    normalize_inbound_filter_params = staticmethod(normalize_inbound_filter_params)
    normalize_inbound_log_entry = staticmethod(normalize_inbound_log_entry)
    normalize_inbound_timestamp = staticmethod(identity)
    normalize_inbound_transaction = staticmethod(normalize_inbound_transaction)
    normalize_inbound_transaction_hash = staticmethod(decode_hex)

    # Outbound
    normalize_outbound_accounts = staticmethod(normalize_outbound_accounts)
    normalize_outbound_balance = staticmethod(identity)
    normalize_outbound_block_hash = staticmethod(encode_hex)
    normalize_outbound_block = staticmethod(normalize_outbound_block)
    normalize_outbound_code = staticmethod(encode_hex)
    normalize_outbound_filter_id = staticmethod(identity)
    normalize_outbound_log_entry = staticmethod(normalize_outbound_log_entry)
    normalize_outbound_gas_estimate = staticmethod(identity)
    normalize_outbound_nonce = staticmethod(identity)
    normalize_outbound_receipt = staticmethod(normalize_outbound_receipt)
    normalize_outbound_return_data = staticmethod(encode_hex)
    normalize_outbound_transaction = staticmethod(normalize_outbound_transaction)
    normalize_outbound_transaction_hash = staticmethod(encode_hex)
