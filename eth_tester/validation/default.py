from __future__ import (
    absolute_import,
)

from .base import (
    BaseValidator,
)
from .common import (
    validate_uint256,
)
from .inbound import (
    validate_account as validate_inbound_account,
    validate_block_hash as validate_inbound_block_hash,
    validate_block_number as validate_inbound_block_number,
    validate_filter_id as validate_inbound_filter_id,
    validate_filter_params as validate_inbound_filter_params,
    validate_inbound_storage_slot as validate_inbound_storage_slot,
    validate_private_key as validate_inbound_private_key,
    validate_raw_transaction as validate_inbound_raw_transaction,
    validate_timestamp as validate_inbound_timestamp,
    validate_transaction as validate_inbound_transaction,
    validate_transaction_hash as validate_inbound_transaction_hash,
)
from .outbound import (
    validate_32_byte_string,
    validate_accounts as validate_outbound_accounts,
    validate_block as validate_outbound_block,
    validate_block_hash as validate_outbound_block_hash,
    validate_bytes as validate_outbound_bytes,
    validate_log_entry as validate_outbound_log_entry,
    validate_receipt as validate_outbound_receipt,
    validate_transaction as validate_outbound_transaction,
)


class DefaultValidator(BaseValidator):
    #
    # Inbound
    #
    validate_inbound_account = staticmethod(validate_inbound_account)
    validate_inbound_block_hash = staticmethod(validate_inbound_block_hash)
    validate_inbound_block_number = staticmethod(validate_inbound_block_number)
    validate_inbound_filter_id = staticmethod(validate_inbound_filter_id)
    validate_inbound_filter_params = staticmethod(validate_inbound_filter_params)
    validate_inbound_private_key = staticmethod(validate_inbound_private_key)
    validate_inbound_raw_transaction = staticmethod(validate_inbound_raw_transaction)
    validate_inbound_storage_slot = staticmethod(validate_inbound_storage_slot)
    validate_inbound_timestamp = staticmethod(validate_inbound_timestamp)
    validate_inbound_transaction = staticmethod(validate_inbound_transaction)
    validate_inbound_transaction_hash = staticmethod(validate_inbound_transaction_hash)

    #
    # Outbound
    #
    validate_outbound_accounts = staticmethod(validate_outbound_accounts)
    validate_outbound_balance = staticmethod(validate_uint256)
    validate_outbound_block = staticmethod(validate_outbound_block)
    validate_outbound_block_hash = staticmethod(validate_outbound_block_hash)
    validate_outbound_code = staticmethod(validate_outbound_bytes)
    validate_outbound_gas_estimate = staticmethod(validate_uint256)
    validate_outbound_nonce = staticmethod(validate_uint256)
    validate_outbound_log_entry = staticmethod(validate_outbound_log_entry)
    validate_outbound_receipt = staticmethod(validate_outbound_receipt)
    validate_outbound_return_data = staticmethod(validate_outbound_bytes)
    validate_outbound_storage = staticmethod(validate_uint256)
    validate_outbound_transaction = staticmethod(validate_outbound_transaction)
    validate_outbound_transaction_hash = staticmethod(validate_32_byte_string)
