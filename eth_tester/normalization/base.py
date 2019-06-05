class BaseNormalizer:
    #
    # Inbound
    #
    def normalize_inbound_account(self, account):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_block_hash(self, block_hash):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_block_number(self, block_number):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_filter_id(self, filter_id):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_filter_params(self, from_block, to_block, address, topics):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_log_entry(self, log_entry):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_private_key(self, private_key):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_raw_transaction(self, raw_transaction_hex):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_timestamp(self, timestamp):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_transaction(self, transaction):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_inbound_transaction_hash(self, transaction_hash):
        raise NotImplementedError("must be implemented by subclasses")

    # Outbound
    def normalize_outbound_account(self, accounts):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_account_list(self, account_list):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_balance(self, account):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_block_hash(self, block_hash):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_block(self, block):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_code(self, account):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_filter_id(self, filter_id):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_log_entry(self, log_entry):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_gas_estimate(self, gas_estimate):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_nonce(self, account):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_receipt(self, receipt):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_return_data(self, data):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_transaction(self, transaction):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_outbound_transaction_hash(self, transaction_hash):
        raise NotImplementedError("must be implemented by subclasses")
