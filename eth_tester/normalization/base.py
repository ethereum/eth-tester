class BaseNormalizer(object):
    def normalize_block_hash(self, block_hash):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_block(self, block):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_log_entry(self, log_entry):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_transaction(self, transaction):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_receipt(self, receipt):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_accounts(self, accounts):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_balance(self, account):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_code(self, account):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_nonce(self, account):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_return_data(self, data):
        raise NotImplementedError("must be implemented by subclasses")

    def normalize_gas_estimate(self, gas_estimate):
        raise NotImplementedError("must be implemented by subclasses")
