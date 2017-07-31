class BaseValidationBackend(object):
    def validate_timestamp(self, value):
        raise NotImplementedError("must be implemented by subclasses")

    def validate_block_number(self, value):
        raise NotImplementedError("must be implemented by subclasses")

    def validate_block_hash(self, value):
        raise NotImplementedError("must be implemented by subclasses")

    def validate_transaction_hash(self, value):
        raise NotImplementedError("must be implemented by subclasses")
