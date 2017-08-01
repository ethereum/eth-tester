class BaseValidationBackend(object):
    def validate_timestamp(self, value):
        raise NotImplementedError("must be implemented by subclasses")

    def validate_block_number(self, value):
        raise NotImplementedError("must be implemented by subclasses")

    def validate_block_hash(self, value):
        raise NotImplementedError("must be implemented by subclasses")

    def validate_transaction_hash(self, value):
        raise NotImplementedError("must be implemented by subclasses")

    def validate_filter_id(self, value):
        raise NotImplementedError("must be implemented by subclasses")

    def validate_filter_params(self, from_block, to_block, address, topics):
        raise NotImplementedError("must be implemented by subclasses")
