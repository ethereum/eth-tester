class BaseChainBackend(object):
    #
    # Mining
    #
    def mine_blocks(self, num_blocks=1, coinbase=None):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Accounts
    #
    def get_accounts(self):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Chain data
    #
    def get_block_by_number(self, block_number):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_block_by_hash(self, block_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_latest_block(self):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_transaction_by_hash(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_transaction_receipt(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Account state
    #
    def get_nonce(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_balance(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_code(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Transactions
    #
    def send_transaction(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    def estimate_gas(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    def call(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Filters
    #
    def create_block_filter(self, *args, **kwargs):
        raise NotImplementedError("Must be implemented by subclasses")

    def create_pending_transaction_filter(self, *args, **kwargs):
        raise NotImplementedError("Must be implemented by subclasses")

    def create_logfilter(self, from_block=None, to_block=None, address=None, topics=None):
        raise NotImplementedError("Must be implemented by subclasses")

    def delete_filter(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_only_filter_changes(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_all_filter_logs(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")
