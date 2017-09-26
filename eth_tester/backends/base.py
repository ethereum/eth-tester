class BaseChainBackend(object):
    #
    # Snapshot API
    #
    def take_snapshot(self):
        raise NotImplementedError("Must be implemented by subclasses")

    def revert_to_snapshot(self, snapshot):
        raise NotImplementedError("Must be implemented by subclasses")

    def reset_to_genesis(self):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Fork block numbers
    #
    def set_fork_block(self, fork_name, fork_block):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_fork_block(self, fork_name):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Meta
    #
    def time_travel(self, to_timestamp):
        raise NotImplementedError("Must be implemented by subclasses")

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

    def add_account(self, private_key):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transaction=True):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_block_by_hash(self, block_hash, full_transaction=True):
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

    def call(self, transaction, block_number="latest"):
        raise NotImplementedError("Must be implemented by subclasses")
