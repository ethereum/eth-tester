from abc import (
    ABCMeta,
    abstractmethod,
)


class BaseChainBackend(metaclass=ABCMeta):
    #
    # Snapshot API
    #
    @abstractmethod
    def take_snapshot(self):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def revert_to_snapshot(self, snapshot):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def reset_to_genesis(self):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Meta
    #
    @abstractmethod
    def time_travel(self, to_timestamp):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Mining
    #
    @abstractmethod
    def mine_blocks(self, num_blocks=1, coinbase=None):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Accounts
    #
    @abstractmethod
    def get_accounts(self):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def add_account(self, private_key):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Chain data
    #
    @abstractmethod
    def get_block_by_number(self, block_number, full_transaction=True):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_block_by_hash(self, block_hash, full_transaction=True):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_transaction_by_hash(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_transaction_receipt(self, transaction_hash):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Account state
    #
    @abstractmethod
    def get_nonce(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_balance(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_code(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Transactions
    #
    @abstractmethod
    def send_transaction(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def send_signed_transaction(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def estimate_gas(self, transaction, block_number="latest"):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def call(self, transaction, block_number="latest"):
        raise NotImplementedError("Must be implemented by subclasses")
