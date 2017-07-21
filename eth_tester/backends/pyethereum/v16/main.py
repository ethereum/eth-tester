from __future__ import absolute_import

import pkg_resources

from semantic_version import (
    Spec,
)

from eth_utils import (
    remove_0x_prefix,
    to_checksum_address,
    to_tuple,
)

from eth_tester.backends.base import BaseChainBackend
from eth_tester.backends.pyethereum.utils import (
    get_pyethereum_version,
    is_pyethereum16_available,
)

from .normalizers import (
    normalize_transaction,
)
from .serializers import (
    serialize_transaction_receipt,
    serialize_transaction,
    serialize_transaction_hash,
    serialize_block,
)
from .validation import (
    validate_transaction,
)


#
# Internal getters for EVM objects
#
def _get_transaction_by_hash(evm, transaction_hash):
    for block in reversed(evm.blocks):
        for index, candidate in enumerate(block.get_transaction_hashes()):
            if candidate == transaction_hash:
                transaction = block.transaction_list[index]
                return block, transaction, index
    else:
        raise ValueError("Transaction not found")


def _get_block_by_number(evm, block_number="latest"):
    if block_number == "latest":
        if len(evm.blocks) == 0:
            raise ValueError("Chain has no blocks")
        elif len(evm.blocks) == 1:
            return evm.blocks[0]
        else:
            return evm.blocks[-2]
    elif block_number == "earliest":
        return evm.blocks[0]
    elif block_number == "pending":
        return evm.block
    else:
        if block_number >= len(evm.blocks):
            raise ValueError("Block number is longer than current chain.")
        return evm.blocks[block_number]


def _get_block_by_hash(evm, block_hash):
    block_hash = block_hash

    for block in reversed(evm.blocks):
        if block.hash == block_hash:
            return block
    else:
        raise ValueError("Could not find block for provided hash")


def _send_evm_transaction(tester_module, evm, transaction):
    try:
        # record the current gas price so that it can be reset after sending
        # the transaction.
        pre_transaction_gas_price = tester_module.gas_price
        pre_transaction_gas_limit = tester_module.gas_limit
        # set the evm gas price to the one specified by the transaction.
        tester_module.gas_price = transaction['gas_price']
        tester_module.gas_limit = transaction['gas']

        # get the private key of the sender.
        sender = tester_module.keys[tester_module.accounts.index(transaction['from'])]

        output = evm.send(
            sender=sender,
            to=transaction['to'],
            value=transaction['value'],
            evmdata=transaction['data'],
        )
    finally:
        # revert the tester_module gas price back to the original value.
        tester_module.gas_price = pre_transaction_gas_price
        tester_module.gas_limit = pre_transaction_gas_limit

    return output


class PyEthereum16Backend(BaseChainBackend):
    tester_module = None

    def __init__(self):
        if not is_pyethereum16_available():
            version = get_pyethereum_version()
            if version is None:
                raise pkg_resources.DistributionNotFound(
                    "The `ethereum` package is not available.  The "
                    "`PyEthereum16Backend` requires a 1.6.x version of the "
                    "ethereum package to be installed."
                )
            elif version not in Spec('>=1.6.0,<1.7.0'):
                raise pkg_resources.DistributionNotFound(
                    "The `PyEthereum16Backend` requires a 1.6.x version of the "
                    "`ethereum` package.  Found {0}".format(version)
                )
        from ethereum import tester
        self.tester_module = tester
        self.evm = tester.state()

    #
    # Mining
    #
    def mine_blocks(self, num_blocks=1, coinbase=None):
        if coinbase is None:
            coinbase = self.tester_module.DEFAULT_ACCOUNT
        self.evm.mine(
            number_of_blocks=num_blocks,
            coinbase=coinbase,
        )

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        for account in self.tester_module.accounts:
            yield to_checksum_address(account)

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash

        block = _get_block_by_number(
            self.evm,
            block_number,
            transaction_serialize_fn,
        )
        return serialize_block(block)

    def get_block_by_hash(self, block_hash, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash

        block = _get_block_by_hash(
            self.evm,
            block_hash,
            transaction_serialize_fn,
        )
        return serialize_block(block)

    def get_latest_block(self, full_transactions=False):
        if full_transactions:
            transaction_serialize_fn = serialize_transaction
        else:
            transaction_serialize_fn = serialize_transaction_hash

        return serialize_block(self.evm.block, transaction_serialize_fn)

    def get_transaction_by_hash(self, transaction_hash):
        block, transaction, transaction_index = _get_transaction_by_hash(
            self.evm,
            transaction_hash,
        )
        return serialize_transaction(block, transaction, transaction_index)

    def get_transaction_receipt(self, transaction_hash):
        block, transaction, transaction_index = _get_transaction_by_hash(
            self.evm,
            transaction_hash,
        )
        return serialize_transaction_receipt(block, transaction, transaction_index)

    #
    # Account state
    #
    def get_nonce(self, account, block_number=None):
        if block_number is not None:
            raise NotImplementedError("Not yet handled")
        block = self.evm.block
        return block.get_nonce(remove_0x_prefix(account))

    def get_balance(self, account, block_number=None):
        if block_number is not None:
            raise NotImplementedError("Not yet handled")
        block = self.evm.block
        return block.get_balance(remove_0x_prefix(account))

    def get_code(self, account, block_number=None):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Transactions
    #
    def send_transaction(self, transaction):
        validate_transaction(transaction)
        _send_evm_transaction(
            tester_module=self.tester_module,
            evm=self.evm,
            transaction=normalize_transaction(
                transaction,
                data=b'',
                value=0,
                gas_price=self.tester_module.gas_price,
            ),
        )
        return self.evm.last_tx.hash

    def estimate_gas(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    def call(self, transaction):
        raise NotImplementedError("Must be implemented by subclasses")

    #
    # Filters
    #
    def new_block_filter(self, *args, **kwargs):
        raise NotImplementedError("Must be implemented by subclasses")

    def new_pending_transaction_filter(self, *args, **kwargs):
        raise NotImplementedError("Must be implemented by subclasses")

    def create_filter(self, from_block=None, to_block=None, address=None, topics=None):
        raise NotImplementedError("Must be implemented by subclasses")

    def delete_filter(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_filter_changes(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")

    def get_filter_logs(self, filter_id):
        raise NotImplementedError("Must be implemented by subclasses")
