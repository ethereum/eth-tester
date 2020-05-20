from __future__ import absolute_import

import time

import rlp

from eth_abi import (
    decode_single
)
from eth_abi.exceptions import (
    DecodingError
)

from eth_utils import (
    encode_hex,
    int_to_big_endian,
    to_dict,
    to_tuple,
    to_wei,
    is_integer,
)

from eth_utils.decorators import replace_exceptions

from eth_utils.toolz import (
    assoc,
)

from eth_keys import KeyAPI

from eth_tester.exceptions import (
    BackendDistributionNotFound,
    BlockNotFound,
    TransactionFailed,
    TransactionNotFound,
    ValidationError,
)

from eth_tester.backends.base import BaseChainBackend
from eth_tester.backends.common import merge_genesis_overrides

from .serializers import (
    serialize_block,
    serialize_transaction,
    serialize_transaction_receipt,
)
from .utils import is_pyevm_available

if is_pyevm_available():
    from eth.constants import (
        GENESIS_PARENT_HASH,
    )
    from eth.exceptions import (
        HeaderNotFound as EVMHeaderNotFound,
        InvalidInstruction as EVMInvalidInstruction,
        Revert as EVMRevert,
    )
    from eth.vm.spoof import (
        SpoofTransaction as EVMSpoofTransaction
    )
else:
    EVMHeaderNotFound = None
    EVMInvalidInstruction = None
    EVMRevert = None
    GENESIS_PARENT_HASH = None


ZERO_ADDRESS = 20 * b'\x00'
ZERO_HASH32 = 32 * b'\x00'
EIP838_SIG = b'\x08\xc3y\xa0'

EMPTY_RLP_LIST_HASH = b'\x1d\xccM\xe8\xde\xc7]z\xab\x85\xb5g\xb6\xcc\xd4\x1a\xd3\x12E\x1b\x94\x8at\x13\xf0\xa1B\xfd@\xd4\x93G'  # noqa: E501
BLANK_ROOT_HASH = b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n\x5bH\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!'  # noqa: E501


GENESIS_BLOCK_NUMBER = 0
GENESIS_DIFFICULTY = 131072
GENESIS_GAS_LIMIT = 3141592
GENESIS_COINBASE = ZERO_ADDRESS
GENESIS_NONCE = b'\x00\x00\x00\x00\x00\x00\x00*'  # 42 encoded as big-endian-integer
GENESIS_MIX_HASH = ZERO_HASH32
GENESIS_EXTRA_DATA = b''
GENESIS_INITIAL_ALLOC = {}


MINIMUM_GAS_ESTIMATE = 30000
# A buffer of 1.1 would mean allocate 10% more gas than estimated
GAS_ESTIMATE_BUFFER = 1.5


def get_default_account_state(overrides=None):
    default_account_state = {
        'balance': to_wei(1000000, 'ether'),
        'storage': {},
        'code': b'',
        'nonce': 0,
    }
    if overrides is not None:
        account_state = merge_genesis_overrides(defaults=default_account_state,
                                                overrides=overrides)
    else:
        account_state = default_account_state
    return account_state


@to_tuple
def get_default_account_keys(quantity=None):
    keys = KeyAPI()
    quantity = quantity or 10
    for i in range(1, quantity+1):
        pk_bytes = int_to_big_endian(i).rjust(32, b'\x00')
        private_key = keys.PrivateKey(pk_bytes)
        yield private_key


@to_dict
def generate_genesis_state_for_keys(account_keys, overrides=None):
    for private_key in account_keys:
        account_state = get_default_account_state(overrides=overrides)
        yield private_key.public_key.to_canonical_address(), account_state


def get_default_genesis_params(overrides=None):
    default_genesis_params = {
        "bloom": 0,
        "coinbase": GENESIS_COINBASE,
        "difficulty": GENESIS_DIFFICULTY,
        "extra_data": GENESIS_EXTRA_DATA,
        "gas_limit": GENESIS_GAS_LIMIT,
        "gas_used": 0,
        "mix_hash": GENESIS_MIX_HASH,
        "nonce": GENESIS_NONCE,
        "block_number": GENESIS_BLOCK_NUMBER,
        "parent_hash": GENESIS_PARENT_HASH,
        "receipt_root": BLANK_ROOT_HASH,
        "timestamp": int(time.time()),
        "transaction_root": BLANK_ROOT_HASH,
        "uncles_hash": EMPTY_RLP_LIST_HASH
    }
    if overrides is not None:
        genesis_params = merge_genesis_overrides(default_genesis_params, overrides=overrides)
    else:
        genesis_params = default_genesis_params
    return genesis_params


def setup_tester_chain(
        genesis_params=None,
        genesis_state=None,
        num_accounts=None,
        vm_configuration=None):

    from eth.chains.base import MiningChain
    from eth.consensus import (
        NoProofConsensus,
        ConsensusApplier,
    )
    from eth.db import get_db_backend

    if vm_configuration is None:
        from eth.vm.forks.muir_glacier import MuirGlacierVM
        no_proof_vms = ((0, MuirGlacierVM.configure(consensus_class=NoProofConsensus)),)
    else:
        consensus_applier = ConsensusApplier(NoProofConsensus)
        no_proof_vms = consensus_applier.amend_vm_configuration(vm_configuration)

    class MainnetTesterNoProofChain(MiningChain):
        vm_configuration = no_proof_vms

        def create_header_from_parent(self, parent_header, **header_params):
            # Keep the gas limit constant
            return super().create_header_from_parent(
                parent_header,
                **assoc(header_params, 'gas_limit', parent_header.gas_limit)
            )

    if genesis_params is None:
        genesis_params = get_default_genesis_params()

    if genesis_state:
        num_accounts = len(genesis_state)

    account_keys = get_default_account_keys(quantity=num_accounts)

    if genesis_state is None:
        genesis_state = generate_genesis_state_for_keys(account_keys)

    base_db = get_db_backend()

    chain = MainnetTesterNoProofChain.from_genesis(base_db, genesis_params, genesis_state)
    return account_keys, chain


def _get_block_by_number(chain, block_number):
    if block_number == "latest":
        head_block = chain.get_block()
        return chain.get_canonical_block_by_number(max(0, head_block.number - 1))
    elif block_number == "earliest":
        return chain.get_canonical_block_by_number(0)
    elif block_number == "pending":
        return chain.get_block()
    elif is_integer(block_number):
        head_block = chain.get_block()
        if block_number == head_block.number:
            return head_block
        elif block_number < head_block.number:
            return chain.get_canonical_block_by_number(block_number)

    # fallback
    raise BlockNotFound(f"No block found for block number: {block_number}")


def _get_block_by_hash(chain, block_hash):
    block = chain.get_block_by_hash(block_hash)

    if block.number >= chain.get_block().number:
        raise BlockNotFound(f"No block found for block hash: {block_hash}")

    block_at_height = chain.get_canonical_block_by_number(block.number)
    if block != block_at_height:
        raise BlockNotFound(f"No block found for block hash: {block_hash}")

    return block


def _get_transaction_by_hash(chain, transaction_hash):
    head_block = chain.get_block()
    for index, transaction in enumerate(head_block.transactions):
        if transaction.hash == transaction_hash:
            return head_block, transaction, index
    for block_number in range(head_block.number - 1, -1, -1):
        # TODO: the chain should be able to look these up directly by hash...
        block = chain.get_canonical_block_by_number(block_number)
        for index, transaction in enumerate(block.transactions):
            if transaction.hash == transaction_hash:
                return block, transaction, index
    else:
        raise TransactionNotFound(
            "No transaction found for transaction hash: {}".format(
                encode_hex(transaction_hash)
            )
        )


def _execute_and_revert_transaction(chain, transaction, block_number="latest"):
    vm = _get_vm_for_block_number(chain, block_number)

    state = vm.state
    snapshot = state.snapshot()
    computation = state.apply_transaction(transaction)
    state.revert(snapshot)
    return computation


def _get_vm_for_block_number(chain, block_number):
    block = _get_block_by_number(chain, block_number)
    vm = chain.get_vm(at_header=block.header)
    return vm


class PyEVMBackend(BaseChainBackend):
    chain = None

    def __init__(self, genesis_parameters=None, genesis_state=None, vm_configuration=None):
        """
        :param vm_configuration: The tuple of virtual machines defining a chain schedule as
            used in py-evm's :attr:`eth.chains.base.Chain.vm_configuration`. (at author time, a
            series of block numbers and virtual machines)
        """
        if not is_pyevm_available():
            raise BackendDistributionNotFound(
                "The `py-evm` package is not available.  The "
                "`PyEVMBackend` requires py-evm to be installed and importable. "
                "Please install the `py-evm` library."
            )

        self.account_keys = None  # set below
        accounts = len(genesis_state) if genesis_state else None
        self.reset_to_genesis(genesis_parameters, genesis_state, accounts, vm_configuration)

    #
    # Genesis
    #

    @staticmethod
    def _generate_genesis_params(overrides=None):
        return get_default_genesis_params(overrides=overrides)

    @staticmethod
    def _generate_genesis_state(overrides=None, num_accounts=None):
        account_keys = get_default_account_keys(quantity=num_accounts)
        return generate_genesis_state_for_keys(account_keys=account_keys, overrides=overrides)

    def reset_to_genesis(self,
                         genesis_params=None,
                         genesis_state=None,
                         num_accounts=None,
                         vm_configuration=None):
        self.account_keys, self.chain = setup_tester_chain(
            genesis_params,
            genesis_state,
            num_accounts,
            vm_configuration,
        )

    #
    # Private Accounts API
    #
    @property
    def _key_lookup(self):
        return {
            key.public_key.to_canonical_address(): key
            for key
            in self.account_keys
        }

    #
    # Snapshot API
    #
    def take_snapshot(self):
        block = _get_block_by_number(self.chain, 'latest')
        return block.hash

    def revert_to_snapshot(self, snapshot):
        block = self.chain.get_block_by_hash(snapshot)
        chaindb = self.chain.chaindb

        chaindb._set_as_canonical_chain_head(chaindb.db, block.header, GENESIS_PARENT_HASH)
        if block.number > 0:
            self.chain.import_block(block)
        else:
            self.chain = self.chain.from_genesis_header(chaindb.db, block.header)

    #
    # Meta
    #
    def time_travel(self, to_timestamp):
        # timestamp adjusted by 1 b/c a second is added in mine_blocks
        self.chain.header = self.chain.header.copy(timestamp=(to_timestamp - 1))
        self.mine_blocks()
        return to_timestamp

    #
    # Mining
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=None):
        if coinbase is not None:
            mine_kwargs = {'coinbase': coinbase}
        else:
            mine_kwargs = {}
        for _ in range(num_blocks):
            block = self.chain.mine_block(**mine_kwargs)
            yield block.hash

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        for private_key in self.account_keys:
            yield private_key.public_key.to_canonical_address()

    def add_account(self, private_key):
        keys = KeyAPI()
        self.account_keys = self.account_keys + (keys.PrivateKey(private_key),)

    #
    # Chain data
    #
    @replace_exceptions({
        EVMHeaderNotFound: BlockNotFound,
    })
    def get_block_by_number(self, block_number, full_transaction=True):
        block = _get_block_by_number(self.chain, block_number)
        is_pending = block.number == self.chain.get_block().number
        return serialize_block(block, full_transaction, is_pending)

    @replace_exceptions({
        EVMHeaderNotFound: BlockNotFound,
    })
    def get_block_by_hash(self, block_hash, full_transaction=True):
        block = _get_block_by_hash(self.chain, block_hash)
        is_pending = block.number == self.chain.get_block().number
        return serialize_block(block, full_transaction, is_pending)

    def get_transaction_by_hash(self, transaction_hash):
        block, transaction, transaction_index = _get_transaction_by_hash(
            self.chain,
            transaction_hash,
        )
        is_pending = block.number == self.chain.get_block().number
        return serialize_transaction(block, transaction, transaction_index, is_pending)

    def get_transaction_receipt(self, transaction_hash):
        block, transaction, transaction_index = _get_transaction_by_hash(
            self.chain,
            transaction_hash,
        )
        is_pending = block.number == self.chain.get_block().number
        block_receipts = block.get_receipts(self.chain.chaindb)

        return serialize_transaction_receipt(
            block,
            block_receipts,
            transaction,
            transaction_index,
            is_pending,
        )

    #
    # Account state
    #
    def get_nonce(self, account, block_number="latest"):
        vm = _get_vm_for_block_number(self.chain, block_number)
        return vm.state.get_nonce(account)

    def get_balance(self, account, block_number="latest"):
        vm = _get_vm_for_block_number(self.chain, block_number)
        return vm.state.get_balance(account)

    def get_code(self, account, block_number="latest"):
        vm = _get_vm_for_block_number(self.chain, block_number)
        return vm.state.get_code(account)

    #
    # Transactions
    #
    @to_dict
    def _normalize_transaction(self, transaction, block_number='latest'):
        for key in transaction:
            if key == 'from':
                continue
            yield key, transaction[key]
        if 'nonce' not in transaction:
            yield 'nonce', self.get_nonce(transaction['from'], block_number)
        if 'data' not in transaction:
            yield 'data', b''
        if 'gas_price' not in transaction:
            yield 'gas_price', 1
        if 'value' not in transaction:
            yield 'value', 0
        if 'to' not in transaction:
            yield 'to', b''

    def _get_normalized_and_unsigned_evm_transaction(self, transaction, block_number='latest'):
        normalized_transaction = self._normalize_transaction(transaction, block_number)
        evm_transaction = self.chain.create_unsigned_transaction(**normalized_transaction)
        return evm_transaction

    def _get_normalized_and_signed_evm_transaction(self, transaction, block_number='latest'):
        if transaction['from'] not in self._key_lookup:
            raise ValidationError(
                'No valid "from" key was provided in the transaction '
                'which is required for transaction signing.'
            )
        signing_key = self._key_lookup[transaction['from']]
        normalized_transaction = self._normalize_transaction(transaction, block_number)
        evm_transaction = self.chain.create_unsigned_transaction(**normalized_transaction)
        return evm_transaction.as_signed_transaction(signing_key)

    def send_raw_transaction(self, raw_transaction):
        vm = _get_vm_for_block_number(self.chain, "latest")
        TransactionClass = vm.get_transaction_class()
        evm_transaction = rlp.decode(raw_transaction, TransactionClass)
        self.chain.apply_transaction(evm_transaction)
        return evm_transaction.hash

    def send_signed_transaction(self, signed_transaction, block_number='latest'):
        normalized_transaction = self._normalize_transaction(signed_transaction, block_number)
        signed_evm_transaction = self.chain.create_transaction(**normalized_transaction)
        self.chain.apply_transaction(signed_evm_transaction)
        return signed_evm_transaction.hash

    def send_transaction(self, transaction):
        signed_evm_transaction = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )
        self.chain.apply_transaction(signed_evm_transaction)
        return signed_evm_transaction.hash

    def _max_available_gas(self):
        header = self.chain.get_block().header
        return header.gas_limit - header.gas_used

    @replace_exceptions({
        EVMInvalidInstruction: TransactionFailed,
        EVMRevert: TransactionFailed})
    def estimate_gas(self, transaction, block_number="latest"):
        evm_transaction = self._get_normalized_and_unsigned_evm_transaction(
            assoc(transaction, 'gas', 21000),
            block_number
        )
        spoofed_transaction = EVMSpoofTransaction(evm_transaction, from_=transaction['from'])

        if block_number == "latest":
            return self.chain.estimate_gas(spoofed_transaction)
        elif block_number == "earliest":
            return self.chain.estimate_gas(
                spoofed_transaction, self.chain.get_canonical_block_header_by_number(0)
            )
        elif block_number == "pending":
            raise NotImplementedError('"pending" block identifier is unsupported in eth-tester')
        else:
            return self.chain.estimate_gas(
                spoofed_transaction,
                self.chain.get_canonical_block_header_by_number(block_number),
            )

    def is_eip838_error(self, error):
        if not isinstance(error, EVMRevert):
            return False
        elif len(error.args) == 0:
            return False

        try:
            return error.args[0][:4] == EIP838_SIG
        except TypeError:
            return False

    def call(self, transaction, block_number="latest"):
        # TODO: move this to the VM level.
        defaulted_transaction = transaction.copy()
        if 'gas' not in defaulted_transaction:
            defaulted_transaction['gas'] = self._max_available_gas()

        signed_evm_transaction = self._get_normalized_and_signed_evm_transaction(
            defaulted_transaction,
            block_number,
        )

        computation = _execute_and_revert_transaction(
            self.chain,
            signed_evm_transaction,
            block_number,
        )
        if computation.is_error:
            msg = str(computation._error)

            # Check to see if it's a EIP838 standard error, with ABI signature
            # of Error(string). If so - extract the message/reason.
            if self.is_eip838_error(computation._error):
                error_str = computation._error.args[0][36:]
                try:
                    msg = decode_single('string', error_str)
                except DecodingError:
                    # Invalid encoded bytes, leave msg as computation._error
                    # byte string.
                    pass

            raise TransactionFailed(msg)

        return computation.output
