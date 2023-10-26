from __future__ import (
    absolute_import,
)

import os
import time
from typing import (
    Dict,
    List,
    Union,
)

from eth_abi import (
    abi,
)
from eth_abi.exceptions import (
    DecodingError,
)
from eth_account.hdaccount import (
    HDPath,
    seed_from_mnemonic,
)
from eth_keys import (
    KeyAPI,
)
from eth_typing import (
    Address,
)
from eth_utils import (
    encode_hex,
    int_to_big_endian,
    is_integer,
    to_bytes,
    to_checksum_address,
    to_dict,
    to_tuple,
    to_wei,
)
from eth_utils.decorators import (
    replace_exceptions,
)
from eth_utils.toolz import (
    assoc,
)

from eth_tester.backends.base import (
    BaseChainBackend,
)
from eth_tester.backends.common import (
    merge_genesis_overrides,
)
from eth_tester.constants import (
    DYNAMIC_FEE_TRANSACTION_PARAMS,
)
from eth_tester.exceptions import (
    BackendDistributionNotFound,
    BlockNotFound,
    TransactionFailed,
    TransactionNotFound,
    ValidationError,
)

from ...validation.inbound import (
    validate_inbound_withdrawals,
)
from .serializers import (
    serialize_block,
    serialize_transaction,
    serialize_transaction_receipt,
)
from .utils import (
    is_supported_pyevm_version_available,
)

if is_supported_pyevm_version_available():
    from eth.constants import (
        GENESIS_PARENT_HASH,
        POST_MERGE_DIFFICULTY,
        POST_MERGE_MIX_HASH,
        POST_MERGE_NONCE,
    )
    from eth.exceptions import (
        HeaderNotFound as EVMHeaderNotFound,
        InvalidInstruction as EVMInvalidInstruction,
        Revert as EVMRevert,
    )
    from eth.vm.forks import (
        ParisVM,
        ShanghaiVM,
    )
    from eth.vm.forks.shanghai.withdrawals import (
        Withdrawal,
    )
    from eth.vm.spoof import (
        SpoofTransaction as EVMSpoofTransaction,
    )
else:
    EVMHeaderNotFound = None
    EVMInvalidInstruction = None
    EVMRevert = None
    GENESIS_PARENT_HASH = None
    ParisVM = None
    POST_MERGE_DIFFICULTY = None
    POST_MERGE_MIX_HASH = None
    POST_MERGE_NONCE = None
    ShanghaiVM = None
    Withdrawal = None


ZERO_ADDRESS = 20 * b"\x00"
ZERO_HASH32 = 32 * b"\x00"
EIP838_SIG = b"\x08\xc3y\xa0"

EMPTY_RLP_LIST_HASH = b"\x1d\xccM\xe8\xde\xc7]z\xab\x85\xb5g\xb6\xcc\xd4\x1a\xd3\x12E\x1b\x94\x8at\x13\xf0\xa1B\xfd@\xd4\x93G"  # noqa: E501
BLANK_ROOT_HASH = b"V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n\x5bH\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!"  # noqa: E501


GENESIS_BLOCK_NUMBER = 0
GENESIS_DIFFICULTY = 131072
GENESIS_GAS_LIMIT = 30029122  # gas limit at London fork block 12965000 on mainnet
GENESIS_COINBASE = ZERO_ADDRESS
GENESIS_NONCE = b"\x00\x00\x00\x00\x00\x00\x00*"  # 42 encoded as big-endian-integer
GENESIS_MIX_HASH = ZERO_HASH32
GENESIS_EXTRA_DATA = b""
GENESIS_INITIAL_ALLOC = {}


MINIMUM_GAS_ESTIMATE = 30000
# A buffer of 1.1 would mean allocate 10% more gas than estimated
GAS_ESTIMATE_BUFFER = 1.5


def get_default_account_state(overrides=None):
    default_account_state = {
        "balance": to_wei(1000000, "ether"),
        "storage": {},
        "code": b"",
        "nonce": 0,
    }
    if overrides is not None:
        account_state = merge_genesis_overrides(
            defaults=default_account_state, overrides=overrides
        )
    else:
        account_state = default_account_state
    return account_state


@to_tuple
def get_default_account_keys(quantity=None):
    keys = KeyAPI()
    quantity = quantity or 10
    for i in range(1, quantity + 1):
        pk_bytes = int_to_big_endian(i).rjust(32, b"\x00")
        private_key = keys.PrivateKey(pk_bytes)
        yield private_key


@to_tuple
def get_account_keys_from_mnemonic(mnemonic, quantity=None, hd_path=None):
    keys = KeyAPI()
    seed = seed_from_mnemonic(mnemonic, "")
    quantity = quantity or 10

    if hd_path is None:
        # default HD path
        hd_path = "m/44'/60'/0'"

    for i in range(0, quantity):
        # create unique HDPath to derive the private key for each account
        key = HDPath(f"{hd_path}/{i}").derive(seed)
        private_key = keys.PrivateKey(key)
        yield private_key


@to_dict
def generate_genesis_state_for_keys(account_keys, overrides=None):
    for private_key in account_keys:
        account_state = get_default_account_state(overrides=overrides)
        yield private_key.public_key.to_canonical_address(), account_state


def get_default_genesis_params(overrides=None):
    # Commented out params became un-configurable in py-evm during London refactor.
    # Post-merge now. Set genesis params to expect post-merge validation. If PoS field
    # value defaults are not desired, use the overrides option.
    default_genesis_params = {
        # "bloom": 0,
        "coinbase": GENESIS_COINBASE,
        "difficulty": POST_MERGE_DIFFICULTY,
        "extra_data": GENESIS_EXTRA_DATA,
        "gas_limit": GENESIS_GAS_LIMIT,
        # "gas_used": 0,
        "mix_hash": POST_MERGE_MIX_HASH,
        "nonce": POST_MERGE_NONCE,
        # "block_number": GENESIS_BLOCK_NUMBER,
        # "parent_hash": GENESIS_PARENT_HASH,
        "receipt_root": BLANK_ROOT_HASH,
        "timestamp": int(time.time()),
        "transaction_root": BLANK_ROOT_HASH,
        # "uncles_hash": EMPTY_RLP_LIST_HASH,
    }
    if overrides is not None:
        genesis_params = merge_genesis_overrides(
            default_genesis_params, overrides=overrides
        )
    else:
        genesis_params = default_genesis_params
    return genesis_params


def setup_tester_chain(
    genesis_params=None,
    genesis_state=None,
    num_accounts=None,
    vm_configuration=None,
    mnemonic=None,
    hd_path=None,
    genesis_is_post_merge=True,
):
    from eth.chains.base import (
        MiningChain,
    )
    from eth.consensus import (
        ConsensusApplier,
        NoProofConsensus,
    )
    from eth.db import (
        get_db_backend,
    )

    if vm_configuration is None:
        vm_config = ((0, ShanghaiVM),)
    else:
        if len(vm_configuration) > 0:
            _genesis_block_num, genesis_vm = vm_configuration[0]
            if not issubclass(genesis_vm, ParisVM):
                genesis_is_post_merge = False
        consensus_applier = ConsensusApplier(NoProofConsensus)
        vm_config = consensus_applier.amend_vm_configuration(vm_configuration)

    class MainnetTesterPosChain(MiningChain):
        # TODO: Once the logic within `MiningChain` is refactored more generally in
        #  py-evm, change this class inheritance to reflect that since a `PosConsensus`
        #  chain does not mine.
        chain_id = 131277322940537
        vm_configuration = vm_config

        def create_header_from_parent(self, parent_header, **header_params):
            # Keep the gas limit constant
            return super().create_header_from_parent(
                parent_header,
                **assoc(header_params, "gas_limit", parent_header.gas_limit),
            )

        def get_transaction_builder(self):
            return super().get_vm().get_transaction_builder()

    if genesis_params is None:
        overrides = {}
        if not genesis_is_post_merge:
            overrides["difficulty"] = GENESIS_DIFFICULTY
            overrides["nonce"] = GENESIS_NONCE
            overrides["mix_hash"] = GENESIS_MIX_HASH
        genesis_params = get_default_genesis_params(overrides=overrides)

    if genesis_state:
        num_accounts = len(genesis_state)

    if mnemonic:
        account_keys = get_account_keys_from_mnemonic(
            mnemonic, quantity=num_accounts, hd_path=hd_path
        )
    else:
        account_keys = get_default_account_keys(quantity=num_accounts)

    if genesis_state is None:
        genesis_state = generate_genesis_state_for_keys(account_keys)

    base_db = get_db_backend()

    chain = MainnetTesterPosChain.from_genesis(base_db, genesis_params, genesis_state)
    return account_keys, chain


def _get_block_by_number(chain, block_number):
    if block_number in ("latest", "safe", "finalized"):
        head_block = chain.get_block()
        return chain.get_canonical_block_by_number(max(0, head_block.number - 1))
    elif block_number == "earliest":
        return chain.get_canonical_block_by_number(0)
    elif block_number == "pending":
        return chain.get_block()
    elif is_integer(block_number):
        # Note: The head block is the pending block. If a block number is passed
        # explicitly here, return the block only if it is already part of the chain
        # (i.e. not pending).
        head_block = chain.get_block()
        if block_number < head_block.number:
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

    def __init__(
        self,
        genesis_parameters=None,
        genesis_state=None,
        vm_configuration=None,
        mnemonic=None,
        hd_path=None,
    ):
        """
        :param genesis_parameters: A dict of chain parameters for overriding default
             values when setting up the chain.
        :param genesis_state: A dict (or list of tuples) matching accounts to state
             properties, such as `balance`.
        :param vm_configuration: The tuple of virtual machines defining a chain
            schedule as used in py-evm's :attr:`eth.chains.base.Chain.vm_configuration`.
            (at author time, a series of block numbers and virtual machines)
        :param mnemonic: A mnemonic str to use when generating accounts.
        """
        if not is_supported_pyevm_version_available():
            raise BackendDistributionNotFound(
                "The `py-evm` package is not available or not up to date. "
                "The `PyEVMBackend` requires py-evm to be installed and importable. "
                "Please install or update the `py-evm` library."
            )

        self.account_keys = None  # set below
        accounts = len(genesis_state) if genesis_state else None
        self.reset_to_genesis(
            genesis_parameters,
            genesis_state,
            accounts,
            vm_configuration,
            mnemonic,
            hd_path,
        )

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic,
        genesis_state_overrides=None,
        num_accounts=None,
        genesis_parameters=None,
        vm_configuration=None,
        hd_path=None,
    ):
        """
        Create a genesis state pre-populated with accounts. A number of accounts can be
        initialized with a mnemonic phrase and heirarchical deterministic path. If no
        overrides are provided, a default set of accounts will be used.
        """
        genesis_state = PyEVMBackend.generate_genesis_state(
            mnemonic=mnemonic,
            overrides=genesis_state_overrides or {},
            num_accounts=num_accounts,
            hd_path=hd_path,
        )

        return cls(
            genesis_parameters=genesis_parameters,
            genesis_state=genesis_state,
            vm_configuration=vm_configuration,
            mnemonic=mnemonic,
            hd_path=hd_path,
        )

    #
    # Genesis
    #

    @classmethod
    def generate_genesis_params(cls, overrides=None):
        return cls._generate_genesis_params(overrides=overrides)

    @staticmethod
    def _generate_genesis_params(overrides=None):
        return get_default_genesis_params(overrides=overrides)

    @classmethod
    def generate_genesis_state(
        cls, overrides=None, num_accounts=None, mnemonic=None, hd_path=None
    ):
        return cls._generate_genesis_state(
            overrides=overrides,
            num_accounts=num_accounts,
            mnemonic=mnemonic,
            hd_path=hd_path,
        )

    @staticmethod
    def _generate_genesis_state(
        overrides=None, num_accounts=None, mnemonic=None, hd_path=None
    ):
        if mnemonic:
            account_keys = get_account_keys_from_mnemonic(
                mnemonic, quantity=num_accounts, hd_path=hd_path
            )
        else:
            account_keys = get_default_account_keys(quantity=num_accounts)

        return generate_genesis_state_for_keys(
            account_keys=account_keys, overrides=overrides
        )

    def reset_to_genesis(
        self,
        genesis_params=None,
        genesis_state=None,
        num_accounts=None,
        vm_configuration=None,
        mnemonic=None,
        hd_path=None,
    ):
        self.account_keys, self.chain = setup_tester_chain(
            genesis_params,
            genesis_state,
            num_accounts,
            vm_configuration,
            mnemonic,
            hd_path,
        )

    #
    # Private Accounts API
    #
    @property
    def _key_lookup(self):
        return {key.public_key.to_canonical_address(): key for key in self.account_keys}

    #
    # Snapshot API
    #
    def take_snapshot(self):
        block = _get_block_by_number(self.chain, "latest")
        return block.hash

    def revert_to_snapshot(self, snapshot):
        block = self.chain.get_block_by_hash(snapshot)
        chaindb = self.chain.chaindb

        chaindb._set_as_canonical_chain_head(
            chaindb.db, block.header, GENESIS_PARENT_HASH
        )
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
    # Importing blocks
    #
    @to_tuple
    def mine_blocks(self, num_blocks=1, coinbase=ZERO_ADDRESS):
        mine_kwargs = {"coinbase": coinbase}

        for _ in range(num_blocks):
            if isinstance(self.chain.get_vm(), ParisVM):
                # post-merge, generate a random `mix_hash` to simulate the
                # `prevrandao` value.
                mine_kwargs["mix_hash"] = os.urandom(32)

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
    @replace_exceptions(
        {
            EVMHeaderNotFound: BlockNotFound,
        }
    )
    def get_block_by_number(self, block_number, full_transaction=True):
        block = _get_block_by_number(self.chain, block_number)
        is_pending = block.number == self.chain.get_block().number
        return serialize_block(block, full_transaction, is_pending)

    @replace_exceptions(
        {
            EVMHeaderNotFound: BlockNotFound,
        }
    )
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

    def get_fee_history(
        self, block_count=1, newest_block="latest", reward_percentiles: List[int] = ()
    ):
        if isinstance(block_count, int) and not 1 <= block_count <= 1024:
            raise ValidationError("block_count must be between 1 and 1024")

        if newest_block == "pending":
            newest_block = "latest"

        block = self.get_block_by_number(newest_block)
        block_header = self.chain.get_canonical_block_header_by_number(block["number"])

        ancestors = self.chain.get_ancestors(block_count, header=block_header)

        base_fee_per_gas = []
        gas_used_ratio = []
        reward = []  # always return empty reward array for now

        for ancestor in ancestors:
            base_fee_per_gas.append(ancestor.header.base_fee_per_gas)
            gas_used_ratio.append(ancestor.header.gas_used / ancestor.header.gas_limit)

        return {
            "oldest_block": 1,
            "base_fee_per_gas": base_fee_per_gas,
            "gas_used_ratio": gas_used_ratio,
            "reward": reward,
        }

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

    def get_storage(self, account: Address, slot: int, block_number="latest") -> bytes:
        vm = _get_vm_for_block_number(self.chain, block_number)
        return vm.state.get_storage(account, slot)

    def get_base_fee(self, block_number="latest"):
        vm = _get_vm_for_block_number(self.chain, block_number)
        return vm.state.base_fee

    #
    # Transactions
    #
    @to_dict
    def _normalize_transaction(self, transaction, block_number="latest"):
        is_dynamic_fee_transaction = (
            any(_ in transaction for _ in DYNAMIC_FEE_TRANSACTION_PARAMS)
            or
            # if no fee params exist, default to dynamic fee transaction:
            not any(
                _ in transaction
                for _ in DYNAMIC_FEE_TRANSACTION_PARAMS + ("gas_price",)
            )
        )
        is_typed_transaction = (
            is_dynamic_fee_transaction or "access_list" in transaction
        )

        for key in transaction:
            if key in ("from", "type"):
                continue
            if key == "v" and is_typed_transaction:
                yield "y_parity", transaction[
                    "v"
                ]  # use y_parity for typed txns, internally
                continue
            yield key, transaction[key]

        if "nonce" not in transaction:
            yield "nonce", self.get_nonce(transaction["from"], block_number)
        if "data" not in transaction:
            yield "data", b""
        if "value" not in transaction:
            yield "value", 0
        if "to" not in transaction:
            yield "to", b""

        if is_dynamic_fee_transaction:
            if not any(_ in transaction for _ in DYNAMIC_FEE_TRANSACTION_PARAMS):
                yield "max_fee_per_gas", 1 * 10**9
                yield "max_priority_fee_per_gas", 1 * 10**9
            elif (
                "max_priority_fee_per_gas" in transaction
                and "max_fee_per_gas" not in transaction
            ):
                yield (
                    "max_fee_per_gas",
                    transaction["max_priority_fee_per_gas"]
                    + 2 * self.get_base_fee(block_number),
                )

        if is_typed_transaction:
            # typed transaction
            if "access_list" not in transaction:
                yield "access_list", ()
            if "chain_id" not in transaction:
                yield "chain_id", self.chain.chain_id

    def _get_normalized_and_unsigned_evm_transaction(
        self, transaction, block_number="latest"
    ):
        normalized_transaction = self._normalize_transaction(transaction, block_number)
        evm_transaction = self._create_type_aware_unsigned_transaction(
            normalized_transaction
        )
        return evm_transaction

    def _get_normalized_and_signed_evm_transaction(
        self, transaction, block_number="latest"
    ):
        if transaction["from"] not in self._key_lookup:
            raise ValidationError(
                'No valid "from" key was provided in the transaction '
                "which is required for transaction signing."
            )
        signing_key = self._key_lookup[transaction["from"]]
        normalized_transaction = self._normalize_transaction(transaction, block_number)
        evm_transaction = self._create_type_aware_unsigned_transaction(
            normalized_transaction
        )
        return evm_transaction.as_signed_transaction(signing_key)

    def _create_type_aware_unsigned_transaction(self, normalized_txn):
        if all(_ in normalized_txn for _ in ("access_list", "gas_price")):
            return self.chain.get_transaction_builder().new_unsigned_access_list_transaction(  # noqa: E501
                **normalized_txn
            )
        elif all(_ in normalized_txn for _ in DYNAMIC_FEE_TRANSACTION_PARAMS):
            return self.chain.get_transaction_builder().new_unsigned_dynamic_fee_transaction(  # noqa: E501
                **normalized_txn
            )
        return self.chain.create_unsigned_transaction(**normalized_txn)

    def send_raw_transaction(self, raw_transaction):
        vm = _get_vm_for_block_number(self.chain, "latest")
        evm_transaction = vm.get_transaction_builder().decode(raw_transaction)
        self.chain.apply_transaction(evm_transaction)
        return evm_transaction.hash

    def send_signed_transaction(self, signed_transaction, block_number="latest"):
        normalized_transaction = self._normalize_transaction(
            signed_transaction, block_number
        )
        signed_evm_transaction = self._create_type_aware_signed_transaction(
            normalized_transaction
        )
        self.chain.apply_transaction(signed_evm_transaction)
        return signed_evm_transaction.hash

    def _create_type_aware_signed_transaction(self, normalized_txn):
        if all(_ in normalized_txn for _ in ("access_list", "gas_price")):
            return self.chain.get_transaction_builder().new_access_list_transaction(
                **normalized_txn
            )
        elif all(_ in normalized_txn for _ in DYNAMIC_FEE_TRANSACTION_PARAMS):
            return self.chain.get_transaction_builder().new_dynamic_fee_transaction(
                **normalized_txn
            )
        return self.chain.create_transaction(**normalized_txn)

    def send_transaction(self, transaction):
        signed_evm_transaction = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )
        self.chain.apply_transaction(signed_evm_transaction)
        return signed_evm_transaction.hash

    def apply_withdrawals(
        self,
        withdrawals_list: List[Dict[str, Union[int, str]]],
    ) -> None:
        """
        Apply withdrawals to the state and mine the block that includes the withdrawals.
        """
        validate_inbound_withdrawals(withdrawals_list)

        vm = _get_vm_for_block_number(self.chain, "latest")
        if not isinstance(vm, ShanghaiVM):
            raise ValidationError(
                "Withdrawals are only supported after the Shanghai fork"
            )

        withdrawals = [
            Withdrawal(
                index=withdrawal_dict["index"],
                validator_index=withdrawal_dict["validator_index"],
                address=to_bytes(
                    hexstr=to_checksum_address(withdrawal_dict["address"])
                ),
                amount=withdrawal_dict["amount"],
            )
            for withdrawal_dict in withdrawals_list
        ]
        self.chain.mine_all(transactions=[], withdrawals=withdrawals)

    def _max_available_gas(self):
        header = self.chain.get_block().header
        return header.gas_limit - header.gas_used

    @replace_exceptions(
        {EVMInvalidInstruction: TransactionFailed, EVMRevert: TransactionFailed}
    )
    def estimate_gas(self, transaction, block_number="latest"):
        evm_transaction = self._get_normalized_and_unsigned_evm_transaction(
            assoc(transaction, "gas", 21000), block_number
        )
        spoofed_transaction = EVMSpoofTransaction(
            evm_transaction, from_=transaction["from"]
        )

        if block_number in ("latest", "safe", "finalized"):
            return self.chain.estimate_gas(spoofed_transaction)
        elif block_number == "earliest":
            return self.chain.estimate_gas(
                spoofed_transaction, self.chain.get_canonical_block_header_by_number(0)
            )
        elif block_number == "pending":
            raise NotImplementedError(
                '"pending" block identifier is unsupported in eth-tester'
            )
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
        if "gas" not in defaulted_transaction:
            defaulted_transaction["gas"] = self._max_available_gas()

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
                error_str = computation._error.args[0][4:]
                try:
                    decoded_args = abi.decode(["string"], error_str)
                    msg = decoded_args[0]
                except DecodingError:
                    # Invalid encoded bytes, leave msg as computation._error
                    # byte string.
                    pass

            raise TransactionFailed(msg)

        return computation.output
