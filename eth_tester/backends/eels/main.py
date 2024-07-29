import time
from typing import (
    Any,
    Dict,
    List,
    Union,
)

from eth_keys import (
    KeyAPI,
)
from eth_keys.datatypes import (
    PrivateKey,
)
from eth_typing import (
    Address,
    ForkName,
)
from eth_utils import (
    int_to_big_endian,
    logging,
    to_dict,
    to_tuple,
)
from ethereum import (
    rlp,
)
from ethereum.base_types import (
    U64,
    U256,
    Uint,
)
from ethereum.crypto.hash import (
    keccak256,
)
from ethereum.exceptions import (
    EthereumException,
)
from ethereum.utils.hexadecimal import (
    hex_to_uint,
)
from ethereum_spec_tools.evm_tools.loaders.fork_loader import (
    ForkLoad,
)
from ethereum_spec_tools.evm_tools.loaders.transaction_loader import (
    TransactionLoad,
)
from ethereum_spec_tools.evm_tools.utils import (
    secp256k1_sign,
)

from eth_tester.backends.base import (
    BaseChainBackend,
)
from eth_tester.backends.common import (
    merge_genesis_overrides,
)
from eth_tester.constants import (
    BEACON_ROOTS_CONTRACT_ADDRESS,
    ZERO_ADDRESS,
    ZERO_HASH32,
)
from eth_tester.exceptions import (
    BackendDistributionNotFound,
    BlockNotFound,
    TransactionNotFound,
    ValidationError,
)

from ...utils.accounts import (
    get_account_keys_from_mnemonic,
    get_default_account_keys,
)
from ...utils.transactions import (
    normalize_transaction_fields,
)
from ...validation.inbound import (
    validate_inbound_withdrawals,
)
from .eels_normalizers import (
    eels_normalize_transaction,
)
from .serializers import (
    serialize_block,
    serialize_receipt,
    serialize_transaction,
    serialize_transaction_for_block,
)
from .utils import (
    is_eels_available,
)

if is_eels_available():
    from ethereum.cancun.fork import (
        SYSTEM_ADDRESS,
        SYSTEM_TRANSACTION_GAS,
        BlockChain,
    )


GENESIS_BLOCK_NUMBER = Uint(0)
GENESIS_DIFFICULTY = Uint(0)
GENESIS_GAS_LIMIT = Uint(30029122)  # gas limit at London fork block 12965000 on mainnet
GENESIS_NONCE = b"\x00\x00\x00\x00\x00\x00\x00*"  # 42 encoded as big-endian-integer
GENESIS_COINBASE = ZERO_ADDRESS
GENESIS_MIX_HASH = ZERO_HASH32
GENESIS_EXTRA_DATA = b""
GENESIS_LOGS_BLOOM = b"\x00" * 256
GENESIS_INITIAL_ALLOC = {}


MINIMUM_GAS_ESTIMATE = 300000
# A buffer of 1.1 would mean allocate 10% more gas than estimated
GAS_ESTIMATE_BUFFER = 1.5


class EELSBlockChain(BlockChain):
    @property
    def latest_block(self):
        return self.blocks[-1]


class EELSBackend(BaseChainBackend):
    logger = logging.get_logger("eth-tester.backends.EELSBackend")
    chain = None

    _pending_block = None
    _account_keys = []
    _transactions_map = {}
    _receipts_map = {}

    def __init__(
        self,
        fork_name: ForkName = None,
        genesis_params=None,
        genesis_state=None,
        num_accounts=None,
        mnemonic=None,
        hd_path=None,
    ):
        if not is_eels_available():
            raise BackendDistributionNotFound(
                "The EELS is package is not available or not up to date. "
                "The `EELSBackend` requires ethereum/execution-specs to be installed "
                "and importable."
            )

        if fork_name is None:
            # always try to keep this as the latest
            fork_name = "cancun"

        self.fork = ForkLoad(str(fork_name).lower())
        self._fork_module = self.fork._module("fork")
        self._state_module = self.fork._module("state")
        self._vm_module = self.fork._module("vm")
        self._blocks_module = self.fork._module("blocks")
        self._transactions_module = self.fork._module("transactions")
        self._fork_types = self.fork._module("fork_types")

        self.reset_to_genesis(
            genesis_params=genesis_params,
            genesis_state=genesis_state,
            num_accounts=num_accounts,
            mnemonic=mnemonic,
            hd_path=hd_path,
        )

    def time_travel(self, to_timestamp):
        pass

    def _get_default_account_state(self, overrides=None):
        account_state = merge_genesis_overrides(
            defaults={
                "balance": U256(0),
                "code": b"",
                "nonce": Uint(0),
            },
            overrides=overrides or {},
        )
        return self.fork.Account(**account_state)

    @to_dict
    def _generate_genesis_state_for_keys(self, account_keys, overrides=None):
        for private_key in account_keys:
            account_state = self._get_default_account_state(
                overrides=overrides or {"balance": U256(10**18)}
            )
            yield private_key.public_key.to_canonical_address(), account_state

    @to_tuple
    def get_default_account_keys(self, quantity=None):
        keys = KeyAPI()
        quantity = quantity or 10
        for i in range(1, quantity + 1):
            pk_bytes = int_to_big_endian(i).rjust(32, b"\x00")
            private_key = keys.PrivateKey(pk_bytes)
            yield private_key

    #
    # Genesis
    #
    def _generate_genesis_state(
        self, overrides=None, num_accounts=None, mnemonic=None, hd_path=None
    ):
        if mnemonic:
            account_keys = get_account_keys_from_mnemonic(
                mnemonic, quantity=num_accounts, hd_path=hd_path
            )
        else:
            account_keys = get_default_account_keys(quantity=num_accounts)

        self._account_keys.extend(account_keys)
        return self._generate_genesis_state_for_keys(
            account_keys=account_keys, overrides=overrides
        )

    def reset_to_genesis(
        self,
        genesis_params=None,
        genesis_state=None,
        num_accounts=None,
        mnemonic=None,
        hd_path=None,
    ):
        if genesis_params is not None:
            raise NotImplementedError(
                "Custom genesis params are not yet supported for `EELSBackend`."
            )

        if genesis_state is None:
            genesis_state = self._generate_genesis_state(
                num_accounts=num_accounts, mnemonic=mnemonic, hd_path=hd_path
            )

        # if self.fork.is_after_fork("ethereum.cancun"):
        # TODO: set up beacon roots contract
        # genesis_state[BEACON_ROOTS_CONTRACT_ADDRESS] = (
        #     self._get_default_account_state(
        #         overrides={"code": BEACON_ROOTS_CONTRACT_CODE}
        #     )
        # )

        eels_state = self._fork_module.State()
        for address, account in genesis_state.items():
            self.fork.set_account(eels_state, address, account)

        self._transactions_map = {}
        self._receipts_map = {}
        self.chain = EELSBlockChain(
            blocks=[self._generate_genesis_block()],
            state=eels_state,
            chain_id=U64(1),
        )
        self._build_new_pending_block()

    #
    # Private Accounts API
    #
    @property
    def _key_lookup(self):
        return {
            key.public_key.to_canonical_address(): key for key in self._account_keys
        }

    #
    # Snapshot API
    #
    def take_snapshot(self):
        pass
        # raise NotImplementedError("Snapshots are not supported in EELS")

    def revert_to_snapshot(self, snapshot):
        pass
        # raise NotImplementedError("Snapshots are not supported in EELS")

    #
    # Importing blocks
    #
    def _internal_apply_body_validation(self) -> Any:
        """
        Use a similar approach to EELS to apply the body, only with a synthetic
        state. This is used to validate the body and generate appropriate values
        for some calculated fields.
        """
        pending_block_header = self._pending_block["header"]

        block_gas_limit = pending_block_header["gas_limit"]
        gas_available = block_gas_limit
        transactions_trie = self.fork.Trie(secured=False, default=None)
        receipts_trie = self.fork.Trie(secured=False, default=None)

        state_copy = self._create_synthetic_state()

        if not self.fork.state_root(self.chain.state) == self.fork.state_root(
            state_copy
        ):
            raise ValidationError(
                "Copied state root does not match the expected state root."
            )

        block_logs = ()
        blob_gas_used = Uint(0)
        if self.fork.is_after_fork("ethereum.cancun"):
            beacon_block_roots_contract_code = self.fork.get_account(
                state_copy, BEACON_ROOTS_CONTRACT_ADDRESS
            ).code
            system_tx_message = self.fork.Message(
                caller=SYSTEM_ADDRESS,
                target=BEACON_ROOTS_CONTRACT_ADDRESS,
                gas=SYSTEM_TRANSACTION_GAS,
                value=U256(0),
                data=pending_block_header["parent_beacon_block_root"],
                code=beacon_block_roots_contract_code,
                depth=Uint(0),
                current_target=BEACON_ROOTS_CONTRACT_ADDRESS,
                code_address=BEACON_ROOTS_CONTRACT_ADDRESS,
                should_transfer_value=False,
                is_static=False,
                accessed_addresses=set(),
                accessed_storage_keys=set(),
                parent_evm=None,
            )

            system_tx_env = self.fork.Environment(
                caller=SYSTEM_ADDRESS,
                origin=SYSTEM_ADDRESS,
                block_hashes=self._fork_module.get_last_256_block_hashes(self.chain),
                coinbase=pending_block_header["coinbase"],
                number=pending_block_header["number"],
                gas_limit=block_gas_limit,
                base_fee_per_gas=pending_block_header["base_fee_per_gas"],
                gas_price=U256(0),
                time=U256(int(time.time())),
                prev_randao=pending_block_header["prev_randao"],
                state=state_copy,
                chain_id=self.chain.chain_id,
                traces=[],
                excess_blob_gas=pending_block_header["excess_blob_gas"],
                blob_versioned_hashes=(),
                transient_storage=self.fork.TransientStorage(),
            )

            system_tx_output = self.fork.process_message_call(
                system_tx_message, system_tx_env
            )

            self.fork.destroy_touched_empty_accounts(
                system_tx_env.state, system_tx_output.touched_accounts
            )

        apply_body_output_dict = {"receipts_map": {}}
        for i, tx in enumerate(self._pending_block["transactions"]):
            try:
                # TODO: Handle state reversion / snapshotting appropriately
                env = self.environment(tx, gas_available, state=state_copy)
                pre_state = self._create_synthetic_state()
                process_transaction_return = self.fork.process_transaction(env, tx)
                post_state = env.state

                contract_address = self._extract_contract_address(pre_state, post_state)

                if self.fork.is_after_fork("ethereum.cancun"):
                    blob_gas_used += self.fork.calculate_total_blob_gas(tx)
                    if blob_gas_used > self.fork.MAX_BLOB_GAS_PER_BLOCK:
                        raise ValidationError(
                            "Blob gas used exceeds the maximum allowed gas per block"
                        )
            except (EthereumException, ValidationError) as e:
                self.logger.warning(f"Transaction {rlp.rlp_hash(tx)} failed: {e}")
            else:
                gas_consumed = process_transaction_return[0]
                gas_available -= gas_consumed

                self.fork.trie_set(
                    transactions_trie,
                    rlp.encode(Uint(i)),
                    self.fork.encode_transaction(tx),
                )

                apply_body_output_dict["receipts_map"][self._get_tx_hash(tx)] = (
                    serialize_receipt(
                        self,
                        tx,
                        process_transaction_return,
                        i,
                        (block_gas_limit - gas_available),
                        contract_address,
                    )
                )
                receipt = self.fork.make_receipt(
                    tx, None, (block_gas_limit - gas_available), block_logs
                )

                self.fork.trie_set(
                    receipts_trie,
                    rlp.encode(Uint(i)),
                    receipt,
                )

                block_logs += process_transaction_return[1]
                state_copy._snapshots = []

        if (
            not self.fork.is_after_fork("ethereum.paris")
            and self._fork_module.BLOCK_REWARD is not None
        ):
            self._fork_module.pay_rewards(
                state_copy,
                pending_block_header["number"],
                pending_block_header["coinbase"],
                self._pending_block["ommers"],
            )

        apply_body_output_dict.update(
            {
                "block_gas_used": block_gas_limit - gas_available,
                "block_logs_bloom": self.fork.logs_bloom(block_logs),
            }
        )
        if self.fork.is_after_fork("ethereum.shanghai"):
            withdrawals_trie = self.fork.Trie(secured=False, default=None)
            for i, wd in enumerate(self._pending_block["withdrawals"]):
                self.fork.trie_set(
                    withdrawals_trie, rlp.encode(Uint(i)), rlp.encode(wd)
                )
                self.fork.process_withdrawal(state_copy, wd)

                if self.fork.account_exists_and_is_empty(state_copy, wd.address):
                    self.fork.destroy_account(state_copy, wd.address)

            apply_body_output_dict["withdrawals_root"] = self.fork.root(
                withdrawals_trie
            )

        if self.fork.is_after_fork("ethereum.cancun"):
            apply_body_output_dict["blob_gas_used"] = blob_gas_used
            apply_body_output_dict["excess_blob_gas"] = (
                pending_block_header["excess_blob_gas"] - blob_gas_used
            )

        apply_body_output_dict["state_root"] = self.fork.state_root(state_copy)
        apply_body_output_dict["tx_root"] = self.fork.root(transactions_trie)
        apply_body_output_dict["receipt_root"] = self.fork.root(receipts_trie)
        apply_body_output_dict["ommers_hash"] = rlp.rlp_hash(
            self._pending_block["ommers"]
        )
        return apply_body_output_dict

    def _create_synthetic_state(self):
        state_copy = self.fork.State()
        for address, account in self.chain.state._main_trie._data.items():
            self.fork.set_account(
                state_copy,
                address,
                self.fork.Account(
                    balance=account.balance,
                    nonce=account.nonce,
                    code=account.code,
                ),
            )
        return state_copy

    def _generate_genesis_block(self):
        return self.fork.Block(
            header=self.fork.Header(
                parent_hash=ZERO_HASH32,
                ommers_hash=ZERO_HASH32,
                coinbase=ZERO_ADDRESS,
                state_root=ZERO_HASH32,
                transactions_root=ZERO_HASH32,
                receipt_root=ZERO_HASH32,
                bloom=GENESIS_LOGS_BLOOM,
                difficulty=GENESIS_DIFFICULTY,
                number=Uint(0),
                gas_limit=GENESIS_GAS_LIMIT,
                gas_used=Uint(0),
                timestamp=Uint(int(time.time())),
                extra_data=ZERO_HASH32,
                prev_randao=ZERO_HASH32,
                nonce=GENESIS_NONCE,
                withdrawals_root=ZERO_HASH32,
                blob_gas_used=Uint(0),
                excess_blob_gas=Uint(0),
                parent_beacon_block_root=ZERO_HASH32,
                base_fee_per_gas=Uint(0),
            ),
            transactions=(),
            ommers=(),
            withdrawals=(),
        )

    def _build_new_pending_block(
        self,
        coinbase=ZERO_ADDRESS,
        difficulty=Uint(0),
        gas_limit=None,
        extra_data=ZERO_HASH32,
        prev_randao=ZERO_HASH32,
        nonce=b"\x00" * 8,
        parent_beacon_block_root=ZERO_HASH32,
    ):
        if (
            self._pending_block
            and self.chain.latest_block.header.number
            != self._pending_block["header"]["number"]
        ):
            raise ValidationError(
                "Cannot build a new pending block until the current pending block has "
                "been included in the chain."
            )

        if gas_limit is None:
            gas_limit = self.chain.latest_block.header.gas_limit

        base_fee_per_gas = self.fork.calculate_base_fee_per_gas(
            block_gas_limit=gas_limit,
            parent_gas_limit=self.chain.latest_block.header.gas_limit,
            parent_gas_used=self.chain.latest_block.header.gas_used,
            parent_base_fee_per_gas=self.chain.latest_block.header.base_fee_per_gas,
        )
        block_number = self.chain.latest_block.header.number + 1

        block_header_fields = {
            "number": block_number,
            "coinbase": coinbase,
            "difficulty": difficulty,
            "gas_limit": gas_limit,
            "timestamp": None,  # set at block finalization
            "extra_data": extra_data,
            "prev_randao": prev_randao,
            "nonce": nonce,
            "parent_hash": self._fork_module.compute_header_hash(
                self.chain.latest_block.header
            ),
            "base_fee_per_gas": base_fee_per_gas,
            "parent_beacon_block_root": parent_beacon_block_root,
            "excess_blob_gas": self._vm_module.gas.calculate_excess_blob_gas(
                self.chain.latest_block.header
            ),
        }
        self._pending_block = {
            "header": block_header_fields,
            "transactions": [],
            "ommers": [],
            "withdrawals": [],
        }

    def _mine_pending_block(self) -> Dict[str, Any]:
        block = self._pending_block
        block_header = block["header"]

        # set the timestamp when mining
        parent_timestamp = self.chain.latest_block.header.timestamp
        current_time = Uint(int(time.time()))
        block_header["timestamp"] = (
            parent_timestamp + 1 if parent_timestamp >= current_time else current_time
        )

        apply_body_output = self._internal_apply_body_validation()
        block_header["bloom"] = apply_body_output["block_logs_bloom"]
        block_header["gas_used"] = apply_body_output["block_gas_used"]
        block_header["state_root"] = apply_body_output["state_root"]
        block_header["receipt_root"] = apply_body_output["receipt_root"]
        block_header["transactions_root"] = apply_body_output["tx_root"]
        block_header["withdrawals_root"] = apply_body_output["withdrawals_root"]
        block_header["blob_gas_used"] = apply_body_output["blob_gas_used"]
        block_header["excess_blob_gas"] = apply_body_output["excess_blob_gas"]
        block_header["ommers_hash"] = apply_body_output["ommers_hash"]

        _eels_block_header = self.fork.Header(**block_header)
        _eels_block = self.fork.Block(
            header=_eels_block_header,
            transactions=tuple(block["transactions"]),
            ommers=tuple(block["ommers"]),
            withdrawals=tuple(block["withdrawals"]),
        )

        self.fork.state_transition(self.chain, _eels_block)

        for i, tx in enumerate(block["transactions"]):
            # update saved tx data post-mining
            tx_hash = self._get_tx_hash(tx)
            updated_tx = self._transactions_map[tx_hash]
            updated_tx["block_number"] = block_header["number"]
            updated_tx["block_hash"] = self._fork_module.compute_header_hash(
                _eels_block_header
            )
            updated_tx["transaction_index"] = i
            self._transactions_map[tx_hash] = updated_tx

            # update receipt values in apply_body_output, post-mining
            updated_receipt = apply_body_output["receipts_map"][tx_hash]
            updated_receipt["block_number"] = block_header["number"]
            updated_receipt["block_hash"] = self._fork_module.compute_header_hash(
                _eels_block_header
            )
            updated_receipt["transaction_index"] = i
            updated_receipt["state_root"] = block_header["state_root"]
            self._receipts_map[tx_hash] = updated_receipt

        return block

    @to_tuple
    def mine_blocks(self, num_blocks: int = 1, coinbase=ZERO_ADDRESS):
        for _ in range(num_blocks):
            self._mine_pending_block()
            self._build_new_pending_block()
            yield self._fork_module.compute_header_hash(self.chain.latest_block.header)

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        return self.chain.state._main_trie._data.keys()

    def add_account(self, private_key):
        pkey = KeyAPI.PrivateKey(private_key)
        address = pkey.public_key.to_canonical_address()
        self._account_keys.append(pkey)
        account = self._get_default_account_state()
        self.fork.set_account(self.chain.state, address, account)

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transaction=True):
        block = None
        is_pending = False

        if block_number == "latest":
            block = self.chain.latest_block
        elif block_number == "earliest":
            block = self.chain.blocks[0]
        elif block_number == "pending":
            block = self._pending_block
            is_pending = True
        elif isinstance(block_number, int):
            # work in reverse order to find the block, since blocks are stored in
            # increasing order by block number
            for i, blk in enumerate(reversed(self.chain.blocks)):
                if blk.header.number == block_number:
                    block = blk

        if block:
            return serialize_block(
                self, block, full_transaction=full_transaction, is_pending=is_pending
            )

        raise BlockNotFound(f"No block found for block number: {block_number}")

    def get_block_by_hash(self, block_hash, full_transaction=True):
        # work in reverse order to find the block, since blocks are stored in
        # increasing order by block number
        for i, bh in enumerate(self._fork_module.get_last_256_block_hashes(self.chain)):
            if bh == block_hash:
                # minus 2 because `get_last_256_block_hashes` mistakenly classifies the
                # genesis header parent hash as a blockhash
                block = list(reversed(self.chain.blocks))[i - 2]
                if block_hash != self._fork_module.compute_header_hash(block.header):
                    # sanity check, we should never get here if the implementation is
                    # correct
                    raise ValueError("Block hash does not match expected hash")

                return serialize_block(self, block, full_transaction=full_transaction)

        raise BlockNotFound(f"No block found for block hash: {block_hash}")

    def get_transaction_by_hash(self, transaction_hash):
        if transaction_hash in self._transactions_map:
            return serialize_transaction(self._transactions_map[transaction_hash])

        raise TransactionNotFound(
            f"No transaction found for transaction hash: {transaction_hash}"
        )

    def get_transaction_receipt(self, transaction_hash):
        if transaction_hash in self._receipts_map:
            return self._receipts_map[transaction_hash]

        raise TransactionNotFound(
            f"No transaction receipt found for transaction hash: {transaction_hash}"
        )

    #
    # Account state
    #
    def get_nonce(self, account, block_number="latest"):
        return self.fork.get_account(self.chain.state, account).nonce

    def get_balance(self, account, block_number="latest"):
        return self.fork.get_account(self.chain.state, account).balance

    def get_code(self, account, block_number="latest"):
        return self.fork.get_account(self.chain.state, account).code

    def get_storage(self, account: Address, slot: int, block_number="latest") -> bytes:
        return self._state_module.get_storage(self.chain.state, account, slot)

    def get_base_fee(self) -> int:
        return self.chain.latest_block.header.base_fee_per_gas

    #
    # Transactions
    #
    def environment(self, tx: Any, gas_available: Any, state: Any = None) -> Any:
        """
        Create the environment for the transaction. The keyword
        arguments are adjusted according to the fork.
        """
        pending_header = self._pending_block["header"]
        kw_arguments = {
            "block_hashes": self._fork_module.get_last_256_block_hashes(self.chain),
            "coinbase": pending_header["coinbase"],
            "number": pending_header["number"],
            "gas_limit": pending_header["gas_limit"],
            "time": pending_header["timestamp"],
            "state": state or self.chain.state,
        }

        if self.fork.is_after_fork("ethereum.paris"):
            kw_arguments["prev_randao"] = pending_header["prev_randao"]
        else:
            kw_arguments["difficulty"] = pending_header["difficulty"]

        if self.fork.is_after_fork("ethereum.istanbul"):
            kw_arguments["chain_id"] = self.chain.chain_id

        check_tx_return = self._check_transaction(tx, gas_available)

        if self.fork.is_after_fork("ethereum.cancun"):
            (
                sender_address,
                effective_gas_price,
                blob_versioned_hashes,
            ) = check_tx_return
            kw_arguments["base_fee_per_gas"] = pending_header["base_fee_per_gas"]
            kw_arguments["caller"] = kw_arguments["origin"] = sender_address
            kw_arguments["gas_price"] = effective_gas_price
            kw_arguments["blob_versioned_hashes"] = blob_versioned_hashes
            kw_arguments["excess_blob_gas"] = pending_header["excess_blob_gas"]
            kw_arguments["transient_storage"] = self.fork.TransientStorage()
        elif self.fork.is_after_fork("ethereum.london"):
            sender_address, effective_gas_price = check_tx_return
            kw_arguments["base_fee_per_gas"] = pending_header["base_fee_per_gas"]
            kw_arguments["caller"] = kw_arguments["origin"] = sender_address
            kw_arguments["gas_price"] = effective_gas_price
        else:
            sender_address = check_tx_return
            kw_arguments["caller"] = kw_arguments["origin"] = sender_address
            kw_arguments["gas_price"] = tx.gas_price

        kw_arguments["traces"] = []
        return self.fork.Environment(**kw_arguments)

    def _check_transaction(self, tx: Any, gas_available: Any = None) -> Any:
        """
        Implements the check_transaction function of the fork.
        The arguments to be passed are adjusted according to the fork.
        """
        if gas_available is None:
            gas_available = self.chain.latest_block.header.gas_limit

        if self.fork.is_after_fork("ethereum.cancun"):
            return self.fork.check_transaction(
                self.chain.state,
                tx,
                gas_available,
                self.chain.chain_id,
                self._pending_block["header"]["base_fee_per_gas"],
                self._vm_module.gas.calculate_excess_blob_gas(
                    self.chain.latest_block.header
                ),
            )
        arguments = [tx]

        if self.fork.is_after_fork("ethereum.london"):
            arguments.append(self._pending_block["header"]["base_fee_per_gas"])

        arguments.append(gas_available)

        if self.fork.is_after_fork("ethereum.spurious_dragon"):
            arguments.append(self.chain.chain_id)

        return self.fork.check_transaction(*arguments)

    def _get_normalized_and_unsigned_evm_transaction(self, transaction: Dict[str, Any]):
        return normalize_transaction_fields(
            transaction,
            self.chain.chain_id,
            self.get_nonce(transaction["from"]),
            self.get_base_fee(),
        )

    def _get_normalized_and_signed_evm_transaction(
        self, transaction: Dict[str, Any]
    ) -> Any:
        if transaction["from"] not in self.get_accounts():
            raise ValidationError(
                'No valid "from" key was provided in the transaction '
                "which is required for transaction signing."
            )

        private_key = self._key_lookup[transaction["from"]]
        eth_tester_normalized_transaction = normalize_transaction_fields(
            transaction,
            self.chain.chain_id,
            self.get_nonce(transaction["from"]),
            self.get_base_fee(),
        )

        # EELS-specific normalization
        eels_normalized_transaction = eels_normalize_transaction(
            eth_tester_normalized_transaction
        )
        signed_transaction = self.sign_transaction(
            eels_normalized_transaction, private_key
        )
        return signed_transaction

    def sign_transaction(
        self, json_tx: Dict[str, Any], private_key: PrivateKey
    ) -> Dict[str, Any]:
        """
        Sign a transaction with a given private key.

        Post spurious dragon, the transaction is signed according to EIP-155
        if the protected flag is missing or set to true.
        """
        protected = json_tx.get("protected", True)

        # for some reason `TransactionLoad` decides to also validate signed transaction
        # fields, r, s, v, y_parity, etc. which is not necessary here as we are still
        # in the process of signing the transaction.
        json_tx["r"], json_tx["s"], json_tx["v"], json_tx["y_parity"] = (
            "0x0",
            "0x0",
            "0x0",
            "0x0",
        )
        tx = TransactionLoad(json_tx, self.fork).read()

        if isinstance(tx, bytes):
            tx_decoded = self.fork.decode_transaction(tx)
        else:
            tx_decoded = tx

        secret_key = hex_to_uint(private_key.to_hex())
        if self.fork.is_after_fork("ethereum.berlin"):
            tx_class = self.fork.LegacyTransaction
        else:
            tx_class = self.fork.Transaction

        if isinstance(tx_decoded, tx_class):
            if self.fork.is_after_fork("ethereum.spurious_dragon"):
                if protected:
                    signing_hash = self.fork.signing_hash_155(tx_decoded, U64(1))
                    v_addend = 37  # Assuming chain_id = 1
                else:
                    signing_hash = self.fork.signing_hash_pre155(tx_decoded)
                    v_addend = 27
            else:
                signing_hash = self.fork.signing_hash(tx_decoded)
                v_addend = 27
        elif isinstance(tx_decoded, self.fork.AccessListTransaction):
            signing_hash = self.fork.signing_hash_2930(tx_decoded)
            v_addend = 0
        elif isinstance(tx_decoded, self.fork.FeeMarketTransaction):
            signing_hash = self.fork.signing_hash_1559(tx_decoded)
            v_addend = 0
        elif isinstance(tx_decoded, self.fork.BlobTransaction):
            signing_hash = self.fork.signing_hash_4844(tx_decoded)
            v_addend = 0
        else:
            raise ValidationError("Unknown transaction type")

        r, s, y = secp256k1_sign(signing_hash, secret_key)
        json_tx["r"] = hex(r)
        json_tx["s"] = hex(s)
        json_tx["v"] = hex(y + v_addend)

        if v_addend == 0:
            json_tx["y_parity"] = json_tx["v"]

        return json_tx

    def _get_tx_hash(self, tx: Any) -> bytes:
        """
        Get the transaction hash of a transaction.
        """
        if self.fork.is_after_fork("ethereum.berlin") and not isinstance(
            tx, self.fork.LegacyTransaction
        ):
            return keccak256(self.fork.encode_transaction(tx))
        else:
            return keccak256(rlp.encode(tx))

    def send_raw_transaction(self, raw_transaction):
        evm_transaction = self._transactions_module.decode_transaction(raw_transaction)
        self._check_transaction(evm_transaction)

        tx_hash = self._get_tx_hash(evm_transaction)
        self._pending_block["transactions"].append(evm_transaction)
        # TODO: This will likely break (untested). We need to get the tx as json with
        #  all fields before adding it to the _transactions_map.
        self._transactions_map[tx_hash] = evm_transaction
        return tx_hash

    def send_signed_transaction(self, signed_json_tx, block_number="latest"):
        eels_transaction = TransactionLoad(signed_json_tx, self.fork).read()
        self._check_transaction(
            eels_transaction,
            # TODO: Stop lazily plugging in the parent block's gas limit
            self.chain.latest_block.header.gas_limit,
        )

        tx_hash = self._get_tx_hash(eels_transaction)
        self._pending_block["transactions"].append(eels_transaction)
        self._transactions_map[tx_hash] = serialize_transaction(
            signed_json_tx, pending_block=True
        )
        return tx_hash

    def send_transaction(self, transaction):
        signed_and_normalized_json_tx = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )
        eels_tx = TransactionLoad(signed_and_normalized_json_tx, self.fork).read()
        self._check_transaction(
            eels_tx,
            # TODO: Stop lazily plugging in the parent block's gas limit
            self.chain.latest_block.header.gas_limit,
        )

        tx_hash = self._get_tx_hash(eels_tx)
        self._transactions_map[tx_hash] = serialize_transaction_for_block(
            self,
            serialized_block=serialize_block(
                self, self._pending_block, full_transaction=False, is_pending=True
            ),
            tx=eels_tx,
            index=len(self._pending_block["transactions"]),
        )
        self._pending_block["transactions"].append(eels_tx)
        return tx_hash

    def apply_withdrawals(
        self,
        withdrawals_list: List[Dict[str, Union[int, str]]],
    ) -> None:
        """
        Send withdrawal requests to the pending block.
        """
        validate_inbound_withdrawals(withdrawals_list)
        for withdrawal in withdrawals_list:
            self._pending_block["withdrawals"].append(
                self.fork.Withdrawal(
                    index=withdrawal["index"],
                    validation_index=withdrawal["validator_index"],
                    address=withdrawal["address"],
                    amount=withdrawal["amount"],
                )
            )

    def _max_available_gas(self):
        header = self.chain.latest_block.header
        return header.gas_limit - header.gas_used

    def _run_transaction_against_synthetic_state(self, transaction):
        signed_and_normalized_json_tx = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )
        signed_transaction = TransactionLoad(
            signed_and_normalized_json_tx, self.fork
        ).read()
        self._check_transaction(
            signed_transaction,
            # TODO: Stop lazily plugging in the parent block's gas limit
            self.chain.latest_block.header.gas_limit,
        )
        # run the transaction against a synthetic version of the state
        state_copy = self._create_synthetic_state()
        env = self.environment(
            signed_transaction, self._max_available_gas(), state=state_copy
        )
        return env, signed_transaction

    def estimate_gas(self, transaction, block_number="latest"):
        transaction["gas"] = MINIMUM_GAS_ESTIMATE
        env, signed_evm_transaction = self._run_transaction_against_synthetic_state(
            transaction
        )
        output = self.fork.process_transaction(env, signed_evm_transaction)
        return output[0]  # total gas consumed

    def call(self, transaction, block_number="latest"):
        env, signed_evm_transaction = self._run_transaction_against_synthetic_state(
            transaction
        )
        self.fork.process_transaction(env, signed_evm_transaction)
        raise NotImplementedError("Continue implementation...")
        # TODO

    def _extract_contract_address(self, pre_state, post_state):
        # TODO: make this more robust !!
        for address in post_state._main_trie._data:
            if address not in pre_state._main_trie._data:
                if self._state_module.get_account(post_state, address).code != b"":
                    return address

        return None
