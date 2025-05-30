from contextlib import (
    contextmanager,
)
import copy
import os
import time
from typing import (
    Any,
    Dict,
    List,
    Tuple,
    Union,
)

from eth_account import (
    Account,
)
from eth_keys import (
    KeyAPI,
)
from eth_keys.datatypes import (
    PrivateKey,
)
from eth_typing import (
    Address,
)
from eth_utils import (
    int_to_big_endian,
    logging,
    to_canonical_address,
    to_dict,
    to_tuple,
    to_wei,
)

from .utils import (
    eels_is_available,
)

if eels_is_available():
    from ethereum.cancun.fork import (
        BlockChain,
    )
    from ethereum.crypto.hash import (
        keccak256,
    )
    from ethereum.exceptions import (
        EthereumException,
    )
    from ethereum.prague.requests import (
        compute_requests_hash,
    )
    from ethereum.utils.hexadecimal import (
        hex_to_uint,
    )
    from ethereum_rlp import (
        rlp,
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
    from ethereum_types.numeric import (
        U64,
        U256,
        Uint,
    )
else:

    class BlockChain:
        ...

    ForkLoad = None
    TransactionLoad = None
    U64 = None
    U256 = None
    Uint = None
    SYSTEM_ADDRESS = None
    SYSTEM_TRANSACTION_GAS = None
    keccak256 = None
    EthereumException = None
    hex_to_uint = None
    secp256k1_sign = None
    rlp = None
    compute_requests_hash = None


from eth_tester.backends.base import (
    BaseChainBackend,
)
from eth_tester.backends.common import (
    merge_genesis_overrides,
)
from eth_tester.constants import (
    BEACON_ROOTS_CONTRACT_ADDRESS,
    BEACON_ROOTS_CONTRACT_CODE,
    ZERO_ADDRESS,
    ZERO_HASH32,
)
from eth_tester.exceptions import (
    BackendDistributionNotFound,
    BlockNotFound,
    TransactionFailed,
    TransactionNotFound,
    ValidationError,
)

from ...utils.accounts import (
    get_account_keys_from_mnemonic,
    get_default_account_keys,
)
from ...utils.transactions import (
    calculate_effective_gas_price,
    normalize_transaction_fields,
)
from ...validation.inbound import (
    validate_inbound_withdrawals,
)
from .eels_normalizers import (
    eels_normalize_inbound_raw_blob_transaction,
    eels_normalize_transaction,
)
from .serializers import (
    serialize_block,
    serialize_eels_transaction_for_block,
    serialize_transaction,
)
from .utils import (
    EELSStateContext,
)

GENESIS_DIFFICULTY = 131072
# gas limit at London fork on mainnet (arbitrary/taken from pyevm backend)
GENESIS_GAS_LIMIT = 30029122
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
    pending_block = None

    @property
    def latest_block(self):
        return self.blocks[-1]


class EELSBackend(BaseChainBackend):
    logger = logging.get_logger("eth-tester.backends.EELSBackend")
    handles_pending_transactions = True

    _state_context = None
    _state_context_history = {}

    def __init__(
        self,
        fork_name: str = None,
        genesis_params=None,
        genesis_state=None,
        num_accounts=None,
        mnemonic=None,
        hd_path=None,
        debug_mode: bool = False,
    ):
        if not eels_is_available():
            raise BackendDistributionNotFound(
                "The EELS is package is not available or not up to date. "
                "The `EELSBackend` requires ethereum/execution-specs to be installed "
                "and importable."
            )

        if fork_name in (None, "latest"):
            # always try to keep this as the latest
            fork_name = "cancun"

        self.fork = ForkLoad(str(fork_name).lower())
        self._fork_module = self.fork._module("fork")
        self._state_module = self.fork._module("state")
        self._vm_module = self.fork._module("vm")
        self._blocks_module = self.fork._module("blocks")
        self._transactions_module = self.fork._module("transactions")
        self._fork_types = self.fork._module("fork_types")
        self._utils_module = self.fork._module("utils")
        self._trie_module = self.fork._module("trie")
        self._bloom_module = self.fork._module("bloom")
        self._account_keys = []
        self.reset_to_genesis(
            genesis_params=genesis_params,
            genesis_state=genesis_state,
            num_accounts=num_accounts,
            mnemonic=mnemonic,
            hd_path=hd_path,
        )
        self._debug_mode = debug_mode

    @property
    def _pending_block(self):
        return self.chain.pending_block

    @_pending_block.setter
    def _pending_block(self, value):
        self.chain.pending_block = value

    @property
    def chain(self):
        return self._state_context.chain

    @chain.setter
    def chain(self, value):
        self._state_context.chain = value

    @property
    def _transactions_map(self):
        return self._state_context.transactions_map if self._state_context else {}

    @property
    def _receipts_map(self):
        return self._state_context.receipts_map if self._state_context else {}

    def time_travel(self, to_timestamp):
        self._pending_block["header"]["timestamp"] = U256(to_timestamp)
        self.mine_blocks()
        return to_timestamp

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
                difficulty=Uint(GENESIS_DIFFICULTY),
                number=Uint(0),
                gas_limit=Uint(GENESIS_GAS_LIMIT),
                gas_used=Uint(0),
                timestamp=U256(int(time.time())),
                extra_data=ZERO_HASH32,
                prev_randao=ZERO_HASH32,
                nonce=GENESIS_NONCE,
                withdrawals_root=ZERO_HASH32,
                blob_gas_used=U64(0),
                excess_blob_gas=U64(0),
                parent_beacon_block_root=ZERO_HASH32,
                base_fee_per_gas=Uint(1000000000),
            ),
            transactions=(),
            ommers=(),
            withdrawals=(),
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

        if self.fork.is_after_fork("ethereum.cancun"):
            genesis_state[
                BEACON_ROOTS_CONTRACT_ADDRESS
            ] = self._get_default_account_state(
                overrides={"code": BEACON_ROOTS_CONTRACT_CODE}
            )

        eels_state = self._fork_module.State()
        for address, account in genesis_state.items():
            self.fork.set_account(eels_state, address, account)

        chain = EELSBlockChain(
            blocks=[self._generate_genesis_block()],
            state=eels_state,
            chain_id=U64(1),
        )
        self._state_context = EELSStateContext(
            chain=chain,
            transactions_map=self._transactions_map,
            receipts_map=self._receipts_map,
        )
        self._build_new_pending_block()
        self._state_context_history[0] = self._copy_state_context()

    #
    # Private Accounts API
    #
    @property
    def _key_lookup(self):
        return {
            key.public_key.to_canonical_address(): key for key in self._account_keys
        }

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
                overrides=overrides or {"balance": U256(to_wei(1000000, "ether"))}
            )
            yield private_key.public_key.to_canonical_address(), account_state

    #
    # Snapshot API
    #
    def take_snapshot(self):
        return int(self.chain.latest_block.header.number)

    def revert_to_snapshot(self, block_number):
        if block_number not in self._state_context_history:
            raise ValidationError(
                f"No snapshot found for block number: {block_number}."
            )
        self._state_context = self._copy_state_context(
            state_context=self._state_context_history[block_number]
        )

    #
    # State management
    #
    def _copy_state_context(self, state_context=None):
        if state_context is None:
            state_context = self._state_context

        state_copy = self.fork.State()
        state_copy._main_trie = self._state_module.copy_trie(
            state_context.chain.state._main_trie
        )
        state_copy._storage_tries = {
            k: self._state_module.copy_trie(t)
            for (k, t) in state_context.chain.state._storage_tries.items()
        }

        state_context_copy = EELSStateContext(
            chain=EELSBlockChain(
                blocks=state_context.chain.blocks[:],
                state=state_copy,
                chain_id=state_context.chain.chain_id,
            ),
            transactions_map=copy.deepcopy(state_context.transactions_map),
            receipts_map=copy.deepcopy(state_context.receipts_map),
        )
        state_context_copy.chain.pending_block = self._copy_pending_block(
            state_context.chain.pending_block
        )
        return state_context_copy

    @contextmanager
    def _state_context_manager(self, block_number, synthetic_state=False):
        pending_block_number = int(self._pending_block["header"]["number"])
        if block_number in ("latest", "safe", "finalized"):
            block_number = int(self.chain.latest_block.header.number)
        elif block_number == "pending":
            block_number = pending_block_number
        elif block_number == "earliest":
            block_number = 0

        block_number = int(block_number)
        if block_number < pending_block_number:
            # if not current state, generate a snapshot and use the desired state
            current_state_context = self._copy_state_context()
            desired_state_context = self._copy_state_context(
                state_context=self._state_context_history[block_number]
            )
            try:
                self._state_context = desired_state_context
                yield
            finally:
                self._state_context = current_state_context
        elif block_number == pending_block_number and synthetic_state:
            current_state_context = self._copy_state_context()
            state_context_copy = self._copy_state_context()
            try:
                # build the state from a copy of the current state
                self._state_context = state_context_copy
                yield
            finally:
                # restore the original state
                self._state_context = current_state_context
        else:
            yield

    # TODO: move somewhere more appropriate
    def _build_block_env(self):
        block_env_args = dict(self._pending_block["header"])
        block_env_args["time"] = block_env_args.pop("timestamp")
        block_env_args["block_gas_limit"] = block_env_args.pop("gas_limit")

        # remove any fields that are not in the fork's BlockEnvironment
        for prop in dict(block_env_args):
            if prop not in self._vm_module.BlockEnvironment.__annotations__:
                block_env_args.pop(prop)

        block_env = self._vm_module.BlockEnvironment(
            chain_id=self.chain.chain_id,
            state=self.chain.state,
            block_hashes=self._fork_module.get_last_256_block_hashes(self.chain),
            **block_env_args,
        )
        return block_env

    #
    # Importing blocks
    #
    def _internal_apply_body_validation(self) -> Tuple[Any, Any]:
        """
        Use a similar approach to EELS to apply the body, only with a synthetic
        state. This is used to validate the body and generate appropriate values
        for calculated fields when building blocks locally.
        """
        with self._state_context_manager("pending", synthetic_state=True):
            apply_body_args = {"block_env": self._build_block_env()}
            for prop in dict(self._pending_block):
                if prop in self._fork_module.apply_body.__annotations__:
                    apply_body_args[prop] = self._pending_block[prop]

            return self._state_context, self._fork_module.apply_body(**apply_body_args)

    def _build_new_pending_block(
        self,
        coinbase=ZERO_ADDRESS,
        difficulty=None,
        gas_limit=None,
        extra_data=ZERO_HASH32,
        prev_randao=None,
        nonce=b"\x00" * 8,
        parent_beacon_block_root=None,
        timestamp=None,
    ):
        if difficulty is None:
            difficulty = Uint(0)

        latest_block_header = self.chain.latest_block.header
        if (
            self._pending_block
            and latest_block_header.number != self._pending_block["header"]["number"]
        ):
            raise ValidationError(
                "Cannot build a new pending block until the current pending block has "
                "been included in the chain."
            )

        gas_limit = gas_limit or latest_block_header.gas_limit
        base_fee_per_gas = self.fork.calculate_base_fee_per_gas(
            block_gas_limit=gas_limit,
            parent_gas_limit=latest_block_header.gas_limit,
            parent_gas_used=latest_block_header.gas_used,
            parent_base_fee_per_gas=latest_block_header.base_fee_per_gas,
        )
        block_header_fields = {
            "number": latest_block_header.number + Uint(1),
            "coinbase": coinbase,
            "difficulty": difficulty,
            "gas_limit": gas_limit,
            "timestamp": timestamp,
            "extra_data": extra_data,
            # the randao is probably fine for now
            "prev_randao": prev_randao or os.urandom(32),
            "nonce": nonce,
            "parent_hash": keccak256(rlp.encode(latest_block_header)),
            "base_fee_per_gas": base_fee_per_gas,
            # TODO: can we do better than random generation for beacon parent root?
            "parent_beacon_block_root": parent_beacon_block_root or os.urandom(32),
            "excess_blob_gas": self._vm_module.gas.calculate_excess_blob_gas(
                latest_block_header
            ),
        }
        self._pending_block = {
            "header": block_header_fields,
            "transactions": [],
            "ommers": [],
            "withdrawals": [],
        }

    @staticmethod
    def _copy_pending_block(pending_block) -> Dict[str, Any]:
        return {
            "header": copy.deepcopy(pending_block["header"]),
            "transactions": pending_block["transactions"][:],
            "ommers": pending_block["ommers"][:],
            "withdrawals": pending_block["withdrawals"][:],
        }

    def _mine_pending_block(self, timestamp: U256 = None) -> Dict[str, Any]:
        # initial validation
        block = self._pending_block
        block_header = block["header"]

        if block_header["number"] != self.chain.latest_block.header.number + Uint(1):
            raise ValidationError(
                f"Cannot mine a block with a number, {block_header['number']}, that is "
                "not one greater than the latest block number, "
                f"{self.chain.latest_block.header.number}."
            )

        # timestamp validation
        block_header["difficulty"] = block_header["difficulty"]
        if block_header["timestamp"] is None:
            # set the timestamp when mining unless already set by time_travel
            parent_timestamp = self.chain.latest_block.header.timestamp
            current_time = U256(timestamp or int(time.time()))
            block_header["timestamp"] = U256(
                parent_timestamp + U256(1)
                if parent_timestamp >= current_time
                else current_time
            )

        # process block
        (synthetic_state_context, block_output) = self._internal_apply_body_validation()

        # build the header
        block_header["state_root"] = self._state_module.state_root(
            synthetic_state_context.chain.state
        )
        block_header["bloom"] = self._bloom_module.logs_bloom(block_output.block_logs)
        block_header["transactions_root"] = self._trie_module.root(
            block_output.transactions_trie
        )
        block_header["receipt_root"] = self._trie_module.root(
            block_output.receipts_trie
        )
        block_header["withdrawals_root"] = self._trie_module.root(
            block_output.withdrawals_trie
        )
        block_header["gas_used"] = block_output.block_gas_used

        if hasattr(block_output, "blob_gas_used"):
            block_header["blob_gas_used"] = block_output.blob_gas_used
        if hasattr(block_output, "requests"):
            block_header["requests_hash"] = compute_requests_hash(block_output.requests)
        block_header["ommers_hash"] = keccak256(rlp.encode(block["ommers"]))

        # build the block
        _eels_block_header = self.fork.Header(**block_header)
        _eels_block = self.fork.Block(
            header=_eels_block_header,
            transactions=tuple(block["transactions"]),
            ommers=tuple(block["ommers"]),
            withdrawals=tuple(block["withdrawals"]),
        )

        # apply the block
        self.fork.state_transition(self.chain, _eels_block)
        assert self.fork.state_root(self.chain.state) == block_header["state_root"]
        blockhash = keccak256(rlp.encode(_eels_block_header))
        assert blockhash == keccak256(rlp.encode(self.chain.latest_block.header))

        # update transactions in the block post-mining
        blocknum = int(block_header["number"])

        # logIndex is sequential across all transactions in a block
        log_index = 0

        for i, (trie_key, tx) in enumerate(
            block_output.transactions_trie._data.items()
        ):
            # update saved tx data post-mining
            tx_hash = self._get_tx_hash(tx)
            updated_tx = self._transactions_map[tx_hash]
            updated_tx["blockNumber"] = blocknum
            updated_tx["blockHash"] = blockhash
            updated_tx["transactionIndex"] = i
            self._transactions_map[tx_hash] = updated_tx

            # update trie_receipt values in apply_body_output, post-mining
            trie_receipt = block_output.receipts_trie._data[trie_key]

            # decode receipt if necessary
            if isinstance(trie_receipt, bytes):
                trie_receipt = rlp.decode_to(
                    self._blocks_module.Receipt, trie_receipt[1:]
                )

            updated_receipt = {"logs": []}

            # transaction references
            updated_receipt["transactionHash"] = tx_hash
            updated_receipt["transactionIndex"] = i
            updated_receipt["blockNumber"] = blocknum
            updated_receipt["blockHash"] = blockhash

            # execution result
            updated_receipt["status"] = int(trie_receipt.succeeded)

            # TODO: not sure where to get gasUsed, using cumulative for now
            updated_receipt["gasUsed"] = int(trie_receipt.cumulative_gas_used)
            updated_receipt["cumulativeGasUsed"] = int(trie_receipt.cumulative_gas_used)
            updated_receipt["effectiveGasPrice"] = calculate_effective_gas_price(
                updated_tx,
                block_header,
            )

            # address information
            updated_receipt["from"] = updated_tx["from"]
            updated_receipt["to"] = updated_tx["to"]

            # TODO move this somewhere
            def calculate_contract_address(sender_address, nonce):
                # Contract address = keccak256(rlp([sender, nonce]))[-20:]
                rlp_encoded = rlp.encode([sender_address, nonce])
                hash_result = keccak256(rlp_encoded)
                return hash_result[-20:]  # Last 20 bytes = address

            updated_receipt["contractAddress"] = (
                calculate_contract_address(
                    updated_tx["from"], Uint(updated_tx["nonce"])
                )
                if not updated_tx["to"]
                else None
            )

            updated_receipt["stateRoot"] = block_header["state_root"]
            for log in trie_receipt.logs:
                updated_receipt["logs"].append(
                    {
                        "address": log.address,
                        "topics": log.topics,
                        "data": log.data,
                        "blockNumber": blocknum,
                        "blockHash": blockhash,
                        "logIndex": log_index,
                        "transactionIndex": i,
                        "transactionHash": tx_hash,
                        "type": "mined",
                    }
                )
                log_index += 1

            updated_receipt["type"] = updated_tx["type"]

            updated_receipt["blobGasUsed"] = int(block_header["blob_gas_used"])

            blob_gas_price = self._vm_module.gas.calculate_blob_gas_price(
                block_header["excess_blob_gas"]
            )
            updated_receipt["blobGasPrice"] = int(blob_gas_price)

            self._receipts_map[tx_hash] = updated_receipt

        # update saved block data post-mining
        self._build_new_pending_block()
        self._state_context_history[blocknum] = self._copy_state_context()
        return block

    @to_tuple
    def mine_blocks(self, num_blocks: int = 1, coinbase=ZERO_ADDRESS):
        for _ in range(num_blocks):
            self._mine_pending_block()
            yield keccak256(rlp.encode(self.chain.latest_block.header))

    #
    # Accounts
    #
    @to_tuple
    def get_accounts(self):
        return self._key_lookup.keys()

    def add_account(self, private_key):
        pkey = KeyAPI.PrivateKey(private_key)
        address = pkey.public_key.to_canonical_address()
        self._account_keys.append(pkey)
        account = self._get_default_account_state()
        self.fork.set_account(self.chain.state, address, account)

    #
    # Chain data
    #
    def get_block_by_number(self, block_number, full_transactions=True):
        block = None
        is_pending = False

        if block_number in ("latest", "safe", "finalized"):
            block = self.chain.latest_block
        elif block_number == "earliest":
            block = self.chain.blocks[0]
        elif block_number == "pending":
            block = self._pending_block
            is_pending = True
        elif isinstance(block_number, int):
            # work in reverse order to find the block, since blocks are stored in
            # increasing order by block number
            for blk in reversed(self.chain.blocks):
                if blk.header.number == block_number:
                    block = blk

        if block:
            return serialize_block(
                self, block, full_transactions=full_transactions, is_pending=is_pending
            )

        raise BlockNotFound(f"No block found for block number: {block_number}.")

    def get_block_by_hash(self, block_hash, full_transactions=True):
        for i, bh in enumerate(self._fork_module.get_last_256_block_hashes(self.chain)):
            if bh == ZERO_HASH32:
                # `get_last_256_block_hashes()` pulls the `parentHash` of the genesis
                # header as if it was an actual block hash, so we skip it
                continue

            if bh == block_hash:
                # bc of the comment above, we have to use i - 1 since we skip the ghost
                # parent of the genesis block
                block = self.chain.blocks[i - 1]
                if block_hash != keccak256(rlp.encode(block.header)):
                    # sanity check, should not get here if the implementation is correct
                    raise ValueError("Block hash does not match the expected hash.")
                return serialize_block(self, block, full_transactions=full_transactions)

        raise BlockNotFound(f"No block found for block hash: {block_hash}.")

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
    def get_nonce(self, account, block_number="pending"):
        with self._state_context_manager(block_number):
            return int(self._fork_module.get_account(self.chain.state, account).nonce)

    def get_balance(self, account, block_number="pending"):
        with self._state_context_manager(block_number):
            return int(self._fork_module.get_account(self.chain.state, account).balance)

    def get_code(self, account, block_number="pending"):
        with self._state_context_manager(block_number):
            return self._fork_module.get_account(self.chain.state, account).code

    def get_storage(
        self, account: Address, slot: Union[int, bytes], block_number="pending"
    ) -> int:
        if isinstance(slot, int):
            slot = int_to_big_endian(slot)
        # left pad with zero bytes to 32 bytes
        slot = slot.rjust(32, b"\x00")
        with self._state_context_manager(block_number):
            return int(self._state_module.get_storage(self.chain.state, account, slot))

    def get_base_fee(self) -> int:
        return self._pending_block["header"]["base_fee_per_gas"]

    #
    # Transactions
    #
    def _synthetic_tx_environment(
        self,
        tx: Any,
    ) -> Any:
        """
        Create the environment for the transaction. The keyword
        arguments are adjusted according to the fork. If the block number is
        provided, the state is generated for that block number.
        """
        block_header = self._pending_block["header"]
        gas_available = block_header["gas_limit"] - block_header.get(
            "gas_used", Uint(0)
        )

        # TODO clean up, don't need kw_arguments anymore, just tx_env
        kw_arguments = {
            "block_hashes": self._fork_module.get_last_256_block_hashes(self.chain),
            "coinbase": block_header["coinbase"],
            "number": self.chain.latest_block.header.number,
            "gas_limit": block_header["gas_limit"],
            "time": block_header.get("timestamp", int(time.time())),
            "state": self.chain.state,
        }
        if self.fork.is_after_fork("ethereum.paris"):
            kw_arguments["prev_randao"] = block_header["prev_randao"]
        else:
            kw_arguments["difficulty"] = block_header["difficulty"]

        if self.fork.is_after_fork("ethereum.istanbul"):
            kw_arguments["chain_id"] = self.chain.chain_id

        check_tx_return = self._check_transaction(tx, gas_available)
        if self.fork.is_after_fork("ethereum.cancun"):
            (
                sender_address,
                effective_gas_price,
                blob_versioned_hashes,
                tx_blob_gas_used,
            ) = check_tx_return
            kw_arguments["base_fee_per_gas"] = block_header["base_fee_per_gas"]
            kw_arguments["gas_price"] = effective_gas_price
            kw_arguments["blob_versioned_hashes"] = blob_versioned_hashes
            kw_arguments["excess_blob_gas"] = U64(block_header["excess_blob_gas"])
            kw_arguments["transient_storage"] = self._vm_module.TransientStorage()
        elif self.fork.is_after_fork("ethereum.london"):
            sender_address, effective_gas_price = check_tx_return
            kw_arguments["base_fee_per_gas"] = block_header["base_fee_per_gas"]
            kw_arguments["gas_price"] = effective_gas_price
        else:
            sender_address = check_tx_return
            kw_arguments["gas_price"] = tx.gas_price

        kw_arguments["caller"] = kw_arguments["origin"] = sender_address
        kw_arguments["traces"] = []

        """

        Right now, kw_arguments contains:
        'base_fee_per_gas',
        'blob_versioned_hashes',
        'block_hashes',
        'caller',
        'chain_id',
        'coinbase',
        'excess_blob_gas',
        'gas_limit',
        'gas_price',
        'number',
        'origin',
        'prev_randao',
        'state',
        'time',
        'traces'
        'transient_storage',

        Class TransactionEnvironment contains:
            access_list_addresses: Set[Address]
            access_list_storage_keys: Set[Tuple[Address, Bytes32]]
            blob_versioned_hashes: Tuple[VersionedHash, ...]
            gas: Uint
            gas_price: Uint
            index_in_block: Optional[Uint]
            origin": Address
            traces: List[dict]
            transient_storage: TransientStorage
            tx_hash: Optional[Hash32]

        """
        tx_env = {
            "origin": sender_address,
            "gas_price": kw_arguments["gas_price"],
            "gas": kw_arguments["gas_limit"],
            "access_list_addresses": set(),
            "access_list_storage_keys": set(),
            "transient_storage": kw_arguments["transient_storage"],
            "blob_versioned_hashes": kw_arguments["blob_versioned_hashes"],
            "index_in_block": None,
            "tx_hash": None,
            "traces": [],
        }
        # return self._vm_module.TransactionEnvironment(**kw_arguments)
        return self._vm_module.TransactionEnvironment(**tx_env)

    def _check_transaction(self, tx: Any, gas_available: Any = None) -> Any:
        """
        Implements the check_transaction function of the fork.
        The arguments to be passed are adjusted according to the fork.
        """
        if gas_available is None:
            # TODO: stop lazily using the latest block gas limit
            gas_available = self.chain.latest_block.header.gas_limit

        base_fee = self._pending_block["header"]["base_fee_per_gas"]
        if self.fork.is_after_fork("ethereum.cancun"):
            block_env = self._vm_module.BlockEnvironment(
                chain_id=U64(self.chain.chain_id),
                state=self.chain.state,
                block_gas_limit=Uint(gas_available),
                block_hashes=self._fork_module.get_last_256_block_hashes(self.chain),
                coinbase=self._pending_block["header"]["coinbase"],
                number=Uint(self.chain.latest_block.header.number),
                base_fee_per_gas=Uint(base_fee),
                time=U256(int(time.time())),
                prev_randao=self._pending_block["header"]["prev_randao"],
                excess_blob_gas=U64(
                    self._vm_module.gas.calculate_excess_blob_gas(
                        self.chain.latest_block.header
                    )
                ),
                parent_beacon_block_root=self._pending_block["header"][
                    "parent_beacon_block_root"
                ],
            )
            # TODO: maybe this should be pulled from somewhere?
            block_output = self._vm_module.BlockOutput(
                block_gas_used=Uint(0),
                transactions_trie=self._trie_module.Trie(secured=False, default=None),
                receipts_trie=self._trie_module.Trie(secured=False, default=None),
                block_logs=tuple(),
                withdrawals_trie=self._trie_module.Trie(secured=False, default=None),
                blob_gas_used=U64(0),
            )

            return self._fork_module.check_transaction(
                block_env,
                block_output,
                tx,
            )

        arguments = [tx]

        if self.fork.is_after_fork("ethereum.london"):
            arguments.append(base_fee)

        arguments.append(gas_available)

        if self.fork.is_after_fork("ethereum.spurious_dragon"):
            arguments.append(self.chain.chain_id)

        return self._fork_module.check_transaction(*arguments)

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
        sender_address = transaction["from"]
        if sender_address not in self._key_lookup:
            raise ValidationError(
                'No valid "from" key was provided in the transaction '
                f"which is required for transaction signing: `{sender_address}`."
            )

        private_key = self._key_lookup[sender_address]
        eth_tester_normalized_transaction = normalize_transaction_fields(
            transaction,
            int(self.chain.chain_id),
            self.get_nonce(sender_address),
            int(self.get_base_fee()),
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
                    signing_hash = self.fork.signing_hash_155(
                        tx_decoded, self.chain.chain_id
                    )
                    v_addend = int(self.chain.chain_id) * 2 + 35
                else:
                    signing_hash = self.fork.signing_hash_pre155(tx_decoded)
                    v_addend = 27
            else:
                signing_hash = self.fork.signing_hash(tx_decoded)
                v_addend = 27
            # legacy transaction, pop out y_parity if it exists
            json_tx.pop("y_parity", None)
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

        r, s, y = secp256k1_sign(signing_hash, int(secret_key))
        json_tx["r"] = hex(r)
        json_tx["s"] = hex(s)
        json_tx["v"] = hex(int(y) + v_addend)

        if v_addend == 0:
            json_tx["y_parity"] = json_tx["v"]

        return json_tx

    def _get_tx_hash(self, tx: Any) -> bytes:
        """
        Get the transaction hash of a transaction.
        """
        if isinstance(tx, bytes):
            tx = self.fork.decode_transaction(tx)

        if self.fork.is_after_fork("ethereum.berlin") and not isinstance(
            tx, self.fork.LegacyTransaction
        ):
            return keccak256(self.fork.encode_transaction(tx))
        else:
            return keccak256(rlp.encode(tx))

    def send_raw_transaction(self, raw_transaction):
        if raw_transaction[0] == 3:
            # use eth-account to decode since EELS doesn't know how to handle blob data
            tx_dict = eels_normalize_inbound_raw_blob_transaction(
                self,
                raw_transaction,
            )
            eels_transaction = self._transactions_module.BlobTransaction(**tx_dict)
        else:
            try:
                eels_transaction = self.fork.decode_transaction(raw_transaction)
            except EthereumException:
                eels_transaction = rlp.decode_to(
                    self._transactions_module.LegacyTransaction, raw_transaction
                )

        self._check_transaction(eels_transaction)
        self._pending_block["transactions"].append(eels_transaction)
        tx_hash = self._get_tx_hash(eels_transaction)
        self._transactions_map[tx_hash] = serialize_eels_transaction_for_block(
            self,
            tx=eels_transaction,
            index=len(self._pending_block["transactions"]),
            block_number=self._pending_block["header"]["number"],
        )
        return tx_hash

    def send_signed_transaction(self, signed_json_tx, block_number="pending"):
        normalized = eels_normalize_transaction(signed_json_tx)
        eels_transaction = TransactionLoad(normalized, self.fork).read()
        self._check_transaction(eels_transaction)

        self._pending_block["transactions"].append(eels_transaction)
        tx_hash = self._get_tx_hash(eels_transaction)
        self._transactions_map[tx_hash] = serialize_transaction(
            signed_json_tx, pending_block=self._pending_block
        )
        return tx_hash

    def send_transaction(self, transaction):
        if (
            transaction.get("to") in (b"", "0x0", "0x00", None)
            and "gas" not in transaction
        ):
            transaction["gas"] = self.estimate_gas(transaction)

        signed_and_normalized_json_tx = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )
        eels_tx = TransactionLoad(signed_and_normalized_json_tx, self.fork).read()
        self._check_transaction(eels_tx)

        pending_block_transactions = self._pending_block["transactions"]
        pending_block_transactions.append(eels_tx)
        tx_hash = self._get_tx_hash(eels_tx)
        self._transactions_map[tx_hash] = serialize_eels_transaction_for_block(
            self,
            tx=eels_tx,
            index=len(pending_block_transactions),
            block_number=self._pending_block["header"]["number"],
        )
        return tx_hash

    def estimate_gas(self, transaction, block_number="pending") -> int:
        original_sender_address = transaction["from"]
        with self._state_context_manager(block_number, synthetic_state=True):
            try:
                transaction["gas"] = self._max_available_gas()
                if original_sender_address not in self._key_lookup:
                    with self._transient_account_from_address(
                        original_sender_address
                    ) as transient_account_address:
                        transaction["from"] = transient_account_address
                        output = self._process_synthetic_transaction(transaction)
                else:
                    output = self._process_synthetic_transaction(transaction)
            except EthereumException as e:
                raise TransactionFailed("Transaction failed to execute.") from e
        return int(output[0])  # gas consumed

    def _process_synthetic_transaction(self, transaction: Dict[str, Any]):
        tx_env, signed_evm_transaction = self._generate_transaction_env(transaction)
        self._run_message_against_evm(tx_env, signed_evm_transaction)

        block_env = self._build_block_env()

        # TODO: maybe this should be pulled from somewhere?
        block_output = self._vm_module.BlockOutput(
            block_gas_used=Uint(0),
            transactions_trie=self._trie_module.Trie(secured=False, default=None),
            receipts_trie=self._trie_module.Trie(secured=False, default=None),
            block_logs=tuple(),
            withdrawals_trie=self._trie_module.Trie(secured=False, default=None),
            blob_gas_used=U64(0),
        )
        output = self._fork_module.process_transaction(
            block_env=block_env,
            block_output=block_output,
            tx=signed_evm_transaction,
            # TODO: where to find index?
            index=Uint(0),
        )
        return output

    def call(self, transaction, block_number="pending"):
        with self._state_context_manager(block_number, synthetic_state=True):
            transaction["gas"] = transaction.get("gas", MINIMUM_GAS_ESTIMATE)
            try:
                tx_env, signed_evm_transaction = self._generate_transaction_env(
                    transaction
                )
            except EthereumException as e:
                raise TransactionFailed("Transaction failed to execute.") from e
            evm = self._run_message_against_evm(tx_env, signed_evm_transaction)
            return evm.output

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
                    index=U64(withdrawal["index"]),
                    validator_index=U64(withdrawal["validator_index"]),
                    address=Address(to_canonical_address(withdrawal["address"])),
                    amount=U256(withdrawal["amount"]),
                )
            )
        # TODO: Consider just adding these to the pending block without auto mining.
        #  This would have to change not just for EELSBackend, so would be a bigger
        #  change later down the line.
        self.mine_blocks(1)

    def get_fee_history(
        self, block_count=1, newest_block="latest", reward_percentiles: List[int] = ()
    ):
        raise NotImplementedError("Fee history is not implemented in the EELS backend.")

    def _max_available_gas(self) -> int:
        header = self.chain.latest_block.header
        return int(header.gas_limit - header.gas_used)

    def _generate_transaction_env(self, transaction):
        signed_and_normalized_json_tx = self._get_normalized_and_signed_evm_transaction(
            transaction,
        )
        signed_transaction = TransactionLoad(
            signed_and_normalized_json_tx, self.fork
        ).read()

        env = self._synthetic_tx_environment(signed_transaction)
        # check / validate the transaction
        self._check_transaction(
            signed_transaction,
            # TODO: Stop lazily plugging in the parent block's gas limit
            self.chain.latest_block.header.gas_limit,
        )
        return env, signed_transaction

    def _run_message_against_evm(self, tx_env, signed_evm_transaction):
        accessed_addresses = set()
        accessed_storage_keys = set()
        if hasattr(signed_evm_transaction, "access_list"):
            for addr, keys in signed_evm_transaction.access_list:
                accessed_addresses.add(addr)
                accessed_storage_keys.update(keys)

        code = self._fork_module.get_account(
            self.chain.state, signed_evm_transaction.to
        ).code
        caller = self._fork_module.recover_sender(
            self.chain.chain_id, signed_evm_transaction
        )

        block_env = self._build_block_env()

        message = self._vm_module.Message(
            block_env=block_env,
            tx_env=tx_env,
            caller=caller,
            target=signed_evm_transaction.to,
            gas=signed_evm_transaction.gas,
            value=signed_evm_transaction.value,
            data=signed_evm_transaction.data,
            code=code,
            depth=Uint(0),
            current_target=signed_evm_transaction.to,
            code_address=signed_evm_transaction.to,
            should_transfer_value=signed_evm_transaction.value > U256(0)
            and signed_evm_transaction.to != b"",
            is_static=False,
            accessed_addresses=accessed_addresses,
            accessed_storage_keys=accessed_storage_keys,
            parent_evm=None,
        )
        evm = self._vm_module.interpreter.process_message(message)
        if evm.error:
            if isinstance(evm.error, self._vm_module.exceptions.Revert):
                str_output = str(evm.output)
                if evm.output == b"" or "Function has been reverted" in str_output:
                    msg = "Function has been reverted."
                else:
                    msg = str_output
            else:
                msg = evm.error
            raise TransactionFailed(msg)
        return evm

    def _extract_contract_address(self, pre_state, post_state):
        # TODO: make this more robust / figure out the best way to get the contract
        #   address with execution-specs API
        for address in post_state._main_trie._data:
            if address not in pre_state._main_trie._data:
                if self._state_module.get_account(post_state, address).code != b"":
                    return address

        return None

    @contextmanager
    def _transient_account_from_address(self, sender_address):
        """
        Create a transient account with known pkey with the same state as the sender.
        """
        sender_address_account = self._fork_module.get_account(
            self.chain.state, sender_address
        )
        acct = Account.create()
        bytes_address = to_canonical_address(acct.address)
        acct_pkey = KeyAPI.PrivateKey(acct.key)
        self._account_keys.append(acct_pkey)
        self.fork.set_account(self.chain.state, bytes_address, sender_address_account)

        yield bytes_address

        popped_key = self._account_keys.pop()
        self.fork.destroy_account(self.chain.state, bytes_address)
        if popped_key != acct_pkey:
            raise ValidationError("Account keys were not cleaned up properly.")
        assert (
            self._state_module.get_account_optional(self.chain.state, bytes_address)
            is None
        ), "Transient account was not destroyed properly."
