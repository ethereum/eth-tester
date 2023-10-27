from __future__ import (
    unicode_literals,
)

from eth_keys import (
    keys,
)
from eth_utils import (
    denoms,
    encode_hex,
    is_address,
    is_dict,
    is_hex,
    is_integer,
    is_same_address,
)
from eth_utils.toolz import (
    assoc,
    dissoc,
    merge,
)
import pytest
import rlp

from eth_tester.constants import (
    BURN_ADDRESS,
    UINT256_MAX,
    UINT256_MIN,
)
from eth_tester.exceptions import (
    AccountLocked,
    BlockNotFound,
    FilterNotFound,
    TransactionFailed,
    TransactionNotFound,
    ValidationError,
)
from eth_tester.tools.gas_burner_contract import (
    _deploy_gas_burner,
    _make_call_gas_burner_transaction,
)

from .emitter_contract import (
    EMITTER_ENUM,
    _call_emitter,
    _deploy_emitter,
)
from .math_contract import (
    _decode_math_result,
    _deploy_math,
    _make_call_math_transaction,
)
from .throws_contract import (
    _decode_throws_result,
    _deploy_throws,
    _make_call_throws_transaction,
)

PK_A = "0x58d23b55bc9cdce1f18c2500f40ff4ab7245df9a89505e9b1fa4851f623d241d"
PK_A_ADDRESS = "0xdc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd"

NON_DEFAULT_GAS_PRICE = 1000000000

SIMPLE_TRANSACTION = {
    "to": BURN_ADDRESS,
    "gas_price": NON_DEFAULT_GAS_PRICE,
    "value": 0,
    "gas": 21000,
}

TRANSACTION_WTH_NONCE = assoc(SIMPLE_TRANSACTION, "nonce", 0)

CONTRACT_TRANSACTION_EMPTY_TO = {
    "to": "",
    "gas_price": NON_DEFAULT_GAS_PRICE,
    "value": 0,
    "gas": 100000,
}
CONTRACT_TRANSACTION_MISSING_TO = dissoc(CONTRACT_TRANSACTION_EMPTY_TO, "to")

BLOCK_KEYS = {
    "number",
    "hash",
    "parent_hash",
    "nonce",
    "sha3_uncles",
    "logs_bloom",
    "transactions_root",
    "receipts_root",
    "state_root",
    "coinbase",
    "difficulty",
    "mix_hash",
    "total_difficulty",
    "size",
    "extra_data",
    "gas_limit",
    "gas_used",
    "timestamp",
    "transactions",
    "uncles",
}


def _validate_serialized_block(block):
    missing_keys = BLOCK_KEYS.difference(block.keys())
    if missing_keys:
        error_message = "Serialized block is missing the following keys: {}".format(
            "|".join(sorted(missing_keys)),
        )
        raise AssertionError(error_message)


class BaseTestBackendDirect:
    #
    # Utils
    #
    def _send_and_check_transaction(self, eth_tester, test_transaction, _from):
        transaction = assoc(test_transaction, "from", _from)

        txn_hash = eth_tester.send_transaction(transaction)
        txn = eth_tester.get_transaction_by_hash(txn_hash)
        self._check_transactions(transaction, txn)

    @staticmethod
    def _check_transactions(sent_transaction, actual_transaction):
        assert is_same_address(actual_transaction["from"], sent_transaction["from"])
        if "to" not in sent_transaction or sent_transaction["to"] == "":
            assert actual_transaction["to"] == ""
        else:
            assert is_same_address(actual_transaction["to"], sent_transaction["to"])

        assert actual_transaction["gas"] == sent_transaction["gas"]
        assert actual_transaction["value"] == sent_transaction["value"]

        if sent_transaction.get("gas_price") is not None:
            assert actual_transaction["gas_price"] == sent_transaction["gas_price"]
        else:
            assert (
                actual_transaction["max_fee_per_gas"]
                == sent_transaction["max_fee_per_gas"]
            )
            assert (
                actual_transaction["max_priority_fee_per_gas"]
                == sent_transaction["max_priority_fee_per_gas"]
            )

    #
    # Testing Flags
    #
    supports_evm_execution = True

    def skip_if_no_evm_execution(self):
        if not self.supports_evm_execution:
            pytest.skip("EVM Execution is not supported.")

    #
    # Accounts
    #
    def test_get_accounts(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts
        assert all(is_address(account) for account in accounts)

    def test_add_account_no_password(self, eth_tester):
        account = eth_tester.add_account(PK_A)
        assert is_address(account)
        assert any(
            is_same_address(account, value) for value in eth_tester.get_accounts()
        )

        # Fund it
        eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": account,
                "value": 1 * denoms.ether,
                "gas": 21000,
                "gas_price": NON_DEFAULT_GAS_PRICE,
            }
        )

        self._send_and_check_transaction(eth_tester, SIMPLE_TRANSACTION, account)

    def test_add_account_with_password(self, eth_tester):
        account = eth_tester.add_account(PK_A, "test-password")
        assert is_address(account)
        assert any(
            is_same_address(account, value) for value in eth_tester.get_accounts()
        )

        # Fund it
        eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": account,
                "value": 1 * denoms.ether,
                "gas": 21000,
                "gas_price": NON_DEFAULT_GAS_PRICE,
            }
        )

        with pytest.raises(AccountLocked):
            self._send_and_check_transaction(eth_tester, SIMPLE_TRANSACTION, account)

        eth_tester.unlock_account(account, "test-password")
        self._send_and_check_transaction(eth_tester, SIMPLE_TRANSACTION, account)

        eth_tester.lock_account(account)

        with pytest.raises(AccountLocked):
            self._send_and_check_transaction(eth_tester, SIMPLE_TRANSACTION, account)

    def test_get_balance_of_listed_accounts(self, eth_tester):
        for account in eth_tester.get_accounts():
            balance = eth_tester.get_balance(account)
            assert is_integer(balance)
            assert balance >= UINT256_MIN
            assert balance <= UINT256_MAX

    def test_get_code_account_with_code(self, eth_tester):
        self.skip_if_no_evm_execution()
        emitter_address = _deploy_emitter(eth_tester)
        code = eth_tester.get_code(emitter_address)
        assert (
            code
            == "0x606060405236156100615760e060020a60003504630bb563d6811461006357806317c0c1801461013657806320f0256e1461017057806390b41d8b146101ca5780639c37705314610215578063aa6fd82214610267578063e17bf956146102a9575b005b60206004803580820135601f810184900490930260809081016040526060848152610061946024939192918401918190838280828437509496505050505050507fa95e6e2a182411e7a6f9ed114a85c3761d87f9b8f453d842c71235aa64fff99f8160405180806020018281038252838181518152602001915080519060200190808383829060006004602084601f0104600f02600301f150905090810190601f1680156101255780820380516001836020036101000a031916815260200191505b509250505060405180910390a15b50565b610061600435600181141561037a577f1e86022f78f8d04f8e3dfd13a2bdb280403e6632877c0dbee5e4eeb259908a5c60006060a1610133565b6100616004356024356044356064356084356005851415610392576060848152608084815260a084905260c08390527ff039d147f23fe975a4254bdf6b1502b8c79132ae1833986b7ccef2638e73fdf991a15b5050505050565b61006160043560243560443560038314156103d457606082815260808290527fdf0cb1dea99afceb3ea698d62e705b736f1345a7eee9eb07e63d1f8f556c1bc590604090a15b505050565b6100616004356024356044356064356004841415610428576060838152608083905260a08290527f4a25b279c7c585f25eda9788ac9420ebadae78ca6b206a0e6ab488fd81f550629080a15b50505050565b61006160043560243560028214156104655760608181527f56d2ef3c5228bf5d88573621e325a4672ab50e033749a601e4f4a5e1dce905d490602090a15b5050565b60206004803580820135601f810184900490930260809081016040526060848152610061946024939192918401918190838280828437509496505050505050507f532fd6ea96cfb78bb46e09279a26828b8b493de1a2b8b1ee1face527978a15a58160405180806020018281038252838181518152602001915080519060200190808383829060006004602084601f0104600f02600301f150905090810190601f1680156101255780820380516001836020036101000a03191681526020019150509250505060405180910390a150565b600081141561038d5760006060a0610133565b610002565b600b85141561038d5760608481526080849052819083907fa30ece802b64cd2b7e57dabf4010aabf5df26d1556977affb07b98a77ad955b590604090a36101c3565b600983141561040f57606082815281907f057bc32826fbe161da1c110afcdcae7c109a8b69149f727fc37a603c60ef94ca90602090a2610210565b600883141561038d5760608281528190602090a1610210565b600a84141561038d576060838152819083907ff16c999b533366ca5138d78e85da51611089cd05749f098d6c225d4cd42ee6ec90602090a3610261565b600782141561049a57807ff70fe689e290d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb1560006060a26102a5565b600682141561038d578060006060a16102a556"  # noqa: E501
        )

    def test_get_code_account_without_code(self, eth_tester):
        code = eth_tester.get_code(BURN_ADDRESS)
        assert code == "0x"

    def test_get_nonce(self, eth_tester):
        for account in eth_tester.get_accounts():
            nonce = eth_tester.get_nonce(account)
        assert is_integer(nonce)
        assert nonce >= UINT256_MIN
        assert nonce <= UINT256_MAX

    #
    # Fee History
    #
    @pytest.mark.parametrize(
        "block_count,newest_block,reward_percentiles,expected",
        [
            [
                3,
                "latest",
                [],
                {
                    "base_fee_per_gas": [300657803, 343608917, 392695905],
                    "gas_used_ratio": [0.0, 0.0, 0.0],
                    "reward": [],
                },
            ],
            [
                1,
                "safe",
                [],
                {
                    "base_fee_per_gas": [300657803],
                    "gas_used_ratio": [0.0],
                    "reward": [],
                },
            ],
            [
                1,
                "finalized",
                [],
                {
                    "base_fee_per_gas": [300657803],
                    "gas_used_ratio": [0.0],
                    "reward": [],
                },
            ],
            [
                1,
                "earliest",
                [],
                {
                    "base_fee_per_gas": [],
                    "gas_used_ratio": [],
                    "reward": [],
                },
            ],
            [
                1,
                "pending",
                [],
                {
                    "base_fee_per_gas": [300657803],
                    "gas_used_ratio": [0.0],
                    "reward": [],
                },
            ],
        ],
    )
    def test_get_fee_history(
        self, eth_tester, block_count, newest_block, reward_percentiles, expected
    ):
        self.skip_if_no_evm_execution()

        eth_tester.mine_blocks(10)
        fee_history = eth_tester.get_fee_history(
            block_count, newest_block, reward_percentiles
        )

        assert fee_history["oldest_block"] == 1
        assert fee_history["base_fee_per_gas"] == expected["base_fee_per_gas"]
        assert fee_history["gas_used_ratio"] == expected["gas_used_ratio"]
        assert fee_history["reward"] == expected["reward"]

    @pytest.mark.parametrize(
        "block_count,newest_block,reward_percentiles,error,message",
        [
            [
                1,
                None,
                None,
                BlockNotFound,
                "No block found for block number: None",
            ],
            [
                0,
                None,
                None,
                ValidationError,
                "block_count must be between 1 and 1024",
            ],
        ],
    )
    def test_get_fee_history_fails(
        self, eth_tester, block_count, newest_block, reward_percentiles, error, message
    ):
        self.skip_if_no_evm_execution()

        eth_tester.mine_blocks(10)

        with pytest.raises(error, match=message):
            eth_tester.get_fee_history(block_count, newest_block, reward_percentiles)

    #
    # Mining
    #
    def test_mine_block_single(self, eth_tester):
        eth_tester.mine_blocks()
        before_block_number = eth_tester.get_block_by_number("latest")["number"]
        eth_tester.mine_blocks()
        after_block_number = eth_tester.get_block_by_number("latest")["number"]
        assert is_integer(before_block_number)
        assert is_integer(after_block_number)
        assert before_block_number == after_block_number - 1

    def test_mine_multiple_blocks(self, eth_tester):
        eth_tester.mine_blocks()
        before_block_number = eth_tester.get_block_by_number("latest")["number"]
        eth_tester.mine_blocks(10)
        after_block_number = eth_tester.get_block_by_number("latest")["number"]
        assert is_integer(before_block_number)
        assert is_integer(after_block_number)
        assert before_block_number == after_block_number - 10

    def test_gas_limit_constant(self, eth_tester):
        eth_tester.mine_blocks()
        before_gas_limit = eth_tester.get_block_by_number("latest")["gas_limit"]
        eth_tester.mine_blocks()
        after_gas_limit = eth_tester.get_block_by_number("latest")["gas_limit"]
        assert before_gas_limit == after_gas_limit

    #
    # Transaction Sending
    #
    @pytest.mark.parametrize("is_pending", [True, False])
    def test_send_raw_transaction_valid_raw_transaction(self, eth_tester, is_pending):
        # send funds to our sender
        raw_privkey = b"\x11" * 32
        test_key = keys.PrivateKey(raw_privkey)
        eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": test_key.public_key.to_checksum_address(),
                "gas": 21000,
                "value": 1 * denoms.ether,
            }
        )

        # transaction: 'to': '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A', 'from':
        # '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A',  'value': 1337, 'nonce': 0
        # 'gas': 21000, 'gas_price': 1000000000, and signed with `test_key`

        transaction_hex = "0xf86580843b9aca008252089419e7e376e7c213b7e7e7e46cc70a5dd086daff2a820539801ba0b101c1f9dc0c588c0194a1093f06e6b30d1fd16d31014ef5851311b7bfbf419ea01cfa8757b7863a630ef7491c62b03d9cd9dff395f61b5df500cc665f0fa5b027"  # noqa: E501
        if is_pending:
            eth_tester.disable_auto_mine_transactions()

        transaction_hash = eth_tester.send_raw_transaction(transaction_hex)

        if is_pending:
            with pytest.raises(TransactionNotFound):
                eth_tester.get_transaction_receipt(transaction_hash)

            eth_tester.enable_auto_mine_transactions()

        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        # assert that the raw transaction is confirmed and successful
        assert receipt["transaction_hash"] == transaction_hash

    def test_send_raw_transaction_invalid_rlp_transaction(self, eth_tester):
        self.skip_if_no_evm_execution()
        invalid_transaction_hex = "0x1234"
        import eth

        with pytest.raises(eth.exceptions.UnrecognizedTransactionType):
            eth_tester.send_raw_transaction(invalid_transaction_hex)

    def test_send_raw_transaction_invalid_raw_transaction(self, eth_tester):
        self.skip_if_no_evm_execution()
        invalid_transaction_hex = "0xffff"
        with pytest.raises(rlp.exceptions.DecodingError):
            eth_tester.send_raw_transaction(invalid_transaction_hex)

    @pytest.mark.parametrize(
        "test_transaction",
        (
            SIMPLE_TRANSACTION,
            TRANSACTION_WTH_NONCE,
            CONTRACT_TRANSACTION_EMPTY_TO,
            CONTRACT_TRANSACTION_MISSING_TO,
        ),
        ids=[
            "Simple transaction",
            "Transaction with nonce",
            "Create Contract - empty to",
            "Create Contract - missing to",
        ],
    )
    def test_send_transaction(self, eth_tester, test_transaction):
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        self._send_and_check_transaction(eth_tester, test_transaction, accounts[0])

    def test_send_transaction_raises_with_legacy_and_dynamic_fee_fields(
        self, eth_tester
    ):
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        test_transaction = {
            "to": accounts[0],
            "from": accounts[0],
            "value": 1,
            "gas": 21000,
            "gas_price": 1234567890,
            "max_fee_per_gas": 1000000000,
            "max_priority_fee_per_gas": 1000000000,
        }
        with pytest.raises(
            ValidationError, match="legacy and dynamic fee transaction values"
        ):
            self._send_and_check_transaction(eth_tester, test_transaction, accounts[0])

    def test_send_transaction_no_gas_price_or_dynamic_fees(self, eth_tester):
        # test that we default to a dynamic fee transaction which, while pending,
        # will include the gas_price as equal to the effective gas price paid.
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        test_transaction = dissoc(SIMPLE_TRANSACTION, "gas_price")
        test_transaction = assoc(test_transaction, "from", accounts[0])

        txn_hash = eth_tester.send_transaction(test_transaction)
        sent_transaction = eth_tester.get_transaction_by_hash(txn_hash)

        assert sent_transaction.get("type") == "0x2"
        assert sent_transaction.get("max_fee_per_gas") == 1000000000
        assert sent_transaction.get("max_priority_fee_per_gas") == 1000000000
        assert sent_transaction.get("access_list") == ()
        assert sent_transaction.get("gas_price") == 1000000000

    def test_send_access_list_transaction(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        access_list_transaction = {
            "chain_id": 131277322940537,
            "from": accounts[0],
            "to": accounts[0],
            "value": 1,
            "gas": 40000,
            "gas_price": 1000000000,
            "access_list": (),
        }
        txn_hash = eth_tester.send_transaction(access_list_transaction)
        txn = eth_tester.get_transaction_by_hash(txn_hash)

        assert txn.get("type") == "0x1"
        assert txn.get("access_list") == ()
        self._check_transactions(access_list_transaction, txn)

        # with non-empty access list
        access_list_transaction["access_list"] = (
            {
                "address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                "storage_keys": (
                    "0x0000000000000000000000000000000000000000000000000000000000000003",  # noqa: E501
                    "0x0000000000000000000000000000000000000000000000000000000000000007",  # noqa: E501
                ),
            },
            {
                "address": "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
                "storage_keys": (),
            },
        )
        txn_hash = eth_tester.send_transaction(access_list_transaction)
        txn = eth_tester.get_transaction_by_hash(txn_hash)

        assert txn.get("type") == "0x1"
        assert txn.get("access_list") != ()
        self._check_transactions(access_list_transaction, txn)

    def test_send_dynamic_fee_transaction(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        dynamic_fee_transaction = {
            "chain_id": 131277322940537,
            "from": accounts[0],
            "to": accounts[0],
            "value": 1,
            "gas": 40000,
            "max_fee_per_gas": 2000000000,
            "max_priority_fee_per_gas": 1000000000,
        }
        txn_hash = eth_tester.send_transaction(dynamic_fee_transaction)
        txn = eth_tester.get_transaction_by_hash(txn_hash)

        assert txn.get("type") == "0x2"
        assert txn.get("access_list") == ()
        self._check_transactions(dynamic_fee_transaction, txn)

        # with non-empty access list
        dynamic_fee_transaction["access_list"] = (
            {
                "address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                "storage_keys": (
                    "0x0000000000000000000000000000000000000000000000000000000000000003",  # noqa: E501
                    "0x0000000000000000000000000000000000000000000000000000000000000007",  # noqa: E501
                ),
            },
            {
                "address": "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
                "storage_keys": (),
            },
        )
        txn_hash = eth_tester.send_transaction(dynamic_fee_transaction)
        txn = eth_tester.get_transaction_by_hash(txn_hash)

        assert txn.get("type") == "0x2"
        assert txn.get("access_list") != ()
        self._check_transactions(dynamic_fee_transaction, txn)

    def test_block_number_auto_mine_transactions_enabled(self, eth_tester):
        eth_tester.mine_blocks()
        eth_tester.enable_auto_mine_transactions()
        before_block_number = eth_tester.get_block_by_number("latest")["number"]
        eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        after_block_number = eth_tester.get_block_by_number("latest")["number"]
        assert before_block_number == after_block_number - 1

    def test_auto_mine_transactions_disabled_block_number(self, eth_tester):
        eth_tester.mine_blocks()
        eth_tester.disable_auto_mine_transactions()
        before_block_number = eth_tester.get_block_by_number("latest")["number"]
        eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        after_block_number = eth_tester.get_block_by_number("latest")["number"]
        assert before_block_number == after_block_number

    def test_auto_mine_transactions_disabled_replace_transaction(self, eth_tester):
        eth_tester.mine_blocks()
        eth_tester.disable_auto_mine_transactions()
        transaction = {
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "value": 1,
            "gas": 21000,
            "nonce": 0,
        }
        try:
            eth_tester.send_transaction(transaction)
            transaction["value"] = 2
            eth_tester.send_transaction(transaction)
        except Exception:
            pytest.fail("Sending replacement transaction caused exception")

    def test_auto_mine_transactions_disabled_multiple_accounts(self, eth_tester):
        eth_tester.mine_blocks()
        eth_tester.disable_auto_mine_transactions()

        tx1 = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "value": 1,
                "gas": 21000,
                "nonce": 0,
            }
        )
        tx2 = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[1],
                "to": BURN_ADDRESS,
                "value": 1,
                "gas": 21000,
                "nonce": 0,
            }
        )

        assert tx1 == eth_tester.get_transaction_by_hash(tx1)["hash"]
        assert tx2 == eth_tester.get_transaction_by_hash(tx2)["hash"]

        tx2_replacement = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[1],
                "to": BURN_ADDRESS,
                "value": 2,
                "gas": 21000,
                "nonce": 0,
            }
        )

        # Replaces the correct transaction
        assert tx1 == eth_tester.get_transaction_by_hash(tx1)["hash"]
        assert (
            tx2_replacement
            == eth_tester.get_transaction_by_hash(tx2_replacement)["hash"]
        )
        with pytest.raises(TransactionNotFound):
            eth_tester.get_transaction_by_hash(tx2)

    def test_auto_mine_transactions_disabled_returns_hashes_when_enabled(
        self, eth_tester
    ):
        self.skip_if_no_evm_execution()
        eth_tester.mine_blocks()
        eth_tester.disable_auto_mine_transactions()

        tx1 = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "value": 1,
                "gas": 21000,
                "nonce": 0,
            }
        )
        tx2 = eth_tester.send_transaction(  # noqa: F841
            {
                "from": eth_tester.get_accounts()[1],
                "to": BURN_ADDRESS,
                "value": 1,
                "gas": 21000,
                "nonce": 0,
            }
        )
        tx2_replacement = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[1],
                "to": BURN_ADDRESS,
                "value": 2,
                "gas": 21000,
                "nonce": 0,
            }
        )
        sent_transactions = eth_tester.enable_auto_mine_transactions()
        assert sent_transactions == [tx1, tx2_replacement]

    @pytest.mark.parametrize(
        "test_transaction",
        (
            SIMPLE_TRANSACTION,
            CONTRACT_TRANSACTION_EMPTY_TO,
            CONTRACT_TRANSACTION_MISSING_TO,
        ),
        ids=[
            "Simple transaction",
            "Create Contract - empty to",
            "Create Contract - missing to",
        ],
    )
    def test_manual_mine_pending_transactions(self, eth_tester, test_transaction):
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        complete_transaction = assoc(test_transaction, "from", accounts[0])

        self.skip_if_no_evm_execution()
        eth_tester.mine_blocks()
        eth_tester.disable_auto_mine_transactions()

        txn_hash = eth_tester.send_transaction(complete_transaction)

        with pytest.raises(TransactionNotFound):
            eth_tester.get_transaction_receipt(txn_hash)

        pending_transaction = eth_tester.get_transaction_by_hash(txn_hash)
        self._check_transactions(complete_transaction, pending_transaction)

        eth_tester.mine_block()

        receipt = eth_tester.get_transaction_receipt(txn_hash)
        assert receipt["transaction_hash"] == txn_hash
        assert receipt["block_number"]

        mined_transaction = eth_tester.get_transaction_by_hash(txn_hash)
        self._check_transactions(complete_transaction, mined_transaction)

    #
    # Blocks
    #
    def test_get_genesis_block_by_number(self, eth_tester):
        block = eth_tester.get_block_by_number(0)
        assert block["number"] == 0
        _validate_serialized_block(block)

    def test_get_genesis_block_by_hash(self, eth_tester):
        genesis_hash = eth_tester.get_block_by_number(0)["hash"]
        block = eth_tester.get_block_by_hash(genesis_hash)
        assert block["number"] == 0
        _validate_serialized_block(block)

    def test_get_block_by_number(self, eth_tester):
        origin_block_number = eth_tester.get_block_by_number("pending")["number"]
        mined_block_hashes = eth_tester.mine_blocks(10)
        for offset, block_hash in enumerate(mined_block_hashes):
            block_number = origin_block_number + offset
            block = eth_tester.get_block_by_number(block_number)
            assert block["number"] == block_number
            assert block["hash"] == block_hash
            _validate_serialized_block(block)

    def test_get_block_by_number_full_transactions(self, eth_tester):
        eth_tester.mine_blocks(2)
        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        block = eth_tester.get_block_by_number(
            transaction["block_number"],
            full_transactions=True,
        )
        assert is_dict(block["transactions"][0])

    def test_get_block_by_number_only_transaction_hashes(self, eth_tester):
        eth_tester.mine_blocks(2)
        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        block = eth_tester.get_block_by_number(
            transaction["block_number"],
            full_transactions=False,
        )
        assert is_hex(block["transactions"][0])

    def test_get_block_by_hash(self, eth_tester):
        origin_block_number = eth_tester.get_block_by_number("pending")["number"]

        mined_block_hashes = eth_tester.mine_blocks(10)
        for offset, block_hash in enumerate(mined_block_hashes):
            block_number = origin_block_number + offset
            block = eth_tester.get_block_by_hash(block_hash)
            assert block["number"] == block_number
            assert block["hash"] == block_hash

    def test_get_block_by_hash_full_transactions(self, eth_tester):
        eth_tester.mine_blocks(2)
        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        block = eth_tester.get_block_by_hash(
            transaction["block_hash"],
            full_transactions=True,
        )
        assert is_dict(block["transactions"][0])

    def test_get_block_by_hash_only_transaction_hashes(self, eth_tester):
        eth_tester.mine_blocks(2)
        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        block = eth_tester.get_block_by_hash(
            transaction["block_hash"],
            full_transactions=False,
        )
        assert is_hex(block["transactions"][0])

    def test_get_block_by_earliest(self, eth_tester):
        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number("earliest")
        assert block["number"] == 0

    def test_get_block_by_latest_unmined_genesis(self, eth_tester):
        block = eth_tester.get_block_by_number("latest")
        assert block["number"] == 0

    def test_get_block_by_latest_only_genesis(self, eth_tester):
        block = eth_tester.get_block_by_number("latest")
        assert block["number"] == 0

    def test_get_block_by_latest(self, eth_tester):
        origin_block_number = eth_tester.get_block_by_number("pending")["number"]

        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number("latest")
        assert block["number"] == 9 + origin_block_number

    def test_get_block_by_pending(self, eth_tester):
        origin_block_number = eth_tester.get_block_by_number("pending")["number"]

        eth_tester.mine_blocks(10)
        block = eth_tester.get_block_by_number("pending")
        assert block["number"] == 10 + origin_block_number

    def test_get_block_missing(self, eth_tester):
        with pytest.raises(BlockNotFound):
            eth_tester.get_block_by_hash("0x" + "00" * 32)

    # Transactions
    def test_get_transaction_by_hash(self, eth_tester):
        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        assert transaction["hash"] == transaction_hash

    def test_get_transaction_by_hash_for_unmined_transaction(self, eth_tester):
        eth_tester.disable_auto_mine_transactions()
        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        assert transaction["hash"] == transaction_hash
        assert transaction["block_hash"] is None

    def test_get_transaction_receipt_for_mined_transaction(self, eth_tester):
        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )

        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt["transaction_hash"] == transaction_hash
        assert receipt["type"] == "0x2"
        assert receipt["effective_gas_price"] == 1000000000

    @pytest.mark.parametrize(
        "type_specific_params,_type",
        (
            (
                {"gas_price": 1234567890},
                # legacy transactions being '0x0' taken from
                # current geth version v1.10.10
                "0x0",
            ),
            (
                {
                    "gas_price": 1234567890,
                    "access_list": (
                        {
                            "address": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
                            "storage_keys": (),
                        },
                    ),
                },
                "0x1",  # access list transaction
            ),
            (
                {
                    "max_fee_per_gas": 1000000000,
                    "max_priority_fee_per_gas": 1000000000,
                    "access_list": (
                        {
                            "address": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
                            "storage_keys": (),
                        },
                    ),
                },
                "0x2",  # dynamic fee transaction
            ),
        ),
    )
    def test_receipt_transaction_type_for_mined_transaction(
        self, eth_tester, type_specific_params, _type
    ):
        transaction_hash = eth_tester.send_transaction(
            merge(
                {
                    "from": eth_tester.get_accounts()[0],
                    "to": BURN_ADDRESS,
                    "gas": 25000,
                },
                type_specific_params,
            )
        )
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt["transaction_hash"] == transaction_hash
        assert receipt["type"] == _type

    def test_receipt_effective_gas_price_for_mined_transaction_legacy(self, eth_tester):
        gas_price = 1234567890

        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
                "gas_price": gas_price,
            }
        )
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt["transaction_hash"] == transaction_hash
        assert receipt["type"] == "0x0"
        assert receipt["effective_gas_price"] == gas_price

    def test_receipt_effective_gas_price_for_mined_transaction_base_fee_minimum(
        self, eth_tester
    ):
        priority_fee = 1500000000

        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
                "max_priority_fee_per_gas": priority_fee,
                "max_fee_per_gas": priority_fee * 2,
            }
        )
        receipt = eth_tester.get_transaction_receipt(transaction_hash)

        base_fee = eth_tester.get_block_by_number(receipt["block_number"])[
            "base_fee_per_gas"
        ]

        # base fee should be 875000000 since genesis was 1000000000
        assert base_fee == 875000000

        assert receipt["transaction_hash"] == transaction_hash
        assert receipt["type"] == "0x2"
        # the max fee is higher than (base fee + priority fee) so the latter should be
        # the effective gas price
        assert receipt["effective_gas_price"] == base_fee + priority_fee

    def test_receipt_effective_gas_price_for_mined_transaction_max_fee_minimum(
        self, eth_tester
    ):
        priority_fee = 1500000000
        max_fee = priority_fee + 1  # arbitrary, to differentiate from the priority fee

        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
                "max_priority_fee_per_gas": priority_fee,
                "max_fee_per_gas": max_fee,
            }
        )
        receipt = eth_tester.get_transaction_receipt(transaction_hash)

        base_fee = eth_tester.get_block_by_number(receipt["block_number"])[
            "base_fee_per_gas"
        ]

        # base fee should be 875000000 since genesis was 1000000000
        assert base_fee == 875000000

        assert receipt["transaction_hash"] == transaction_hash
        assert receipt["type"] == "0x2"
        # the max fee is lower than (base fee + priority fee) so the former should be
        # the effective gas price
        assert receipt["effective_gas_price"] == max_fee

    def test_get_transaction_receipt_for_unmined_transaction_raises(self, eth_tester):
        eth_tester.disable_auto_mine_transactions()
        transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
            }
        )
        with pytest.raises(TransactionNotFound):
            eth_tester.get_transaction_receipt(transaction_hash)

    def test_call_return13(self, eth_tester):
        self.skip_if_no_evm_execution()

        math_address = _deploy_math(eth_tester)
        call_math_transaction = _make_call_math_transaction(
            eth_tester,
            math_address,
            "return13",
        )
        raw_result = eth_tester.call(call_math_transaction)
        result = _decode_math_result("return13", raw_result)
        assert result == (13,)

    def test_call_add(self, eth_tester):
        self.skip_if_no_evm_execution()

        math_address = _deploy_math(eth_tester)
        call_math_transaction = _make_call_math_transaction(
            eth_tester,
            math_address,
            "add",
            fn_args=(7, 13),
        )
        raw_result = eth_tester.call(call_math_transaction)
        result = _decode_math_result("add", raw_result)
        assert result == (20,)

    def test_call_query_previous_state(self, eth_tester):
        self.skip_if_no_evm_execution()

        math_address = _deploy_math(eth_tester)
        call_math_transaction = _make_call_math_transaction(
            eth_tester, math_address, "counter"
        )

        call_math_transaction_inc = _make_call_math_transaction(
            eth_tester,
            math_address,
            "increment",
        )

        eth_tester.mine_blocks(2)
        eth_tester.send_transaction(call_math_transaction_inc)

        raw_result = eth_tester.call(call_math_transaction, 1)
        result = _decode_math_result("counter", raw_result)

        raw_result_new = eth_tester.call(call_math_transaction)
        result_new = _decode_math_result("counter", raw_result_new)

        assert result == (0,)
        assert result_new == (1,)

    def test_estimate_gas(self, eth_tester):
        self.skip_if_no_evm_execution()

        math_address = _deploy_math(eth_tester)
        estimate_call_math_transaction = _make_call_math_transaction(
            eth_tester,
            math_address,
            "increment",
        )
        gas_estimation = eth_tester.estimate_gas(estimate_call_math_transaction)
        call_math_transaction = assoc(
            estimate_call_math_transaction, "gas", gas_estimation
        )
        transaction_hash = eth_tester.send_transaction(call_math_transaction)
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt["gas_used"] <= gas_estimation
        # Tolerance set to the default py-evm tolerance:
        # https://github.com/ethereum/py-evm/blob/f0276e684edebd7cd9e84cd04b3229ab9dd958b9/evm/estimators/gas.py#L77
        # https://github.com/ethereum/py-evm/blob/f0276e684edebd7cd9e84cd04b3229ab9dd958b9/evm/estimators/__init__.py#L11
        assert receipt["gas_used"] >= gas_estimation - 21000

    def test_estimate_gas_with_block_identifier(self, eth_tester):
        self.skip_if_no_evm_execution()

        gas_burner_address = _deploy_gas_burner(eth_tester)
        estimate_call_gas_burner_transaction = _make_call_gas_burner_transaction(
            eth_tester,
            gas_burner_address,
            "burnBlockNumberDependentGas",
        )
        latest_gas_estimation = eth_tester.estimate_gas(
            estimate_call_gas_burner_transaction, "latest"
        )
        earliest_gas_estimation = eth_tester.estimate_gas(
            estimate_call_gas_burner_transaction, "earliest"
        )
        assert latest_gas_estimation > earliest_gas_estimation

    def test_can_call_after_exception_raised_calling(self, eth_tester):
        self.skip_if_no_evm_execution()

        throws_address = _deploy_throws(eth_tester, "throw_contract")
        call_will_throw_transaction = _make_call_throws_transaction(
            eth_tester,
            throws_address,
            "throw_contract",
            "willThrow",
        )
        with pytest.raises(TransactionFailed):
            eth_tester.call(call_will_throw_transaction)

        call_value_transaction = _make_call_throws_transaction(
            eth_tester,
            throws_address,
            "throw_contract",
            "value",
        )
        raw_result = eth_tester.call(call_value_transaction)
        result = _decode_throws_result("throw_contract", "value", raw_result)
        assert result == (1,)

    def test_can_estimate_gas_after_exception_raised_estimating_gas(self, eth_tester):
        self.skip_if_no_evm_execution()

        throws_address = _deploy_throws(eth_tester, "throw_contract")
        call_will_throw_transaction = _make_call_throws_transaction(
            eth_tester,
            throws_address,
            "throw_contract",
            "willThrow",
        )
        with pytest.raises(TransactionFailed):
            eth_tester.estimate_gas(dissoc(call_will_throw_transaction, "gas"))

        call_set_value_transaction = _make_call_throws_transaction(
            eth_tester,
            throws_address,
            "throw_contract",
            "setValue",
            fn_args=(2,),
        )
        gas_estimation = eth_tester.estimate_gas(
            dissoc(call_set_value_transaction, "gas")
        )
        assert gas_estimation

    #
    # Test revert with reason message
    #
    def test_revert_reason_message(self, eth_tester):
        self.skip_if_no_evm_execution()

        revert_address = _deploy_throws(eth_tester, "revert_contract")

        call_with_revert = _make_call_throws_transaction(
            eth_tester,
            revert_address,
            "revert_contract",
            "do_revert",
            fn_args=(True,),
        )
        call_without_revert = _make_call_throws_transaction(
            eth_tester,
            revert_address,
            "revert_contract",
            "do_revert",
            fn_args=(False,),
        )

        raw_result = eth_tester.call(call_without_revert)
        result = _decode_throws_result("revert_contract", "do_revert", raw_result)
        assert result[0] == "No ribbert"

        with pytest.raises(TransactionFailed) as excinfo:
            eth_tester.call(call_with_revert)
        assert (
            len(excinfo.value.args) > 0 and excinfo.value.args[0] == "ribbert, ribbert"
        )

    #
    # Snapshot and Revert
    #
    def test_genesis_snapshot_and_revert(self, eth_tester):
        origin_latest = eth_tester.get_block_by_number("latest")["number"]
        origin_pending = eth_tester.get_block_by_number("pending")["number"]

        snapshot_id = eth_tester.take_snapshot()

        # now mine 10 blocks in
        eth_tester.mine_blocks(10)
        assert eth_tester.get_block_by_number("latest")["number"] == origin_latest + 10
        assert (
            eth_tester.get_block_by_number("pending")["number"] == origin_pending + 10
        )

        eth_tester.revert_to_snapshot(snapshot_id)
        assert eth_tester.get_block_by_number("latest")["number"] == origin_latest
        assert eth_tester.get_block_by_number("pending")["number"] == origin_pending

    def test_snapshot_and_revert_post_genesis(self, eth_tester):
        eth_tester.mine_blocks(5)

        origin_latest = eth_tester.get_block_by_number("latest")["number"]
        origin_pending = eth_tester.get_block_by_number("pending")["number"]

        snapshot_id = eth_tester.take_snapshot()

        # now mine 10 blocks in
        eth_tester.mine_blocks(10)
        assert eth_tester.get_block_by_number("latest")["number"] == origin_latest + 10
        assert (
            eth_tester.get_block_by_number("pending")["number"] == origin_pending + 10
        )

        eth_tester.revert_to_snapshot(snapshot_id)

        assert eth_tester.get_block_by_number("latest")["number"] == origin_latest
        assert eth_tester.get_block_by_number("pending")["number"] == origin_pending

    def test_revert_cleans_up_invalidated_pending_block_filters(self, eth_tester):
        # first mine 10 blocks in
        eth_tester.mine_blocks(2)

        # setup a filter
        filter_a_id = eth_tester.create_block_filter()
        filter_b_id = eth_tester.create_block_filter()

        # mine 5 blocks before the snapshot
        common_blocks = set(eth_tester.mine_blocks(2))

        snapshot_id = eth_tester.take_snapshot()

        # mine another 5 blocks
        fork_a_transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
                "value": 1,
            }
        )
        fork_a_transaction_block_hash = eth_tester.get_transaction_by_hash(
            fork_a_transaction_hash,
        )["block_hash"]
        fork_a_blocks = eth_tester.mine_blocks(2)

        before_revert_changes_logs_a = eth_tester.get_only_filter_changes(filter_a_id)
        before_revert_all_logs_a = eth_tester.get_all_filter_logs(filter_a_id)
        before_revert_all_logs_b = eth_tester.get_all_filter_logs(filter_b_id)

        assert common_blocks.intersection(before_revert_changes_logs_a) == common_blocks
        assert common_blocks.intersection(before_revert_all_logs_a) == common_blocks
        assert common_blocks.intersection(before_revert_all_logs_b) == common_blocks

        expected_before_block_hashes = common_blocks.union(
            [
                fork_a_transaction_block_hash,
            ]
        ).union(fork_a_blocks)

        # sanity check that the filters picked up on the log changes.
        assert set(before_revert_changes_logs_a) == expected_before_block_hashes
        assert set(before_revert_changes_logs_a) == expected_before_block_hashes
        assert set(before_revert_all_logs_a) == expected_before_block_hashes
        assert set(before_revert_all_logs_b) == expected_before_block_hashes

        # now revert to snapshot
        eth_tester.revert_to_snapshot(snapshot_id)

        # send a different transaction to ensure our new blocks are different
        fork_b_transaction_hash = eth_tester.send_transaction(
            {
                "from": eth_tester.get_accounts()[0],
                "to": BURN_ADDRESS,
                "gas": 21000,
                "value": 2,
            }
        )
        fork_b_transaction_block_hash = eth_tester.get_transaction_by_hash(
            fork_b_transaction_hash,
        )["block_hash"]
        fork_b_blocks = eth_tester.mine_blocks(2)

        # check that are blocks don't intersect
        assert not set(fork_a_blocks).intersection(fork_b_blocks)

        after_revert_changes_logs_a = eth_tester.get_only_filter_changes(filter_a_id)
        after_revert_changes_logs_b = eth_tester.get_only_filter_changes(filter_b_id)
        after_revert_all_logs_a = eth_tester.get_all_filter_logs(filter_a_id)
        after_revert_all_logs_b = eth_tester.get_all_filter_logs(filter_b_id)

        expected_all_after_blocks = common_blocks.union(
            [
                fork_b_transaction_block_hash,
            ]
        ).union(fork_b_blocks)
        expected_new_after_blocks = set(fork_b_blocks).union(
            [
                fork_b_transaction_block_hash,
            ]
        )

        assert set(after_revert_changes_logs_a) == expected_new_after_blocks
        assert set(after_revert_changes_logs_b) == expected_all_after_blocks
        assert set(after_revert_all_logs_a) == expected_all_after_blocks
        assert set(after_revert_all_logs_b) == expected_all_after_blocks

    def test_revert_cleans_up_invalidated_pending_transaction_filters(self, eth_tester):
        def _transaction(**kwargs):
            return merge(
                {
                    "from": eth_tester.get_accounts()[0],
                    "to": BURN_ADDRESS,
                    "gas": 21000,
                },
                kwargs,
            )

        # send a few initial transactions
        for _ in range(5):
            eth_tester.send_transaction(_transaction())

        # setup a filter
        filter_id = eth_tester.create_pending_transaction_filter()

        # send 2 transactions
        common_transactions = {
            eth_tester.send_transaction(_transaction(value=1)),
            eth_tester.send_transaction(_transaction(value=2)),
        }

        # take a snapshot
        snapshot_id = eth_tester.take_snapshot()

        # send 3 transactions
        before_transactions = [
            eth_tester.send_transaction(_transaction(value=3)),
            eth_tester.send_transaction(_transaction(value=4)),
            eth_tester.send_transaction(_transaction(value=5)),
        ]

        # pull and sanity check the filter changes
        before_filter_changes = eth_tester.get_only_filter_changes(filter_id)
        before_filter_logs = eth_tester.get_all_filter_logs(filter_id)

        assert set(before_filter_changes) == common_transactions.union(
            before_transactions
        )
        assert set(before_filter_logs) == common_transactions.union(before_transactions)

        # revert the chain
        eth_tester.revert_to_snapshot(snapshot_id)

        # send 3 transactions on the new fork
        after_transactions = [
            eth_tester.send_transaction(_transaction(value=6)),
            eth_tester.send_transaction(_transaction(value=7)),
            eth_tester.send_transaction(_transaction(value=8)),
        ]

        # pull and sanity check the filter changes
        after_filter_changes = eth_tester.get_only_filter_changes(filter_id)
        after_filter_logs = eth_tester.get_all_filter_logs(filter_id)

        assert set(after_filter_changes) == set(after_transactions)
        assert set(after_filter_logs) == common_transactions.union(after_transactions)

    def test_revert_cleans_up_invalidated_log_entries(self, eth_tester):
        self.skip_if_no_evm_execution()

        # setup the emitter
        emitter_address = _deploy_emitter(eth_tester)

        def _emit(v):
            return _call_emitter(
                eth_tester,
                emitter_address,
                "logSingle",
                [EMITTER_ENUM["LogSingleWithIndex"], v],
            )

        # emit 2 logs pre-filtering
        _emit(1)
        _emit(2)

        # setup a filter
        filter_id = eth_tester.create_log_filter()

        # emit 2 logs pre-snapshot
        _emit(1)
        _emit(2)

        # take a snapshot
        snapshot_id = eth_tester.take_snapshot()

        # emit 3 logs after-snapshot
        _emit(3)
        _emit(4)
        _emit(5)

        before_changes = eth_tester.get_only_filter_changes(filter_id)
        before_all = eth_tester.get_all_filter_logs(filter_id)

        assert len(before_changes) == 5
        assert len(before_all) == 5

        # revert the chain
        eth_tester.revert_to_snapshot(snapshot_id)

        # emit 4 logs after-reverting
        _emit(6)
        _emit(7)
        _emit(8)
        _emit(9)

        after_changes = eth_tester.get_only_filter_changes(filter_id)
        after_all = eth_tester.get_all_filter_logs(filter_id)

        assert len(after_changes) == 4
        assert len(after_all) == 6

    def test_reset_to_genesis(self, eth_tester):
        origin_latest = eth_tester.get_block_by_number("latest")["number"]
        origin_pending = eth_tester.get_block_by_number("pending")["number"]
        eth_tester.mine_blocks(5)

        assert eth_tester.get_block_by_number("latest")["number"] == origin_latest + 5
        assert eth_tester.get_block_by_number("pending")["number"] == origin_pending + 5

        eth_tester.reset_to_genesis()

        assert eth_tester.get_block_by_number("latest")["number"] == origin_latest
        assert eth_tester.get_block_by_number("pending")["number"] == origin_pending

    #
    # Filters
    #
    def test_block_filter(self, eth_tester):
        # first mine 10 blocks in
        eth_tester.mine_blocks(10)

        # setup a filter
        filter_a_id = eth_tester.create_block_filter()

        # mine another 5 blocks
        blocks_10_to_14 = eth_tester.mine_blocks(5)

        # setup another filter
        filter_b_id = eth_tester.create_block_filter()

        # mine another 8 blocks
        blocks_15_to_22 = eth_tester.mine_blocks(8)

        filter_a_changes_part_1 = eth_tester.get_only_filter_changes(filter_a_id)
        filter_a_logs_part_1 = eth_tester.get_all_filter_logs(filter_a_id)
        filter_b_logs_part_1 = eth_tester.get_all_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_1) == 13
        assert len(filter_a_logs_part_1) == 13
        assert len(filter_b_logs_part_1) == 8

        assert set(filter_a_changes_part_1) == set(filter_a_logs_part_1)
        assert set(filter_a_changes_part_1) == set(blocks_10_to_14).union(
            blocks_15_to_22
        )
        assert set(filter_b_logs_part_1) == set(blocks_15_to_22)

        # mine another 7 blocks
        blocks_23_to_29 = eth_tester.mine_blocks(7)

        filter_a_changes_part_2 = eth_tester.get_only_filter_changes(filter_a_id)
        filter_b_changes = eth_tester.get_only_filter_changes(filter_b_id)
        filter_a_logs_part_2 = eth_tester.get_all_filter_logs(filter_a_id)
        filter_b_logs_part_2 = eth_tester.get_all_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_2) == 7
        assert len(filter_b_changes) == 15
        assert len(filter_a_logs_part_2) == 20
        assert len(filter_b_logs_part_2) == 15

        assert set(filter_a_changes_part_2) == set(blocks_23_to_29)
        assert set(filter_b_changes) == set(blocks_15_to_22).union(blocks_23_to_29)
        assert set(filter_b_changes) == set(filter_b_logs_part_2)
        assert set(filter_a_logs_part_2) == set(blocks_10_to_14).union(
            blocks_15_to_22,
        ).union(blocks_23_to_29)
        assert set(filter_b_logs_part_2) == set(blocks_15_to_22).union(blocks_23_to_29)

    def test_pending_transaction_filter(self, eth_tester):
        transaction = {
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        }

        # send a few initial transactions
        for _ in range(5):
            eth_tester.send_transaction(transaction)

        # setup a filter
        filter_a_id = eth_tester.create_pending_transaction_filter()

        # send 8 transactions
        transactions_0_to_7 = [
            eth_tester.send_transaction(transaction) for _ in range(8)
        ]

        # setup another filter
        filter_b_id = eth_tester.create_pending_transaction_filter()

        # send 5 transactions
        transactions_8_to_12 = [
            eth_tester.send_transaction(transaction) for _ in range(5)
        ]

        filter_a_changes_part_1 = eth_tester.get_only_filter_changes(filter_a_id)
        filter_a_logs_part_1 = eth_tester.get_all_filter_logs(filter_a_id)
        filter_b_logs_part_1 = eth_tester.get_all_filter_logs(filter_b_id)

        assert set(filter_a_changes_part_1) == set(filter_a_logs_part_1)
        assert set(filter_a_changes_part_1) == set(transactions_0_to_7).union(
            transactions_8_to_12
        )
        assert set(filter_b_logs_part_1) == set(transactions_8_to_12)

        # send 7 transactions
        transactions_13_to_20 = [
            eth_tester.send_transaction(transaction) for _ in range(7)
        ]

        filter_a_changes_part_2 = eth_tester.get_only_filter_changes(filter_a_id)
        filter_b_changes = eth_tester.get_only_filter_changes(filter_b_id)
        filter_a_logs_part_2 = eth_tester.get_all_filter_logs(filter_a_id)
        filter_b_logs_part_2 = eth_tester.get_all_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_2) == 7
        assert len(filter_b_changes) == 12
        assert len(filter_a_logs_part_2) == 20
        assert len(filter_b_logs_part_2) == 12

        assert set(filter_a_changes_part_2) == set(transactions_13_to_20)
        assert set(filter_b_changes) == set(filter_b_logs_part_2)
        assert set(filter_b_changes) == set(transactions_8_to_12).union(
            transactions_13_to_20
        )
        assert set(filter_a_logs_part_2) == set(transactions_0_to_7).union(
            transactions_8_to_12,
        ).union(transactions_13_to_20)
        assert set(filter_b_logs_part_2) == set(transactions_8_to_12).union(
            transactions_13_to_20
        )

    @pytest.mark.parametrize(
        "filter_topics,expected",
        (
            [None, 1],
            [[], 1],
            [["0xf70fe689e290d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb15"], 1],
            [
                [
                    "0xf70fe689e290d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb15",  # noqa: E501
                    None,
                ],
                1,
            ],
            [
                [
                    "0xf70fe689e290d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb15",  # noqa: E501
                    "0x" + "00" * 31 + "02",
                ],
                1,
            ],
            [
                [
                    "0xf70fe689e290d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb15",  # noqa: E501
                    "0x" + "00" * 31 + "99",
                ],
                0,
            ],
            [
                [
                    (
                        b"\xf7\x0f\xe6\x89\xe2\x90\xd8\xce+*8\x8a\xc2\x8d\xb3o\xbb\x0e"
                        b"\x16\xa6\xd8\x9ch\x04\xc4a\xf6Z\x1b@\xbb\x15"
                    )
                ],
                1,
            ],
        ),
        ids=[
            "filter None",
            "filter []",
            "filter Event only",
            "filter Event and None",
            "filter Event and argument",
            "filter Event and wrong argument",
            "filter Event only bytes",
        ],
    )
    def test_log_filter_picks_up_new_logs(self, eth_tester, filter_topics, expected):
        """
        Cases to test:
        - filter multiple transactions in one block.
        - filter mined.
        self.skip_if_no_evm_execution()

        - filter against topics.
        - filter against blocks numbers that are already mined.
        """
        self.skip_if_no_evm_execution()

        emitter_address = _deploy_emitter(eth_tester)
        emit_a_hash = _call_emitter(
            eth_tester,
            emitter_address,
            "logSingle",
            [EMITTER_ENUM["LogSingleWithIndex"], 1],
        )
        eth_tester.get_transaction_receipt(emit_a_hash)

        filter_event = eth_tester.create_log_filter(topics=filter_topics)
        _call_emitter(
            eth_tester,
            emitter_address,
            "logSingle",
            [EMITTER_ENUM["LogSingleWithIndex"], 2],
        )

        specific_logs_changes = eth_tester.get_only_filter_changes(filter_event)
        specific_logs_all = eth_tester.get_all_filter_logs(filter_event)
        specific_direct_logs_all = eth_tester.get_logs(topics=filter_topics)
        assert len(specific_logs_changes) == expected
        assert len(specific_logs_all) == expected
        assert len(specific_direct_logs_all) == expected

    @pytest.mark.parametrize(
        "filter_topics",
        (
            "not a list",
            {},
            1,
            [1],
            [1, 2],
            [1, None],
            [None, 1],
            [encode_hex(b"\x00" * 30 + b"\x01")],
            [encode_hex(b"\x00" * 32 + b"\x01")],
        ),
        ids=[
            "filter string",
            "filter dict",
            "filter int",
            "filter int in list",
            "filter multiple ints in list",
            "filter int and None in list",
            "filter None and int in list",
            "filter bytes with less than 32 bytes",
            "filter bytes with more than 32 bytes",
        ],
    )
    def test_log_filter_invalid_topics_throws_error(self, eth_tester, filter_topics):
        self.skip_if_no_evm_execution()

        emitter_address = _deploy_emitter(eth_tester)
        _call_emitter(
            eth_tester,
            emitter_address,
            "logSingle",
            [EMITTER_ENUM["LogSingleWithIndex"], 1],
        )

        with pytest.raises(ValidationError):
            eth_tester.create_log_filter(from_block=0, topics=filter_topics)

    def test_log_filter_includes_old_logs(self, eth_tester):
        """
        Cases to test:
        - filter multiple transactions in one block.
        - filter mined.
        self.skip_if_no_evm_execution()

        - filter against topics.
        - filter against blocks numbers that are already mined.
        """
        self.skip_if_no_evm_execution()

        emitter_address = _deploy_emitter(eth_tester)
        _call_emitter(
            eth_tester,
            emitter_address,
            "logSingle",
            [EMITTER_ENUM["LogSingleWithIndex"], 1],
        )

        filter_any_id = eth_tester.create_log_filter(from_block=0)
        _call_emitter(
            eth_tester,
            emitter_address,
            "logSingle",
            [EMITTER_ENUM["LogSingleWithIndex"], 2],
        )

        logs_changes = eth_tester.get_only_filter_changes(filter_any_id)
        logs_all = eth_tester.get_all_filter_logs(filter_any_id)
        direct_logs_all = eth_tester.get_logs(from_block=0)
        assert len(logs_changes) == len(logs_all) == len(direct_logs_all) == 2

    def test_log_filter_includes_latest_block_with_to_block(self, eth_tester):
        self.skip_if_no_evm_execution()

        emitter_address = _deploy_emitter(eth_tester)
        no_of_events = 2
        for i in range(1, no_of_events + 1):
            _call_emitter(
                eth_tester,
                emitter_address,
                "logSingle",
                [EMITTER_ENUM["LogSingleWithIndex"], i],
            )

        filter_any_id = eth_tester.create_log_filter(
            from_block=0, to_block=eth_tester.get_block_by_number("latest")["number"]
        )

        logs_changes = eth_tester.get_only_filter_changes(filter_any_id)
        logs_all = eth_tester.get_all_filter_logs(filter_any_id)
        assert len(logs_changes) == len(logs_all) == no_of_events

    def test_delete_filter(self, eth_tester):
        self.skip_if_no_evm_execution()

        filter_id = eth_tester.create_block_filter()

        eth_tester.get_all_filter_logs(filter_id)
        eth_tester.get_only_filter_changes(filter_id)

        eth_tester.delete_filter(filter_id)

        with pytest.raises(FilterNotFound):
            eth_tester.get_all_filter_logs(filter_id)
        with pytest.raises(FilterNotFound):
            eth_tester.get_only_filter_changes(filter_id)

        with pytest.raises(FilterNotFound):
            eth_tester.delete_filter(filter_id)

        with pytest.raises(FilterNotFound):
            eth_tester.delete_filter(12345)

    #
    # Serializer
    #
    def test_receipt_gas_used_computation(self, eth_tester):
        eth_tester.disable_auto_mine_transactions()

        tx_hashes = []
        for i in range(4):
            tx = {
                "from": eth_tester.get_accounts()[i],
                "to": eth_tester.get_accounts()[i + 1],
                "gas": (i + 1) * 20000 + 10000,
                "value": 1,
            }
            tx_hash = eth_tester.send_transaction(tx)
            tx_hashes.append(tx_hash)
        eth_tester.mine_block()

        cumulative_gas_used = 0
        for tx_hash in tx_hashes:
            receipt = eth_tester.get_transaction_receipt(tx_hash)
            cumulative_gas_used += receipt["gas_used"]
            assert receipt["gas_used"] == 21000
            assert receipt["cumulative_gas_used"] == cumulative_gas_used

    #
    # Time Travel
    #
    def test_time_traveling(self, eth_tester):
        # first mine a few blocks
        eth_tester.mine_blocks(3)

        # grab the block before time traveling
        before_block = eth_tester.get_block_by_number("pending")

        # now travel forward 2 minutes
        eth_tester.time_travel(before_block["timestamp"] + 120)

        # grab the new block
        after_block = eth_tester.get_block_by_number("pending")

        # test a block has been mined with expected timestamp during travel
        assert after_block["number"] == (before_block["number"] + 1)
        assert before_block["timestamp"] + 120 == after_block["timestamp"]

    def test_time_traveling_backwards_not_allowed(self, eth_tester):
        # first mine a few blocks
        eth_tester.mine_blocks(3)

        # check the time
        before_timestamp = eth_tester.get_block_by_number("pending")["timestamp"]

        # try to travel backwards 10 seconds
        with pytest.raises(ValidationError):
            eth_tester.time_travel(before_timestamp - 10)

    @pytest.mark.parametrize(
        "test_transaction", (SIMPLE_TRANSACTION,), ids=["Simple transaction"]
    )
    def test_get_transaction_receipt_byzantium(self, eth_tester, test_transaction):
        backend = eth_tester.backend.__class__()
        byzantium_eth_tester = eth_tester.__class__(backend=backend)
        accounts = byzantium_eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        transaction = assoc(test_transaction, "from", accounts[0])
        txn_hash = byzantium_eth_tester.send_transaction(transaction)
        txn = byzantium_eth_tester.get_transaction_receipt(txn_hash)

        assert "status" in txn
        assert txn["status"] == 1

    def test_duplicate_log_entries(self, eth_tester):
        self.skip_if_no_evm_execution()

        # setup the emitter
        emitter_address = _deploy_emitter(eth_tester)

        def _emit(v):
            return _call_emitter(
                eth_tester,
                emitter_address,
                "logSingle",
                [EMITTER_ENUM["LogSingleWithIndex"], v],
            )

        filter_id_1 = eth_tester.create_log_filter(from_block=0)
        assert len(eth_tester.get_all_filter_logs(filter_id_1)) == 0
        # emit 2 logs pre-filtering
        _emit(1)
        assert len(eth_tester.get_all_filter_logs(filter_id_1)) == 1
        _emit(2)
        assert len(eth_tester.get_all_filter_logs(filter_id_1)) == 2

        filter_id_2 = eth_tester.create_log_filter(from_block=0)
        assert len(eth_tester.get_all_filter_logs(filter_id_1)) == 2
        assert len(eth_tester.get_all_filter_logs(filter_id_2)) == 2
