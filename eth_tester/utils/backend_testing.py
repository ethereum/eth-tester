from toolz.dicttoolz import (
    merge,
)
from hypothesis import (
    strategies as st,
    given,
    settings,
)
from hypothesis.stateful import (
    RuleBasedStateMachine,
    Bundle,
    rule,
)

from eth_utils import (
    to_normalized_address,
    is_address,
    is_integer,
    is_same_address,
)

from eth_tester.constants import (
    UINT256_MIN,
    UINT256_MAX,
    BURN_ADDRESS,
)


EVENT_EMITTER_BYTECODE = (
    "60606040526104ae806100126000396000f3606060405236156100615760e060020a60003504630b"
    "b563d6811461006357806317c0c1801461013657806320f0256e1461017057806390b41d8b146101"
    "ca5780639c37705314610215578063aa6fd82214610267578063e17bf956146102a9575b005b6020"
    "6004803580820135601f810184900490930260809081016040526060848152610061946024939192"
    "918401918190838280828437509496505050505050507fa95e6e2a182411e7a6f9ed114a85c3761d"
    "87f9b8f453d842c71235aa64fff99f81604051808060200182810382528381815181526020019150"
    "80519060200190808383829060006004602084601f0104600f02600301f150905090810190601f16"
    "80156101255780820380516001836020036101000a031916815260200191505b5092505050604051"
    "80910390a15b50565b610061600435600181141561037a577f1e86022f78f8d04f8e3dfd13a2bdb2"
    "80403e6632877c0dbee5e4eeb259908a5c60006060a1610133565b61006160043560243560443560"
    "64356084356005851415610392576060848152608084815260a084905260c08390527ff039d147f2"
    "3fe975a4254bdf6b1502b8c79132ae1833986b7ccef2638e73fdf991a15b5050505050565b610061"
    "60043560243560443560038314156103d457606082815260808290527fdf0cb1dea99afceb3ea698"
    "d62e705b736f1345a7eee9eb07e63d1f8f556c1bc590604090a15b505050565b6100616004356024"
    "356044356064356004841415610428576060838152608083905260a08290527f4a25b279c7c585f2"
    "5eda9788ac9420ebadae78ca6b206a0e6ab488fd81f550629080a15b50505050565b610061600435"
    "60243560028214156104655760608181527f56d2ef3c5228bf5d88573621e325a4672ab50e033749"
    "a601e4f4a5e1dce905d490602090a15b5050565b60206004803580820135601f8101849004909302"
    "60809081016040526060848152610061946024939192918401918190838280828437509496505050"
    "505050507f532fd6ea96cfb78bb46e09279a26828b8b493de1a2b8b1ee1face527978a15a5816040"
    "51808060200182810382528381815181526020019150805190602001908083838290600060046020"
    "84601f0104600f02600301f150905090810190601f16801561012557808203805160018360200361"
    "01000a03191681526020019150509250505060405180910390a150565b600081141561038d576000"
    "6060a0610133565b610002565b600b85141561038d5760608481526080849052819083907fa30ece"
    "802b64cd2b7e57dabf4010aabf5df26d1556977affb07b98a77ad955b590604090a36101c3565b60"
    "0983141561040f57606082815281907f057bc32826fbe161da1c110afcdcae7c109a8b69149f727f"
    "c37a603c60ef94ca90602090a2610210565b600883141561038d5760608281528190602090a16102"
    "10565b600a84141561038d576060838152819083907ff16c999b533366ca5138d78e85da51611089"
    "cd05749f098d6c225d4cd42ee6ec90602090a3610261565b600782141561049a57807ff70fe689e2"
    "90d8ce2b2a388ac28db36fbb0e16a6d89c6804c461f65a1b40bb1560006060a26102a5565b600682"
    "141561038d578060006060a16102a556"
)


CONTRACT_EMITTER_ABI = {
    {
        "constant": False,
        "inputs": [{"name": "v", "type": "string"}],
        "name": "logString",
        "outputs": [],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [{"name": "which", "type": "uint8"}],
        "name": "logNoArgs",
        "outputs": [],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "which", "type": "uint8"},
            {"name": "arg0", "type": "uint256"},
            {"name": "arg1", "type": "uint256"},
            {"name": "arg2", "type": "uint256"},
            {"name": "arg3", "type": "uint256"},
        ],
        "name": "logQuadruple",
        "outputs": [],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "which", "type": "uint8"},
            {"name": "arg0", "type": "uint256"},
            {"name": "arg1", "type": "uint256"},
        ],
        "name": "logDouble",
        "outputs": [],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "which", "type": "uint8"},
            {"name": "arg0", "type": "uint256"},
            {"name": "arg1", "type": "uint256"},
            {"name": "arg2", "type": "uint256"},
        ],
        "name": "logTriple",
        "outputs": [],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "which", "type": "uint8"},
            {"name": "arg0", "type": "uint256"},
        ],
        "name": "logSingle",
        "outputs": [],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [{"name": "v", "type": "bytes"}],
        "name": "logBytes",
        "outputs": [],
        "type": "function",
    },
    {"anonymous": True, "inputs": [], "name": "LogAnonymous", "type": "event"},
    {"anonymous": False, "inputs": [], "name": "LogNoArguments", "type": "event"},
    {
        "anonymous": False,
        "inputs": [{"indexed": False, "name": "arg0", "type": "uint256"}],
        "name": "LogSingleArg",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "name": "arg0", "type": "uint256"},
            {"indexed": False, "name": "arg1", "type": "uint256"},
        ],
        "name": "LogDoubleArg",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "name": "arg0", "type": "uint256"},
            {"indexed": False, "name": "arg1", "type": "uint256"},
            {"indexed": False, "name": "arg2", "type": "uint256"},
        ],
        "name": "LogTripleArg",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "name": "arg0", "type": "uint256"},
            {"indexed": False, "name": "arg1", "type": "uint256"},
            {"indexed": False, "name": "arg2", "type": "uint256"},
            {"indexed": False, "name": "arg3", "type": "uint256"},
        ],
        "name": "LogQuadrupleArg",
        "type": "event",
    },
    {
        "anonymous": True,
        "inputs": [{"indexed": True, "name": "arg0", "type": "uint256"}],
        "name": "LogSingleAnonymous",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [{"indexed": True, "name": "arg0", "type": "uint256"}],
        "name": "LogSingleWithIndex",
        "type": "event",
    },
    {
        "anonymous": True,
        "inputs": [
            {"indexed": False, "name": "arg0", "type": "uint256"},
            {"indexed": True, "name": "arg1", "type": "uint256"},
        ],
        "name": "LogDoubleAnonymous",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "name": "arg0", "type": "uint256"},
            {"indexed": True, "name": "arg1", "type": "uint256"},
        ],
        "name": "LogDoubleWithIndex",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "name": "arg0", "type": "uint256"},
            {"indexed": True, "name": "arg1", "type": "uint256"},
            {"indexed": True, "name": "arg2", "type": "uint256"},
        ],
        "name": "LogTripleWithIndex",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "name": "arg0", "type": "uint256"},
            {"indexed": False, "name": "arg1", "type": "uint256"},
            {"indexed": True, "name": "arg2", "type": "uint256"},
            {"indexed": True, "name": "arg3", "type": "uint256"},
        ],
        "name": "LogQuadrupleWithIndex",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [{"indexed": False, "name": "v", "type": "bytes"}],
        "name": "LogBytes",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [{"indexed": False, "name": "v", "type": "string"}],
        "name": "LogString",
        "type": "event",
    },
}


class BaseTestBackendDirect(object):
    #
    # Accounts
    #
    def test_get_accounts(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts
        assert all(
            is_address(account)
            for account
            in accounts
        )

    def test_get_balance_of_listed_accounts(self, eth_tester):
        for account in eth_tester.get_accounts():
            balance = eth_tester.get_balance(account)
            assert is_integer(balance)
            assert balance >= UINT256_MIN
            assert balance <= UINT256_MAX

    def test_get_nonce(self, eth_tester):
        for account in eth_tester.get_accounts():
            nonce = eth_tester.get_nonce(account)
        assert is_integer(nonce)
        assert nonce >= UINT256_MIN
        assert nonce <= UINT256_MAX

    #
    # Mining
    #
    def test_mine_block_single(self, eth_tester):
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.mine_blocks()
        after_block_number = eth_tester.get_latest_block()['number']
        assert is_integer(before_block_number)
        assert is_integer(after_block_number)
        assert before_block_number == after_block_number - 1

    def test_mine_multiple_blocks(self, eth_tester):
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.mine_blocks(10)
        after_block_number = eth_tester.get_latest_block()['number']
        assert is_integer(before_block_number)
        assert is_integer(after_block_number)
        assert before_block_number == after_block_number - 10

    #
    # Transaction Sending
    #
    def test_send_transaction(self, eth_tester):
        accounts = eth_tester.get_accounts()
        assert accounts, "No accounts available for transaction sending"

        transaction = {
            "from": accounts[0],
            "to": BURN_ADDRESS,
            "gas_price": 1,
            "value": 0,
            "gas": 21000,
        }
        txn_hash = eth_tester.send_transaction(transaction)
        txn = eth_tester.get_transaction_by_hash(txn_hash)

        assert is_same_address(txn['from'], transaction['from'])
        assert is_same_address(txn['to'], transaction['to'])
        assert txn['gas_price'] == transaction['gas_price']
        assert txn['gas'] == transaction['gas']
        assert txn['value'] == transaction['value']

    def test_auto_mine_transactions_enabled(self, eth_tester):
        eth_tester.configure(auto_mine_transactions=True)
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        after_block_number = eth_tester.get_latest_block()['number']
        assert before_block_number == after_block_number - 1

    def test_auto_mine_transactions_disabled(self, eth_tester):
        eth_tester.configure(auto_mine_transactions=False)
        before_block_number = eth_tester.get_latest_block()['number']
        eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        after_block_number = eth_tester.get_latest_block()['number']
        assert before_block_number == after_block_number

    #
    # Blocks
    #
    def test_get_genesis_block_by_number(self, eth_tester):
        block = eth_tester.get_block_by_number(0)
        assert block['number'] == 0

    def test_get_genesis_block_by_hash(self, eth_tester):
        genesis_hash = eth_tester.get_block_by_number(0)['hash']
        block = eth_tester.get_block_by_hash(genesis_hash)
        assert block['number'] == 0

    def test_get_block_by_number(self, eth_tester):
        mined_block_hashes = eth_tester.mine_blocks(10)
        for block_number, block_hash in enumerate(mined_block_hashes):
            block = eth_tester.get_block_by_number(block_number)
            assert block['number'] == block_number
            assert block['hash'] == block_hash

    def test_get_block_by_hash(self, eth_tester):
        mined_block_hashes = eth_tester.mine_blocks(10)
        for block_number, block_hash in enumerate(mined_block_hashes):
            block = eth_tester.get_block_by_hash(block_hash)
            assert block['number'] == block_number
            assert block['hash'] == block_hash

    # TODO: get_block_by_number('latest')
    # TODO: get_block_by_number('earliest')

    # Transactions
    def test_get_transaction_by_hash(self, eth_tester):
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        transaction = eth_tester.get_transaction_by_hash(transaction_hash)
        assert transaction['hash'] == transaction_hash

    def test_get_transaction_receipt_for_mined_transaction(self, eth_tester):
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt['transaction_hash'] == transaction_hash

    def test_get_transaction_receipt_for_unmined_transaction(self, eth_tester):
        eth_tester.configure(auto_mine_transactions=False)
        transaction_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        })
        receipt = eth_tester.get_transaction_receipt(transaction_hash)
        assert receipt is None

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

        filter_a_changes_part_1 = eth_tester.get_filter_changes(filter_a_id)
        filter_a_logs_part_1 = eth_tester.get_filter_logs(filter_a_id)
        filter_b_logs_part_1 = eth_tester.get_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_1) == 13
        assert len(filter_a_logs_part_1) == 13
        assert len(filter_b_logs_part_1) == 8

        assert set(filter_a_changes_part_1) == set(filter_a_logs_part_1)
        assert set(filter_a_changes_part_1) == set(blocks_10_to_14).union(blocks_15_to_22)
        assert set(filter_b_logs_part_1) == set(blocks_15_to_22)

        # mine another 7 blocks
        blocks_23_to_29 = eth_tester.mine_blocks(7)

        filter_a_changes_part_2 = eth_tester.get_filter_changes(filter_a_id)
        filter_b_changes = eth_tester.get_filter_changes(filter_b_id)
        filter_a_logs_part_2 = eth_tester.get_filter_logs(filter_a_id)
        filter_b_logs_part_2 = eth_tester.get_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_2) == 7
        assert len(filter_b_changes) == 15
        assert len(filter_a_logs_part_2) == 20
        assert len(filter_b_logs_part_2) == 15

        assert set(filter_a_changes_part_2) == set(blocks_23_to_29)
        assert set(filter_b_changes) == set(blocks_15_to_22).union(blocks_23_to_29)
        assert set(filter_b_changes) == set(filter_b_logs_part_2)
        assert set(filter_a_logs_part_2) == set(blocks_10_to_14).union(blocks_15_to_22).union(blocks_23_to_29)
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
            eth_tester.send_transaction(transaction)
            for _ in range(8)
        ]

        # setup another filter
        filter_b_id = eth_tester.create_pending_transaction_filter()

        # send 5 transactions
        transactions_8_to_12 = [
            eth_tester.send_transaction(transaction)
            for _ in range(5)
        ]

        filter_a_changes_part_1 = eth_tester.get_filter_changes(filter_a_id)
        filter_a_logs_part_1 = eth_tester.get_filter_logs(filter_a_id)
        filter_b_logs_part_1 = eth_tester.get_filter_logs(filter_b_id)

        assert set(filter_a_changes_part_1) == set(filter_a_logs_part_1)
        assert set(filter_a_changes_part_1) == set(transactions_0_to_7).union(transactions_8_to_12)
        assert set(filter_b_logs_part_1) == set(transactions_8_to_12)

        # send 7 transactions
        transactions_13_to_20 = [
            eth_tester.send_transaction(transaction)
            for _ in range(7)
        ]

        filter_a_changes_part_2 = eth_tester.get_filter_changes(filter_a_id)
        filter_b_changes = eth_tester.get_filter_changes(filter_b_id)
        filter_a_logs_part_2 = eth_tester.get_filter_logs(filter_a_id)
        filter_b_logs_part_2 = eth_tester.get_filter_logs(filter_b_id)

        assert len(filter_a_changes_part_2) == 7
        assert len(filter_b_changes) == 12
        assert len(filter_a_logs_part_2) == 20
        assert len(filter_b_logs_part_2) == 12

        assert set(filter_a_changes_part_2) == set(transactions_13_to_20)
        assert set(filter_b_changes) == set(filter_b_logs_part_2)
        assert set(filter_b_changes) == set(transactions_8_to_12).union(transactions_13_to_20)
        assert set(filter_a_logs_part_2) == set(transactions_0_to_7).union(transactions_8_to_12).union(transactions_13_to_20)
        assert set(filter_b_logs_part_2) == set(transactions_8_to_12).union(transactions_13_to_20)

    def test_log_filter(self, eth_tester):
        deploy_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "gas": 500000,
            "data": EVENT_EMITTER_BYTECODE,
        })
        deploy_receipt = eth_tester.get_transaction_receipt(deploy_hash)
        emitter_address = deploy_receipt['contract_address']
        assert len(emitter_address) > 3

        from eth_abi import (
            encode_abi,
        )
        emit_a_hash = eth_tester.send_transaction({
            "from": eth_tester.get_accounts()[0],
            "gas": 500000,
            "data": encode_abi(,
        })


address = st.binary(
    min_size=20,
    max_size=20,
).map(to_normalized_address)


class BaseTestBackendFuzz(object):
    @given(account=address)
    @settings(max_examples=10)
    def test_get_balance_simple_fuzzing(self, eth_tester, account):
        balance = eth_tester.get_balance(account)
        assert is_integer(balance)
        assert balance >= UINT256_MIN
        assert balance <= UINT256_MAX

    @given(account=address)
    @settings(max_examples=10)
    def test_get_nonce_simple_fuzzing(self, eth_tester, account):
        nonce = eth_tester.get_nonce(account)
        assert is_integer(nonce)
        assert nonce >= UINT256_MIN
        assert nonce <= UINT256_MAX


tx_gas = st.integers(min_value=0, max_value=10000000)
tx_gas_price = st.integers(min_value=1, max_value=1e15)
tx_value = st.integers(min_value=0, max_value=1e21)

transaction_st = st.tuples(
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'from': address}),
    ),
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'to': address}),
    ),
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'value': tx_value}),
    ),
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'gas': tx_gas}),
    ),
    st.one_of(
        st.fixed_dictionaries({}),
        st.fixed_dictionaries({'gas_price': tx_gas_price}),
    ),
).map(lambda parts: merge(*parts))


class EVMStateFuzzer(RuleBasedStateMachine):
    sent_transactions = Bundle('Transactions')

    def __init__(self, *args, **kwargs):
        from eth_tester import (
            EthereumTester,
            PyEthereum16Backend,
        )
        backend = PyEthereum16Backend()
        self.eth_tester = EthereumTester(backend=backend)
        super(EVMStateFuzzer, self).__init__(*args, **kwargs)

    #@rule(target=transactions, transaction=transaction_st)
    @rule(target=sent_transactions)
    def send_transaction(self, transaction=transaction_st):
        transaction = {
            "from": self.eth_tester.get_accounts()[0],
            "to": BURN_ADDRESS,
            "gas": 21000,
        }
        transaction_hash = self.eth_tester.send_transaction(transaction)
        return (transaction, transaction_hash)

    @rule(sent_transaction=sent_transactions)
    def check_transaction_hashes(self, sent_transaction):
        transaction, transaction_hash = sent_transaction
        actual_transaction = self.eth_tester.get_transaction_by_hash(transaction_hash)
        assert actual_transaction['hash'] == transaction_hash
