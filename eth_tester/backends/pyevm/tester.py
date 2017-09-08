#
#
# THIS IS A SNIPPET FROM THE LOCAL VERSION OF PYEVM/TOOLS/TESTER.PY
#
#
import tempfile

from evm.db import get_db_backend
from evm.chain import Chain
from evm.constants import (
    GENESIS_PARENT_HASH,
    EMPTY_UNCLE_HASH,
    GENESIS_COINBASE,
    BLANK_ROOT_HASH,
    GENESIS_BLOCK_NUMBER,
    GENESIS_DIFFICULTY,
    GENESIS_GAS_LIMIT,
    GENESIS_EXTRA_DATA,
    GENESIS_MIX_HASH,
    GENESIS_NONCE
)
from evm.utils.address import private_key_to_address
from evm.utils.keccak import keccak
from evm.utils.numeric import int_to_big_endian
from evm.vm.flavors.frontier import FrontierVM
from rlp.utils import decode_hex, encode_hex as _encode_hex, ascii_chr, str_to_bytes
import rlp

accounts = []
keys = []
languages = {}

for account_number in range(10):
    keys.append(keccak(int_to_big_endian(account_number)))
    accounts.append(private_key_to_address(keys[-1]))

k0, k1, k2, k3, k4, k5, k6, k7, k8, k9 = keys[:10]
a0, a1, a2, a3, a4, a5, a6, a7, a8, a9 = accounts[:10]

DEFAULT_ACCOUNT = a0

def int_to_addr(x):
        o = [b''] * 20
        for i in range(20):
            o[19 - i] = ascii_chr(x & 0xff)
            x >>= 8
        return b''.join(o)

class state(object):
    def __init__(self, num_accounts=len(keys)):
        self.temp_data_dir = tempfile.mkdtemp()
        self.db = get_db_backend()
        self.config = {}
        self.last_tx = None

        initial_balances = {}

        for i in range(num_accounts):
            account = accounts[i]
            initial_balances[account] = {'wei': 10 ** 24}

        for i in range(1, 5):
            address = int_to_addr(i)
            initial_balances[address] = {'wei': 1}
        Chain.vms_by_range = {0 : FrontierVM}

        self.block = Chain.from_genesis(
            self.db,
            genesis_params = {
                'parent_hash': GENESIS_PARENT_HASH,
                'uncles_hash': EMPTY_UNCLE_HASH,
                'coinbase': GENESIS_COINBASE,
                'state_root': BLANK_ROOT_HASH,
                'transaction_root': b'',
                'receipt_root': b'',
                'bloom': 0,
                'difficulty': GENESIS_DIFFICULTY,
                'block_number': GENESIS_BLOCK_NUMBER,
                'gas_limit': GENESIS_GAS_LIMIT,
                'gas_used': 0,
                'timestamp': 0,
                'extra_data': GENESIS_EXTRA_DATA,
                'mix_hash': GENESIS_MIX_HASH,
                'nonce': GENESIS_NONCE,
            }
        )

        self.blocks = [self.block]

    def mine(self, number_of_blocks=1, coinbase=DEFAULT_ACCOUNT, **kwargs):
        if 'n' in kwargs: # compatibility
            number_of_blocks = kwargs['n']
            wargnings.warn(
                "The argument 'n' is deprecated and its support will be removed "
                "in the future versions. Please use the name 'number_of_blocks'."
            )

        for _ in range(number_of_blocks):
            # self.block.finalize()
            # self.block.commit_state()
            # self.db.set(self.block.hash, rlp.encode(self.block))
            self.db.set(self.block.__hash__, b'')
            # timestamp = self.block.timestamp + 6 + rand() % 12

            block = blocks.Block.init_from_parent(
                self.block,
                coinbase,
                timestamp=timestamp,
            )

            self.block = block
            self.blocks.append(self.block)
