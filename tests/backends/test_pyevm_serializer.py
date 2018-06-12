import pytest

from eth_tester import (
    EthereumTester,
    PyEVMBackend,
)


@pytest.mark.parametrize(
    'txs_info',
    (
        (
            [
                {'from': '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', 'to': '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF', 'gas': 30000, 'value': 1},  #noqa: E501
                {'from': '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF', 'to': '0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69', 'gas': 50000, 'value': 1},  #noqa: E501
                {'from': '0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69', 'to': '0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718', 'gas': 70000, 'value': 1},  #noqa: E501
                {'from': '0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718', 'to': '0xe1AB8145F7E55DC933d51a18c793F901A3A0b276', 'gas': 90000, 'value': 1},  #noqa: E501
            ]
        ),
    ),
)
def test_pyevm_receipt_gas_used_computation(txs_info):
    tester_chain = EthereumTester(backend=PyEVMBackend(), auto_mine_transactions=False)
    tx_hashes = []
    for tx_info in txs_info:
        tx_hash = tester_chain.send_transaction(tx_info)
        tx_hashes.append(tx_hash)
    tester_chain.mine_block()

    cumulative_gas_used = 0
    for tx_hash in tx_hashes:
        receipt = tester_chain.get_transaction_receipt(tx_hash)
        cumulative_gas_used += receipt['gas_used']
        assert receipt['gas_used'] == 21000
        assert receipt['cumulative_gas_used'] == cumulative_gas_used
