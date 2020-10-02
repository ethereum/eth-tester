from __future__ import unicode_literals

from eth_utils import (
    encode_hex,
    function_abi_to_4byte_selector,
)


GAS_BURNER_BYTECODE = (
    "6080604052348015600f57600080fd5b5060978061001e6000396000f3fe6080604052348015600f5"
    "7600080fd5b506004361060285760003560e01c8063aeecb68814602d575b600080fd5b6033603556"
    "5b005b60008090505b43811015605f576000808154809291906001019190505550808060010191505"
    "0603b565b5056fea265627a7a72305820a3f36f9da109907cd816ff48f1fd3bab758923f9dbccbd1a"
    "0f397cc70ef5423f64736f6c63430005090032"
)

GAS_BURNER_ABI = {
    "burnBlockNumberDependentGas": {
        "inputs": [],
        "name": "burnBlockNumberDependentGas",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
}


def _deploy_gas_burner(eth_tester):
    deploy_hash = eth_tester.send_transaction({
        "from": eth_tester.get_accounts()[0],
        "gas": 500000,
        "data": GAS_BURNER_BYTECODE,
    })
    deploy_receipt = eth_tester.get_transaction_receipt(deploy_hash)
    gas_burner_address = deploy_receipt['contract_address']
    assert gas_burner_address
    gas_burner_code = eth_tester.get_code(gas_burner_address)
    assert len(gas_burner_code) > 2
    return gas_burner_address


def _make_call_gas_burner_transaction(eth_tester, contract_address, fn_name, fn_args=None):
    from eth_abi import encode_abi

    if fn_args is None:
        fn_args = tuple()

    fn_abi = GAS_BURNER_ABI[fn_name]
    arg_types = [
        arg_abi['type']
        for arg_abi
        in fn_abi['inputs']
    ]
    fn_selector = function_abi_to_4byte_selector(fn_abi)
    transaction = {
        "from": eth_tester.get_accounts()[0],
        "to": contract_address,
        "gas": 500000,
        "data": encode_hex(fn_selector + encode_abi(arg_types, fn_args)),
    }
    return transaction
