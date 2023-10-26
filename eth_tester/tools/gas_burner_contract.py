from __future__ import (
    unicode_literals,
)

from eth_abi import (
    abi,
)
from eth_utils import (
    encode_hex,
    function_abi_to_4byte_selector,
)

# The following contract burns gas relative to the current block number. The
# higher the block number, the more gas is burned. It is used to test
# functionality that uses block identifiers.
#
# pragma solidity >=0.4.22 <0.7.0;
#
# contract GasBurner {
#     uint256 total;
#     function burnBlockNumberDependentGas() public {
#         for(uint256 i=0; i<block.number*10; i++) {
#             total++;
#         }
#     }
# }

GAS_BURNER_BYTECODE = (
    "6080604052348015600f57600080fd5b50609b8061001e6000396000f3fe6080604052348015600f5"
    "7600080fd5b506004361060285760003560e01c8063aeecb68814602d575b600080fd5b6033603556"
    "5b005b60008090505b600a43028110156062576000808154809291906001019190505550808060010"
    "1915050603b565b5056fea2646970667358221220b69191cdd18045d942bd33c23c74ed334b2604f5"
    "8490458cc8581e54f8cffed664736f6c63430006060033"
)

GAS_BURNER_ABI = {
    "burnBlockNumberDependentGas": {
        "inputs": [],
        "name": "burnBlockNumberDependentGas",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
}


def _deploy_gas_burner(eth_tester):
    deploy_hash = eth_tester.send_transaction(
        {
            "from": eth_tester.get_accounts()[0],
            "gas": 500000,
            "data": GAS_BURNER_BYTECODE,
        }
    )
    deploy_receipt = eth_tester.get_transaction_receipt(deploy_hash)
    gas_burner_address = deploy_receipt["contract_address"]
    assert gas_burner_address
    gas_burner_code = eth_tester.get_code(gas_burner_address)
    assert len(gas_burner_code) > 2
    return gas_burner_address


def _make_call_gas_burner_transaction(
    eth_tester, contract_address, fn_name, fn_args=tuple()
):
    fn_abi = GAS_BURNER_ABI[fn_name]
    arg_types = [arg_abi["type"] for arg_abi in fn_abi["inputs"]]
    fn_selector = function_abi_to_4byte_selector(fn_abi)
    transaction = {
        "from": eth_tester.get_accounts()[0],
        "to": contract_address,
        "gas": 500000,
        "data": encode_hex(fn_selector + abi.encode(arg_types, fn_args)),
    }
    return transaction
