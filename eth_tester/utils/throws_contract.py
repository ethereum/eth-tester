from __future__ import (
    unicode_literals,
)

from eth_abi import (
    abi,
)
from eth_utils import (
    decode_hex,
    encode_hex,
    function_abi_to_4byte_selector,
)

# Just for reference.
THROWS_SOURCE = (
    """
    contract Test {
        uint public value = 1;
        function setValue(uint _value) {
            value = _value;
        }
        function willThrow() {
            require(false);
        }
    }
    """,
    """
    pragma solidity ^0.4.22;
    contract DoRevert {
        function do_revert(bool _revert) public pure returns (string message) {
            if (_revert) {
                revert("ribbert, ribbert");
            }
            return "No ribbert";
        }
    }
    """,
)


THROWS_BYTECODE = {
    "throw_contract": "60606040526001600055341561001457600080fd5b60f280610022600039600"
    "0f30060606040526000357c0100000000000000000000000000000000000000000000000000000000"
    "900463ffffffff16806318955b1e1460505780633fa4f245146062578063552410771460885760008"
    "0fd5b3415605a57600080fd5b606060a8565b005b3415606c57600080fd5b607260b6565b60405180"
    "82815260200191505060405180910390f35b3415609257600080fd5b60a6600480803590602001909"
    "190505060bc565b005b6000151560b457600080fd5b565b60005481565b80600081905550505600a1"
    "65627a7a72305820d58a6b595eeb1a765e71924eec6e96c98c1fe9e90876ec232593b9ebb9c686500"
    "029",
    "revert_contract": "608060405234801561001057600080fd5b506101cd806100206000396000f3"
    "00608060405260043610610041576000357c010000000000000000000000000000000000000000000"
    "0000000000000900463ffffffff168063dfac107114610046575b600080fd5b348015610052576000"
    "80fd5b506100736004803603810190808035151590602001909291905050506100ee565b604051808"
    "0602001828103825283818151815260200191508051906020019080838360005b838110156100b357"
    "8082015181840152602081019050610098565b50505050905090810190601f1680156100e05780820"
    "380516001836020036101000a031916815260200191505b509250505060405180910390f35b606081"
    "15610164576040517f08c379a00000000000000000000000000000000000000000000000000000000"
    "081526004018080602001828103825260108152602001807f726962626572742c2072696262657274"
    "0000000000000000000000000000000081525060200191505060405180910390fd5b6040805190810"
    "160405280600a81526020017f4e6f2072696262657274000000000000000000000000000000000000"
    "0000000081525090509190505600a165627a7a723058206fc7f85b6a52373bc74978757e75e3a100b"
    "44024e61485612d0f3cd27e32cdd60029",
}


THROWS_ABI = {
    "throw_contract": {
        "willThrow": {
            "constant": False,
            "inputs": [],
            "name": "willThrow",
            "outputs": [],
            "payable": False,
            "stateMutability": "nonpayable",
            "type": "function",
        },
        "value": {
            "constant": True,
            "inputs": [],
            "name": "value",
            "outputs": [{"name": "", "type": "uint256"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        "setValue": {
            "constant": False,
            "inputs": [{"name": "_value", "type": "uint256"}],
            "name": "setValue",
            "outputs": [],
            "payable": False,
            "stateMutability": "nonpayable",
            "type": "function",
        },
    },
    "revert_contract": {
        "do_revert": {
            "constant": True,
            "inputs": [{"name": "_revert", "type": "bool"}],
            "name": "do_revert",
            "outputs": [{"name": "message", "type": "string"}],
            "payable": False,
            "stateMutability": "pure",
            "type": "function",
        }
    },
}


def _deploy_throws(eth_tester, contract_name):
    deploy_hash = eth_tester.send_transaction(
        {
            "from": eth_tester.get_accounts()[0],
            "gas": 500000,
            "data": THROWS_BYTECODE[contract_name],
        }
    )
    deploy_receipt = eth_tester.get_transaction_receipt(deploy_hash)
    throws_address = deploy_receipt["contract_address"]
    assert throws_address
    throws_code = eth_tester.get_code(throws_address)
    assert len(throws_code) > 2
    return throws_address


def _make_call_throws_transaction(
    eth_tester, contract_address, contract_name, fn_name, fn_args=None
):
    from eth_abi import (
        encode,
    )

    if fn_args is None:
        fn_args = tuple()

    fn_abi = THROWS_ABI[contract_name][fn_name]
    arg_types = [arg_abi["type"] for arg_abi in fn_abi["inputs"]]
    fn_selector = function_abi_to_4byte_selector(fn_abi)
    transaction = {
        "from": eth_tester.get_accounts()[0],
        "to": contract_address,
        "gas": 500000,
        "data": encode_hex(fn_selector + encode(arg_types, fn_args)),
    }
    return transaction


def _decode_throws_result(contract_name, fn_name, result):
    fn_abi = THROWS_ABI[contract_name][fn_name]
    output_types = [output_abi["type"] for output_abi in fn_abi["outputs"]]

    return abi.decode(output_types, decode_hex(result))
