from __future__ import unicode_literals

from eth_utils import (
    encode_hex,
    function_abi_to_4byte_selector,
)


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
    """
)


THROWS_BYTECODE = (
    "60606040526001600055341561001457600080fd5b60f2806100226000396000f3006060604052600"
    "0357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680"
    "6318955b1e1460505780633fa4f2451460625780635524107714608857600080fd5b3415605a57600"
    "080fd5b606060a8565b005b3415606c57600080fd5b607260b6565b60405180828152602001915050"
    "60405180910390f35b3415609257600080fd5b60a6600480803590602001909190505060bc565b005"
    "b6000151560b457600080fd5b565b60005481565b80600081905550505600a165627a7a72305820d5"
    "8a6b595eeb1a765e71924eec6e96c98c1fe9e90876ec232593b9ebb9c686500029"
)


THROWS_ABI = {
    'willThrow': {
        'constant': False,
        'inputs': [],
        'name': 'willThrow',
        'outputs': [],
        'payable': False,
        'stateMutability': 'nonpayable',
        'type': 'function',
    },
    'value': {
        'constant': True,
        'inputs': [],
        'name': 'value',
        'outputs': [{'name': '', 'type': 'uint256'}],
        'payable': False,
        'stateMutability': 'view',
        'type': 'function',
    },
    'setValue': {
        'constant': False,
        'inputs': [{'name': '_value', 'type': 'uint256'}],
        'name': 'setValue',
        'outputs': [],
        'payable': False,
        'stateMutability': 'nonpayable',
        'type': 'function',
    },
}


def _deploy_throws(eth_tester):
    deploy_hash = eth_tester.send_transaction({
        "from": eth_tester.get_accounts()[0],
        "gas": 500000,
        "data": THROWS_BYTECODE,
    })
    deploy_receipt = eth_tester.get_transaction_receipt(deploy_hash)
    throws_address = deploy_receipt['contract_address']
    assert throws_address
    throws_code = eth_tester.get_code(throws_address)
    assert len(throws_code) > 2
    return throws_address


def _make_call_throws_transaction(eth_tester, contract_address, fn_name, fn_args=None):
    from eth_abi import encode_abi

    if fn_args is None:
        fn_args = tuple()

    fn_abi = THROWS_ABI[fn_name]
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


def _decode_throws_result(fn_name, result):
    from eth_abi import decode_abi

    fn_abi = THROWS_ABI[fn_name]
    output_types = [
        output_abi['type']
        for output_abi
        in fn_abi['outputs']
    ]

    return decode_abi(output_types, result)
