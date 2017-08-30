def test_web3_web3_clientVersion(web3):
    client_version = web3.version.node
    assert client_version.startswith('EthereumTester')
