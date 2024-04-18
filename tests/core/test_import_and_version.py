def test_import_and_version():
    import eth_tester

    assert isinstance(eth_tester.__version__, str)
