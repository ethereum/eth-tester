from eth_tester.normalization.inbound import (
    _normalize_inbound_access_list,
)


def test_inbound_access_list_normalization():
    inbound_access_list = [
        {
            "address": "0x52908400098527886E0F7030069857D2E4169EE7",
            "storage_keys": [f"0x{'00' * 30}3039", f"0x{'00' * 30}0539"],
        },
        {
            "address": "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            "storage_keys": [],
        },
        {
            "address": f"0x{'00' * 20}",
            "storage_keys": [f"0x{'00' * 28}499602d2"],
        },
    ]
    expected = (
        (
            b"R\x90\x84\x00\t\x85'\x88n\x0fp0\x06\x98W\xd2\xe4\x16\x9e\xe7",
            (12345, 1337),
        ),
        (
            b"\x86\x17\xe3@\xb3\xd0\x1f\xa5\xf1\x1f0o@\x90\xfdP\xe28\x07\r",
            (),
        ),
        (b"\x00" * 20, (1234567890,)),
    )
    assert _normalize_inbound_access_list(inbound_access_list) == expected
