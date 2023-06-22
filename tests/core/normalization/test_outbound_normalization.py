import pytest

from eth_tester.normalization.outbound import (
    normalize_receipt,
)

from tests.utils import (
    make_receipt,
)


@pytest.mark.parametrize(
    "status,contract_address,expected",
    (
        (1, b"\x01" * 20, f"0x{'01' * 20}"),
        (0, b"\x01" * 20, None),
    ),
)
def test_outbound_receipt_contract_address_status_based_normalization(
    status,
    contract_address,
    expected,
):
    receipt = make_receipt(status=status, contract_address=contract_address)

    assert receipt["status"] == status
    assert receipt["contract_address"] == contract_address

    normalized_receipt = normalize_receipt(receipt)

    assert normalized_receipt["status"] == status
    assert normalized_receipt["contract_address"] == expected
