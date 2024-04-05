from __future__ import (
    absolute_import,
)

from typing import (
    Any,
    Dict,
    Union,
)

import pkg_resources
from semantic_version import (
    Version,
)


def get_pyevm_version():
    try:
        base_version = pkg_resources.parse_version(
            pkg_resources.get_distribution("py-evm").version
        ).base_version
        return Version(base_version)
    except pkg_resources.DistributionNotFound:
        return None


def is_supported_pyevm_version_available():
    version = get_pyevm_version()
    return version and version >= Version("0.5.0")


# --- network utils --- #


if is_supported_pyevm_version_available():
    from eth.abc import (
        BlockAPI,
    )
else:

    class BlockAPI:
        pass


def is_london_block(block: Union[Dict[str, Any], BlockAPI]) -> bool:
    if isinstance(block, BlockAPI):
        try:
            # it's not enough to check hasattr because the attribute could be
            # defined in earlier VM's while raising an AttributeError until implemented
            return block.header.base_fee_per_gas is not None
        except AttributeError:
            return False

    elif isinstance(block, dict) and "base_fee_per_gas" in block:
        return True

    return False


def is_shanghai_block(block: Union[Dict[str, Any], BlockAPI]) -> bool:
    if isinstance(block, BlockAPI):
        try:
            # it's not enough to check hasattr because the attribute could be
            # defined in earlier VM's while raising an AttributeError until implemented
            return block.header.withdrawals_root is not None
        except AttributeError:
            return False
    elif isinstance(block, dict) and "withdrawals_root" in block:
        return True

    return False


def is_cancun_block(block: Union[Dict[str, Any], BlockAPI]) -> bool:
    if isinstance(block, BlockAPI):
        try:
            # it's not enough to check hasattr because the attribute could be
            # defined in earlier VM's while raising an AttributeError until implemented
            return block.header.parent_beacon_block_root is not None
        except AttributeError:
            return False

    elif isinstance(block, dict) and all(
        cancun_field in block
        for cancun_field in (
            "parent_beacon_block_root",
            "blob_gas_used",
            "excess_blob_gas",
        )
    ):
        return True

    return False
