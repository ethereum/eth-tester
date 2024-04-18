from importlib.metadata import (
    PackageNotFoundError,
    version,
)
from typing import (
    Any,
    Dict,
    Union,
)

from semantic_version import (
    Version,
)


def get_pyevm_version():
    try:
        # Fetch the version string of py-evm from its metadata
        base_version = version("py-evm")
        # Create a Version instance from the semantic version library
        return Version.coerce(base_version)
    except PackageNotFoundError:
        print("Package 'py-evm' not found.")
        return None
    except ValueError as ve:
        print(f"Version parsing error: {ve}")
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
