from __future__ import (
    absolute_import,
)

import importlib.metadata
import re

from semantic_version import (
    Version,
)

# We only care about the release segment of the version. Regexp taken from:
# https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions
RELEASE_MATCHER = re.compile(r'^[0-9]+(?:\.[0-9]+)*').match


def get_pyevm_version():
    try:
        version = importlib.metadata.version("py-evm")
    except importlib.metadata.PackageNotFoundError:
        return None
    else:
        base_version = RELEASE_MATCHER(version)[0]
        return Version(base_version)


def is_supported_pyevm_version_available():
    version = get_pyevm_version()
    return version and version >= Version("0.5.0")
