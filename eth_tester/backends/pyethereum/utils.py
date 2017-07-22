from __future__ import absolute_import

import pkg_resources

from semantic_version import (
    Version,
    Spec,
)


def get_pyethereum_version():
    try:
        return Version(pkg_resources.get_distribution("ethereum").version)
    except pkg_resources.DistributionNotFound:
        return None


def is_pyethereum16_available():
    pyethereum_version = get_pyethereum_version()

    if pyethereum_version is None:
        return False
    elif pyethereum_version not in Spec('>=1.6.0,<1.7.0'):
        return False
    else:
        return True


def is_pyethereum20_available():
    pyethereum_version = get_pyethereum_version()

    if pyethereum_version is None:
        return False
    elif pyethereum_version not in Spec('>=2.0.0,<2.1.0'):
        return False
    else:
        return True
