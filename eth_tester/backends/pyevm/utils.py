from __future__ import absolute_import

import pkg_resources

from semantic_version import (
    Version,
    Spec,
)

def get_pyevm_version():
    try:
        return pkg_resources.get_distribution("py-evm").version
    except pkg_resources.DistributionNotFound:
        return None

def is_pyevm_available():
    pyevm_version = get_pyevm_version()
    
    if pyevm_version is None:
        return False
    else: 
        return True