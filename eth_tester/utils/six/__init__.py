from __future__ import absolute_import

import sys


if sys.version_info.major == 2:
    from .py2 import (  # noqa: F401
        Queue,
        Empty,
    )
else:
    from .py3 import (  # noqa: F401
        Queue,
        Empty,
    )
