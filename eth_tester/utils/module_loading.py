from __future__ import (
    absolute_import,
)

from importlib import (
    import_module,
)


def import_string(dotted_path):
    """
    Source: django.utils.module_loading

    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.
    """
    try:
        module_path, class_name = dotted_path.rsplit(".", 1)
    except ValueError:
        msg = "%s doesn't look like a module path" % dotted_path
        raise ImportError(msg)

    module = import_module(module_path)

    try:
        return getattr(module, class_name)
    except AttributeError:
        msg = 'Module "{}" does not define a "{}" attribute/class'.format(
            module_path, class_name
        )
        raise ImportError(msg)


def get_import_path(obj):
    return ".".join(
        (
            obj.__module__,
            obj.__name__,
        )
    )
