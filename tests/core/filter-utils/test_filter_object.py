from __future__ import (
    unicode_literals,
)

import pytest

from eth_tester.utils.filters import (
    Filter,
)


@pytest.fixture
def f():
    _f = Filter(None)
    return _f


def test_filter_starts_empty(f):
    assert not f.get_changes()
    assert not f.get_all()

    # put an item in the filter
    f.add("value-a")

    # verify it has values
    assert f.get_all()
    # get all the changes
    assert f.get_changes()

    # verify that it no longer has changes
    assert not f.get_changes()

    # put another item in the filter
    f.add("value-b")

    # verify that it now has changes again
    assert f.get_changes()

    # verify that it no longer has changes
    assert not f.get_changes()


def test_filter_maintains_ordering(f):
    values = ("value-a", "value-b", "value-c", "value-d", "value-e")
    for item in values[:3]:
        f.add(item)

    assert f.get_changes() == values[:3]
    assert f.get_all() == values[:3]

    for item in values[3:]:
        f.add(item)

    assert f.get_changes() == values[3:]
    assert f.get_all() == values
