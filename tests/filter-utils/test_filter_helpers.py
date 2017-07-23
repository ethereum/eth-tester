from __future__ import unicode_literals

import pytest

from eth_tester.utils.filters import (
    check_single_topic_match,
    check_if_from_block_match,
    check_if_to_block_match,
    check_if_topics_match,
    check_if_address_match,
    check_if_log_matches,
    is_topic,
    is_flat_topic_array,
    is_nested_topic_array,
    is_topic_array,
)


TOPIC_A = b'\x00' * 32
TOPIC_B = b'\x00' * 31 + b'\x01'
TOPIC_C = b'\x00' * 31 + b'\x02'


@pytest.mark.parametrize(
    'value,expected',
    (
        # bad values
        ('', False),
        ('a', False),
        (1, False),
        (True, False),
        ({'a': 1, 'b': 2}, False),
        (tuple(), False),
        (list(), False),
        (('a', 'b'), False),
        (['a', 'b'], False),
        (b'', False),
        (b'arst', False),
        # good values
        (None, True),
        (TOPIC_A, True),
        (TOPIC_B, True),
    )
)
def test_is_topic(value, expected):
    actual = is_topic(value)
    assert actual is expected


TOPICS_EMPTY = tuple()
TOPICS_SINGLE_NULL = (None,)
TOPICS_MANY = (TOPIC_A, TOPIC_B)
TOPICS_MANY_WITH_NULL = (TOPIC_A, None, TOPIC_B)


@pytest.mark.parametrize(
    'value,expected',
    (
        # bad values
        ('', False),
        ('a', False),
        (1, False),
        (True, False),
        ({'a': 1, 'b': 2}, False),
        (None, False),
        (b'', False),
        (b'arst', False),
        (('a', 'b'), False),
        (['a', 'b'], False),
        ([b'a', b'b'], False),
        ([b'a', None, b'b'], False),
        (list(), False),
        ([None], False),
        ((None, b'a'), False),
        ((TOPIC_A, b'a'), False),
        ((b'a', None), False),
        ((b'a', TOPIC_A), False),
        ((TOPIC_A, b'a', TOPIC_B), False),
        # good values
        (TOPICS_EMPTY, True),
        (TOPICS_SINGLE_NULL, True),
        (TOPICS_MANY, True),
        (TOPICS_MANY_WITH_NULL, True),
    )
)
def test_is_flat_topic_array(value, expected):
    actual = is_flat_topic_array(value)
    assert actual is expected


NESTED_TOPICS_A = (TOPICS_EMPTY,)
NESTED_TOPICS_B = (TOPICS_EMPTY, TOPICS_SINGLE_NULL)
NESTED_TOPICS_C = (TOPICS_SINGLE_NULL, TOPICS_MANY)
NESTED_TOPICS_D = (TOPICS_MANY_WITH_NULL, TOPICS_MANY, TOPICS_EMPTY)


@pytest.mark.parametrize(
    'value,expected',
    (
        # bad values
        ('', False),
        ('a', False),
        (1, False),
        (True, False),
        ({'a': 1, 'b': 2}, False),
        (None, False),
        (b'', False),
        (b'arst', False),
        (('a', 'b'), False),
        (['a', 'b'], False),
        ([b'a', b'b'], False),
        ([b'a', None, b'b'], False),
        (list(), False),
        ([None], False),
        (TOPIC_A, False),
        (TOPICS_EMPTY, False),
        (TOPICS_SINGLE_NULL, False),
        (TOPICS_MANY, False),
        (TOPICS_MANY_WITH_NULL, False),
        (([],), False),
        (([tuple()],), False),
        ([tuple()], False),
        ((tuple(), []), False),
        ((TOPICS_EMPTY, (b'arst',)), False),
        # good values
        (NESTED_TOPICS_A, True),
        (NESTED_TOPICS_B, True),
        (NESTED_TOPICS_C, True),
        (NESTED_TOPICS_D, True),
    )
)
def test_is_nested_topic_array(value, expected):
    actual = is_nested_topic_array(value)
    assert actual is expected


@pytest.mark.parametrize(
    'value,expected',
    (
        # bad values
        ('', False),
        ('a', False),
        (1, False),
        (True, False),
        ({'a': 1, 'b': 2}, False),
        (None, False),
        (b'', False),
        (b'arst', False),
        (('a', 'b'), False),
        (['a', 'b'], False),
        ([b'a', b'b'], False),
        ([b'a', None, b'b'], False),
        (list(), False),
        ([None], False),
        (([],), False),
        (([tuple()],), False),
        ([tuple()], False),
        ((tuple(), []), False),
        ((TOPICS_EMPTY, (b'arst',)), False),
        # good values
        (TOPICS_EMPTY, True),
        (TOPICS_SINGLE_NULL, True),
        (TOPICS_MANY, True),
        (TOPICS_MANY_WITH_NULL, True),
        (NESTED_TOPICS_A, True),
        (NESTED_TOPICS_B, True),
        (NESTED_TOPICS_C, True),
        (NESTED_TOPICS_D, True),
    )
)
def test_is_topic_array(value, expected):
    actual = is_topic_array(value)
    assert actual is expected


TOPIC_A_AS_TEXT = '\x00' * 32
TOPIC_B_AS_TEXT = '\x00' * 31 + '\x01'


@pytest.mark.parametrize(
    'value,topic,expected',
    (
        # bad values
        ('mismatch', TOPIC_A, False),
        (TOPIC_A_AS_TEXT, TOPIC_A, False),
        (TOPIC_B, TOPIC_A, False),
        # good values
        (TOPIC_A, TOPIC_A, True),
        (TOPIC_B, TOPIC_B, True),
        (TOPIC_A, None, True),
        (TOPIC_B, None, True),
    )
)
def test_check_single_topic_match(value, topic, expected):
    actual = check_single_topic_match(value, topic)
    assert actual is expected


@pytest.mark.parametrize(
    'block_number,_type,from_block,expected',
    (
        # bad values
        (10, 'mined', 11, False),
        (10, 'mined', 'pending', False),
        (10, 'mined', 'earliest', False),
        # good values
        (10, 'mined', None, True),
        (10, 'mined', 10, True),
        (20, 'mined', 10, True),
        (10, 'mined', 'latest', True),
        (10, 'pending', 'pending', True),
        (10, 'pending', 'earliest', True),
    )
)
def test_check_if_from_block_match(block_number, _type, from_block, expected):
    actual =  check_if_from_block_match(block_number, _type, from_block)
    assert actual is expected


@pytest.mark.parametrize(
    'block_number,_type,to_block,expected',
    (
        # bad values
        (11, 'mined', 10, False),
        (10, 'mined', 'pending', False),
        (10, 'mined', 'earliest', False),
        # good values
        (10, 'mined', None, True),
        (10, 'mined', 10, True),
        (9, 'mined', 10, True),
        (10, 'mined', 'latest', True),
        (10, 'pending', 'pending', True),
        (10, 'pending', 'earliest', True),
    )
)
def test_check_if_to_block_match(block_number, _type, to_block, expected):
    actual = check_if_to_block_match(block_number, _type, to_block)
    assert actual is expected


TOPICS_EMPTY = tuple()
TOPICS_ONLY_A = (TOPIC_A,)
TOPICS_ONLY_B = (TOPIC_B,)
TOPICS_ONLY_C = (TOPIC_C,)
TOPICS_A_A = (TOPIC_A, TOPIC_A)
TOPICS_A_B = (TOPIC_A, TOPIC_B)
TOPICS_A_C = (TOPIC_A, TOPIC_C)
TOPICS_A_B_C = (TOPIC_A, TOPIC_B, TOPIC_C)
TOPICS_A_C_B = (TOPIC_A, TOPIC_C, TOPIC_B)
TOPICS_B_A = (TOPIC_B, TOPIC_A)
TOPICS_B_C = (TOPIC_B, TOPIC_C)
TOPICS_B_A_C = (TOPIC_B, TOPIC_A, TOPIC_C)
TOPICS_B_C_A = (TOPIC_B, TOPIC_C, TOPIC_A)


FILTER_MATCH_ALL = tuple()
FILTER_MATCH_ANY_ONE = (None,)
FILTER_MATCH_ANY_TWO = (None, None)
FILTER_MATCH_ANY_THREE = (None, None, None)
FILTER_MATCH_ONLY_A = (TOPIC_A,)
FILTER_MATCH_ONLY_B = (TOPIC_B,)
FILTER_MATCH_ONLY_C = (TOPIC_C,)
FILTER_MATCH_A_ANY = (TOPIC_A, None)
FILTER_MATCH_B_ANY = (TOPIC_B, None)
FILTER_MATCH_C_ANY = (TOPIC_C, None)
FILTER_MATCH_ANY_A = (None, TOPIC_A)
FILTER_MATCH_ANY_B = (None, TOPIC_B)
FILTER_MATCH_ANY_C = (None, TOPIC_C)
FILTER_MATCH_A_B = (TOPIC_A, TOPIC_B)
FILTER_MATCH_B_C = (TOPIC_B, TOPIC_C)
FILTER_MATCH_A_B_C = (TOPIC_A, TOPIC_B, TOPIC_C)
FILTER_MATCH_A_C_B = (TOPIC_A, TOPIC_C, TOPIC_B)


@pytest.mark.parametrize(
    'log_topics,filter_topics,expected',
    (
        # match all values
        (TOPICS_EMPTY, FILTER_MATCH_ALL, True),
        (TOPICS_ONLY_A, FILTER_MATCH_ALL, True),
        (TOPICS_ONLY_B, FILTER_MATCH_ALL, True),
        (TOPICS_ONLY_C, FILTER_MATCH_ALL, True),
        (TOPICS_A_A, FILTER_MATCH_ALL, True),
        (TOPICS_A_B, FILTER_MATCH_ALL, True),
        (TOPICS_A_C, FILTER_MATCH_ALL, True),
        (TOPICS_B_C, FILTER_MATCH_ALL, True),
        (TOPICS_B_A, FILTER_MATCH_ALL, True),
        (TOPICS_A_B_C, FILTER_MATCH_ALL, True),
        (TOPICS_A_C_B, FILTER_MATCH_ALL, True),
        (TOPICS_B_A_C, FILTER_MATCH_ALL, True),
        (TOPICS_B_C_A, FILTER_MATCH_ALL, True),
        # length 1 matches
        (TOPICS_EMPTY, FILTER_MATCH_ANY_ONE, False),
        (TOPICS_ONLY_A, FILTER_MATCH_ANY_ONE, True),
        (TOPICS_ONLY_B, FILTER_MATCH_ANY_ONE, True),
        (TOPICS_ONLY_C, FILTER_MATCH_ANY_ONE, True),
        (TOPICS_EMPTY, FILTER_MATCH_ONLY_A, False),
        (TOPICS_EMPTY, FILTER_MATCH_ONLY_B, False),
        (TOPICS_EMPTY, FILTER_MATCH_ONLY_C, False),
        (TOPICS_ONLY_A, FILTER_MATCH_ONLY_A, True),
        (TOPICS_ONLY_B, FILTER_MATCH_ONLY_B, True),
        (TOPICS_ONLY_C, FILTER_MATCH_ONLY_C, True),
        (TOPICS_ONLY_B, FILTER_MATCH_ONLY_A, False),
        (TOPICS_ONLY_C, FILTER_MATCH_ONLY_A, False),
        (TOPICS_ONLY_A, FILTER_MATCH_ONLY_B, False),
        (TOPICS_ONLY_C, FILTER_MATCH_ONLY_B, False),
        (TOPICS_ONLY_A, FILTER_MATCH_ONLY_C, False),
        (TOPICS_ONLY_B, FILTER_MATCH_ONLY_C, False),
        (TOPICS_A_A, FILTER_MATCH_ONLY_A, False),
        (TOPICS_A_B, FILTER_MATCH_ONLY_A, False),
        (TOPICS_A_C, FILTER_MATCH_ONLY_A, False),
        (TOPICS_A_B_C, FILTER_MATCH_ONLY_A, False),
        (TOPICS_A_C_B, FILTER_MATCH_ONLY_A, False),
        # length 2 matches
        (TOPICS_EMPTY, FILTER_MATCH_ANY_TWO, False),
        (TOPICS_A_A, FILTER_MATCH_ANY_TWO, True),
        (TOPICS_A_B, FILTER_MATCH_ANY_TWO, True),
        (TOPICS_ONLY_A, FILTER_MATCH_ANY_TWO, False),
        (TOPICS_ONLY_B, FILTER_MATCH_ANY_TWO, False),
        (TOPICS_ONLY_C, FILTER_MATCH_ANY_TWO, False),
        (TOPICS_A_A, FILTER_MATCH_A_B, False),
        (TOPICS_A_B, FILTER_MATCH_A_B, True),
        (TOPICS_A_C, FILTER_MATCH_A_B, False),
        (TOPICS_A_C, FILTER_MATCH_B_C, False),
        (TOPICS_B_C, FILTER_MATCH_B_C, True),
        (TOPICS_A_A, FILTER_MATCH_A_ANY, True),
        (TOPICS_A_B, FILTER_MATCH_A_ANY, True),
        (TOPICS_A_C, FILTER_MATCH_A_ANY, True),
        (TOPICS_B_C, FILTER_MATCH_A_ANY, False),
        (TOPICS_A_B, FILTER_MATCH_B_ANY, False),
        (TOPICS_A_C, FILTER_MATCH_B_ANY, False),
        (TOPICS_B_C, FILTER_MATCH_B_ANY, True),
        (TOPICS_B_A, FILTER_MATCH_B_ANY, True),
        (TOPICS_A_A, FILTER_MATCH_ANY_A, True),
        (TOPICS_A_B, FILTER_MATCH_ANY_A, False),
        (TOPICS_B_A, FILTER_MATCH_ANY_A, True),
        (TOPICS_A_B, FILTER_MATCH_ANY_B, True),
        (TOPICS_A_B, FILTER_MATCH_ANY_C, False),
        # length 3 matches
        (TOPICS_EMPTY, FILTER_MATCH_ANY_THREE, False),
        (TOPICS_A_B_C, FILTER_MATCH_ANY_THREE, True),
        (TOPICS_A_C_B, FILTER_MATCH_ANY_THREE, True),
        (TOPICS_B_A_C, FILTER_MATCH_ANY_THREE, True),
        (TOPICS_B_C_A, FILTER_MATCH_ANY_THREE, True),
        (TOPICS_A_A, FILTER_MATCH_ANY_THREE, False),
        # nested matches
        (TOPICS_EMPTY, (FILTER_MATCH_ONLY_A, FILTER_MATCH_ONLY_B, FILTER_MATCH_ONLY_C), False),
        (TOPICS_ONLY_A, (FILTER_MATCH_ONLY_A, FILTER_MATCH_ONLY_B, FILTER_MATCH_ONLY_C), True),
        (TOPICS_ONLY_B, (FILTER_MATCH_ONLY_A, FILTER_MATCH_ONLY_B, FILTER_MATCH_ONLY_C), True),
        (TOPICS_ONLY_C, (FILTER_MATCH_ONLY_A, FILTER_MATCH_ONLY_B, FILTER_MATCH_ONLY_C), True),
        (TOPICS_A_B, (FILTER_MATCH_ONLY_A, FILTER_MATCH_ONLY_B, FILTER_MATCH_ONLY_C), False),
        (TOPICS_A_B, (FILTER_MATCH_ONLY_A, FILTER_MATCH_ONLY_B, FILTER_MATCH_ONLY_C), False),
        (TOPICS_A_C, (FILTER_MATCH_A_ANY, FILTER_MATCH_ANY_A), True),
        (TOPICS_B_A, (FILTER_MATCH_A_ANY, FILTER_MATCH_ANY_A), True),
        (TOPICS_B_C, (FILTER_MATCH_A_ANY, FILTER_MATCH_ANY_A), False),
    )
)
def test_check_if_topics_match(log_topics, filter_topics, expected):
    actual = check_if_topics_match(log_topics, filter_topics)
    assert actual is expected


ADDRESS_A = b'\x00' * 20
ADDRESS_B = b'\x00' * 19 + b'\x01'
ADDRESS_C = b'\x00' * 19 + b'\x02'
ADDRESS_D = b'\x00' * 19 + b'\x03'


@pytest.mark.parametrize(
    'address,addresses,expected',
    (
        (ADDRESS_A, None, True),
        (ADDRESS_B, None, True),
        (ADDRESS_C, None, True),
        (ADDRESS_D, None, True),
        (ADDRESS_A, ADDRESS_A, True),
        (ADDRESS_B, ADDRESS_A, False),
        (ADDRESS_C, ADDRESS_A, False),
        (ADDRESS_D, ADDRESS_A, False),
        (ADDRESS_A, (ADDRESS_A,), True),
        (ADDRESS_B, (ADDRESS_A,), False),
        (ADDRESS_C, (ADDRESS_A,), False),
        (ADDRESS_D, (ADDRESS_A,), False),
        (ADDRESS_A, (ADDRESS_A, ADDRESS_B), True),
        (ADDRESS_B, (ADDRESS_A, ADDRESS_B), True),
        (ADDRESS_C, (ADDRESS_A, ADDRESS_B), False),
        (ADDRESS_D, (ADDRESS_A, ADDRESS_B), False),
        (ADDRESS_A, (ADDRESS_B, ADDRESS_A), True),
        (ADDRESS_B, (ADDRESS_B, ADDRESS_A), True),
        (ADDRESS_C, (ADDRESS_B, ADDRESS_A), False),
        (ADDRESS_D, (ADDRESS_B, ADDRESS_A), False),
    ),
)
def test_check_if_address_match(address, addresses, expected):
    actual = check_if_address_match(address, addresses)
    assert actual is expected


def _make_log(block_number=10, topics=None, address=ADDRESS_A, _type='mined', **kwargs):
    return dict(
        block_number=block_number,
        topics=topics or [],
        address=address,
        type=_type,
        **kwargs
    )


def _make_filter(from_block=None, to_block=None, topics=None, addresses=None):
    return {
        'from_block': from_block,
        'to_block': to_block,
        'topics': topics,
        'addresses': addresses,
    }


@pytest.mark.parametrize(
    'log_entry,filter_params,expected',
    (
        (_make_log(), _make_filter(), True),
    ),
)
def test_check_if_log_matches(log_entry, filter_params, expected):
    actual = check_if_log_matches(log_entry, **filter_params)
    assert actual == expected
