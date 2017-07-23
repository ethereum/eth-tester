from __future__ import unicode_literals

import pytest

from eth_tester.utils.filters import (
    check_if_topic_match,
    check_if_log_matches_from_block,
    check_if_log_matches_to_block,
    check_if_log_matches_topics,
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
        (None, TOPIC_A, True),
        (None, TOPIC_B, True),
    )
)
def test_check_topic_match(value, topic, expected):
    actual = check_if_topic_match(value, topic)
    assert actual is expected


def _make_log(block_number, _type='mined', topics=None, **kwargs):
    if topics is None:
        topics = []
    return dict(
        block_number=block_number,
        type=_type,
        topics=topics,
        **kwargs
    )


@pytest.mark.parametrize(
    'log_entry,from_block,expected',
    (
        # bad values
        (_make_log(10), 11, False),
        (_make_log(10), 'pending', False),
        (_make_log(10), 'earliest', False),
        # good values
        (_make_log(10), None, True),
        (_make_log(10), 10, True),
        (_make_log(20), 10, True),
        (_make_log(10), 'latest', True),
        (_make_log(10, _type='pending'), 'pending', True),
        (_make_log(10, _type='pending'), 'earliest', True),
    )
)
def test_check_if_log_matches_from_block(log_entry, from_block, expected):
    actual = check_if_log_matches_from_block(log_entry, from_block)
    assert actual is expected


@pytest.mark.parametrize(
    'log_entry,to_block,expected',
    (
        # bad values
        (_make_log(11), 10, False),
        (_make_log(10), 'pending', False),
        (_make_log(10), 'earliest', False),
        # good values
        (_make_log(10), None, True),
        (_make_log(10), 10, True),
        (_make_log(9), 10, True),
        (_make_log(10), 'latest', True),
        (_make_log(10, _type='pending'), 'pending', True),
        (_make_log(10, _type='pending'), 'earliest', True),
    )
)
def test_check_if_log_matches_to_block(log_entry, to_block, expected):
    actual = check_if_log_matches_to_block(log_entry, to_block)
    assert actual is expected


TOPICS_ONLY_A = (TOPIC_A,)
TOPICS_ONLY_B = (TOPIC_B,)
TOPICS_ONLY_C = (TOPIC_C,)
TOPICS_A_B = (TOPIC_A, TOPIC_B)
TOPICS_A_C = (TOPIC_A, TOPIC_C)
TOPICS_A_B_C = (TOPIC_A, TOPIC_B, TOPIC_C)
TOPICS_A_C_B = (TOPIC_A, TOPIC_C, TOPIC_B)
TOPICS_B_A = (TOPIC_B, TOPIC_A)
TOPICS_B_C = (TOPIC_B, TOPIC_C)
TOPICS_B_A_C = (TOPIC_B, TOPIC_A, TOPIC_C)
TOPICS_B_C_A = (TOPIC_B, TOPIC_C, TOPIC_A)


FILTER_MATCH_ALL = tuple()
FILTER_MATCH_ONE_ANY = (None,)
FILTER_MATCH_TWO_ANY = (None, None)
FILTER_MATCH_THREE_ANY = (None, None, None)
FILTER_MATCH_ONLY_A = (TOPIC_A,)
FILTER_MATCH_ONLY_B = (TOPIC_B,)
FILTER_MATCH_ONLY_C = (TOPIC_C,)
FILTER_MATCH_A_B = (TOPIC_A, TOPIC_B)


@pytest.mark.parametrize(
    'log_entry,filter_topics,expected',
    (
        # bad values
        # good values
        (_make_log(10, topics=TOPICS_ONLY_A), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_ONLY_B), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_ONLY_C), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_A_B), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_A_C), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_B_C), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_B_A), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_A_B_C), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_A_C_B), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_B_A_C), FILTER_MATCH_ALL, True),
        (_make_log(10, topics=TOPICS_B_C_A), FILTER_MATCH_ALL, True),
    )
)
def test_check_if_log_matches_topics(log_entry, filter_topics, expected):
    actual = check_if_log_matches_topics(log_entry, filter_topics)
    assert actual is expected
