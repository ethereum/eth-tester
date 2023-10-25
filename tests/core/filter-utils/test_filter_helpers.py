from __future__ import (
    unicode_literals,
)

from eth_utils import (
    big_endian_to_int,
    is_list_like,
)
import pytest

from eth_tester.utils.filters import (
    check_if_address_match,
    check_if_from_block_match,
    check_if_log_matches,
    check_if_to_block_match,
    check_if_topics_match,
    check_single_topic_match,
    extrapolate_flat_topic_from_topic_list,
    is_flat_topic_array,
    is_topic,
    is_topic_array,
    is_valid_with_nested_topic_array,
)

TOPIC_A = b"\x00" * 32
TOPIC_B = b"\x00" * 31 + b"\x01"
TOPIC_C = b"\x00" * 31 + b"\x02"


def topic_to_name(param):
    if is_list_like(param):
        return [topic_to_name(t) for t in param]
    if isinstance(param, bytes):
        topic_int = big_endian_to_int(param)
        return chr(topic_int + 65)
    else:
        return param


def topic_id(param):
    return repr(topic_to_name(param))


@pytest.mark.parametrize(
    "value,expected",
    (
        # bad values
        ("", False),
        ("a", False),
        (1, False),
        (True, False),
        ({"a": 1, "b": 2}, False),
        (tuple(), False),
        (list(), False),
        (("a", "b"), False),
        (["a", "b"], False),
        (b"", False),
        (b"arst", False),
        # good values
        (None, True),
        (TOPIC_A, True),
        (TOPIC_B, True),
    ),
)
def test_is_topic(value, expected):
    actual = is_topic(value)
    assert actual is expected


TOPICS_EMPTY = tuple()
TOPICS_SINGLE_NULL = (None,)
TOPICS_MANY = (TOPIC_A, TOPIC_B)
TOPICS_MANY_WITH_NULL = (TOPIC_A, None, TOPIC_B)


@pytest.mark.parametrize(
    "value,expected",
    (
        # bad values
        ("", False),
        ("a", False),
        (1, False),
        (True, False),
        ({"a": 1, "b": 2}, False),
        (None, False),
        (b"", False),
        (b"arst", False),
        (("a", "b"), False),
        (["a", "b"], False),
        ([b"a", b"b"], False),
        ([b"a", None, b"b"], False),
        (list(), False),
        ([None], False),
        ((None, b"a"), False),
        ((TOPIC_A, b"a"), False),
        ((b"a", None), False),
        ((b"a", TOPIC_A), False),
        ((TOPIC_A, b"a", TOPIC_B), False),
        # good values
        (TOPICS_EMPTY, True),
        (TOPICS_SINGLE_NULL, True),
        (TOPICS_MANY, True),
        (TOPICS_MANY_WITH_NULL, True),
    ),
)
def test_is_valid_topic_array_with_flat_topic_arrays(value, expected):
    actual = is_flat_topic_array(value)
    assert actual is expected


NESTED_TOPICS_A = (TOPICS_EMPTY,)
NESTED_TOPICS_B = (TOPICS_EMPTY, TOPICS_SINGLE_NULL)
NESTED_TOPICS_C = (TOPICS_SINGLE_NULL, TOPICS_MANY)
NESTED_TOPICS_D = (TOPICS_MANY_WITH_NULL, TOPICS_MANY, TOPICS_EMPTY)
NESTED_TOPICS_E = (TOPIC_A, TOPICS_MANY, TOPICS_EMPTY)


@pytest.mark.parametrize(
    "value,expected",
    (
        # bad values
        ("", False),
        ("a", False),
        (1, False),
        (True, False),
        ({"a": 1, "b": 2}, False),
        (None, False),
        (b"", False),
        (b"arst", False),
        (("a", "b"), False),
        (["a", "b"], False),
        ([b"a", b"b"], False),
        ([b"a", None, b"b"], False),
        (list(), False),
        ([None], False),
        (([],), False),
        (([tuple()],), False),
        ([tuple()], False),
        ((tuple(), []), False),
        ((TOPICS_EMPTY, (b"arst",)), False),
        (TOPIC_A, False),
        (TOPICS_EMPTY, False),
        # good values
        (TOPICS_SINGLE_NULL, True),
        (TOPICS_MANY, True),
        (TOPICS_MANY_WITH_NULL, True),
        (NESTED_TOPICS_A, True),
        (NESTED_TOPICS_B, True),
        (NESTED_TOPICS_C, True),
        (NESTED_TOPICS_D, True),
        (NESTED_TOPICS_E, True),
    ),
)
def test_is_valid_with_nested_topic_array(value, expected):
    actual = is_valid_with_nested_topic_array(value)
    assert actual is expected


@pytest.mark.parametrize(
    "value,expected",
    (
        # bad values
        ("", False),
        ("a", False),
        (1, False),
        (True, False),
        ({"a": 1, "b": 2}, False),
        (None, False),
        (b"", False),
        (b"arst", False),
        (("a", "b"), False),
        (["a", "b"], False),
        ([b"a", b"b"], False),
        ([b"a", None, b"b"], False),
        (list(), False),
        ([None], False),
        (([],), False),
        (([tuple()],), False),
        ([tuple()], False),
        ((tuple(), []), False),
        ((TOPICS_EMPTY, (b"arst",)), False),
        # good values
        (TOPICS_EMPTY, True),
        (TOPICS_SINGLE_NULL, True),
        (TOPICS_MANY, True),
        (TOPICS_MANY_WITH_NULL, True),
        (NESTED_TOPICS_A, True),
        (NESTED_TOPICS_B, True),
        (NESTED_TOPICS_C, True),
        (NESTED_TOPICS_D, True),
    ),
)
def test_is_topic_array(value, expected):
    actual = is_topic_array(value)
    assert actual is expected


TOPIC_A_AS_TEXT = "\x00" * 32
TOPIC_B_AS_TEXT = "\x00" * 31 + "\x01"


@pytest.mark.parametrize(
    "value,topic,expected",
    (
        # bad values
        ("mismatch", TOPIC_A, False),
        (TOPIC_A_AS_TEXT, TOPIC_A, False),
        (TOPIC_B, TOPIC_A, False),
        # good values
        (TOPIC_A, TOPIC_A, True),
        (TOPIC_B, TOPIC_B, True),
        (TOPIC_A, None, True),
        (TOPIC_B, None, True),
    ),
)
def test_check_single_topic_match(value, topic, expected):
    actual = check_single_topic_match(value, topic)
    assert actual is expected


@pytest.mark.parametrize(
    "block_number,_type,from_block,expected",
    (
        # bad values
        (10, "mined", 11, False),
        (10, "mined", "pending", False),
        (10, "mined", "earliest", False),
        # good values
        (10, "mined", None, True),
        (10, "mined", 10, True),
        (20, "mined", 10, True),
        (10, "mined", "latest", True),
        (10, "pending", "pending", True),
        (10, "pending", "earliest", True),
    ),
)
def test_check_if_from_block_match(block_number, _type, from_block, expected):
    actual = check_if_from_block_match(block_number, _type, from_block)
    assert actual is expected


@pytest.mark.parametrize(
    "block_number,_type,to_block,expected",
    (
        # bad values
        (11, "mined", 10, False),
        (10, "mined", "pending", False),
        (10, "mined", "earliest", False),
        # good values
        (10, "mined", None, True),
        (10, "mined", 10, True),
        (9, "mined", 10, True),
        (10, "mined", "latest", True),
        (10, "pending", "pending", True),
        (10, "pending", "earliest", True),
    ),
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
FILTER_MATCH_ONE_OR_MORE = (None,)
FILTER_MATCH_TWO_OR_MORE = (None, None)
FILTER_MATCH_THREE_OR_MORE = (None, None, None)
FILTER_MATCH_A = (TOPIC_A,)
FILTER_MATCH_B = (TOPIC_B,)
FILTER_MATCH_C = (TOPIC_C,)
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
    "log_topics,filter_topics,expected",
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
        (TOPICS_EMPTY, FILTER_MATCH_ONE_OR_MORE, False),
        (TOPICS_ONLY_A, FILTER_MATCH_ONE_OR_MORE, True),
        (TOPICS_ONLY_B, FILTER_MATCH_ONE_OR_MORE, True),
        (TOPICS_ONLY_C, FILTER_MATCH_ONE_OR_MORE, True),
        (TOPICS_EMPTY, FILTER_MATCH_A, False),
        (TOPICS_EMPTY, FILTER_MATCH_B, False),
        (TOPICS_EMPTY, FILTER_MATCH_C, False),
        (TOPICS_ONLY_A, FILTER_MATCH_A, True),
        (TOPICS_ONLY_B, FILTER_MATCH_B, True),
        (TOPICS_ONLY_C, FILTER_MATCH_C, True),
        (TOPICS_ONLY_B, FILTER_MATCH_A, False),
        (TOPICS_ONLY_C, FILTER_MATCH_A, False),
        (TOPICS_ONLY_A, FILTER_MATCH_B, False),
        (TOPICS_ONLY_C, FILTER_MATCH_B, False),
        (TOPICS_ONLY_A, FILTER_MATCH_C, False),
        (TOPICS_ONLY_B, FILTER_MATCH_C, False),
        (TOPICS_A_A, FILTER_MATCH_A, True),
        (TOPICS_A_B, FILTER_MATCH_A, True),
        (TOPICS_A_C, FILTER_MATCH_A, True),
        (TOPICS_A_B_C, FILTER_MATCH_A, True),
        (TOPICS_A_C_B, FILTER_MATCH_A, True),
        (TOPICS_B_A, FILTER_MATCH_A, False),
        (TOPICS_B_C, FILTER_MATCH_A, False),
        (TOPICS_B_A_C, FILTER_MATCH_A, False),
        (TOPICS_B_C_A, FILTER_MATCH_A, False),
        # length 2 matches
        (TOPICS_EMPTY, FILTER_MATCH_TWO_OR_MORE, False),
        (TOPICS_A_A, FILTER_MATCH_TWO_OR_MORE, True),
        (TOPICS_A_B, FILTER_MATCH_TWO_OR_MORE, True),
        (TOPICS_ONLY_A, FILTER_MATCH_TWO_OR_MORE, False),
        (TOPICS_ONLY_B, FILTER_MATCH_TWO_OR_MORE, False),
        (TOPICS_ONLY_C, FILTER_MATCH_TWO_OR_MORE, False),
        (TOPICS_A_A, FILTER_MATCH_A_B, False),
        (TOPICS_A_B, FILTER_MATCH_A_B, True),
        (TOPICS_A_B_C, FILTER_MATCH_A_B, True),
        (TOPICS_A_C, FILTER_MATCH_A_B, False),
        (TOPICS_A_C, FILTER_MATCH_B_C, False),
        (TOPICS_B_C, FILTER_MATCH_B_C, True),
        (TOPICS_B_C_A, FILTER_MATCH_B_C, True),
        (TOPICS_A_A, FILTER_MATCH_A_ANY, True),
        (TOPICS_A_B, FILTER_MATCH_A_ANY, True),
        (TOPICS_A_C, FILTER_MATCH_A_ANY, True),
        (TOPICS_A_B_C, FILTER_MATCH_A_ANY, True),
        (TOPICS_A_C_B, FILTER_MATCH_A_ANY, True),
        (TOPICS_B_C, FILTER_MATCH_A_ANY, False),
        (TOPICS_A_B, FILTER_MATCH_B_ANY, False),
        (TOPICS_A_C, FILTER_MATCH_B_ANY, False),
        (TOPICS_B_C, FILTER_MATCH_B_ANY, True),
        (TOPICS_B_C_A, FILTER_MATCH_B_ANY, True),
        (TOPICS_B_A, FILTER_MATCH_B_ANY, True),
        (TOPICS_B_A_C, FILTER_MATCH_B_ANY, True),
        (TOPICS_A_A, FILTER_MATCH_ANY_A, True),
        (TOPICS_A_B, FILTER_MATCH_ANY_A, False),
        (TOPICS_B_A, FILTER_MATCH_ANY_A, True),
        (TOPICS_B_A_C, FILTER_MATCH_ANY_A, True),
        (TOPICS_A_B, FILTER_MATCH_ANY_B, True),
        (TOPICS_A_B_C, FILTER_MATCH_ANY_B, True),
        (TOPICS_A_B, FILTER_MATCH_ANY_C, False),
        (TOPICS_A_B_C, FILTER_MATCH_ANY_C, False),
        # length 3 matches
        (TOPICS_EMPTY, FILTER_MATCH_THREE_OR_MORE, False),
        (TOPICS_A_B_C, FILTER_MATCH_THREE_OR_MORE, True),
        (TOPICS_A_C_B, FILTER_MATCH_THREE_OR_MORE, True),
        (TOPICS_B_A_C, FILTER_MATCH_THREE_OR_MORE, True),
        (TOPICS_B_C_A, FILTER_MATCH_THREE_OR_MORE, True),
        (TOPICS_A_A, FILTER_MATCH_THREE_OR_MORE, False),
        (TOPICS_A_B_C, FILTER_MATCH_A_B_C, True),
        (TOPICS_A_C_B, FILTER_MATCH_A_B_C, False),
        (TOPICS_A_C_B, FILTER_MATCH_A_C_B, True),
        (TOPICS_A_B_C, FILTER_MATCH_A_C_B, False),
        # positional topic options matches
        (TOPICS_EMPTY, (FILTER_MATCH_A, FILTER_MATCH_B, FILTER_MATCH_C), False),
        (TOPICS_ONLY_A, (FILTER_MATCH_A, FILTER_MATCH_B, FILTER_MATCH_C), False),
        (TOPICS_ONLY_B, (FILTER_MATCH_A, FILTER_MATCH_B, FILTER_MATCH_C), False),
        (TOPICS_ONLY_C, (FILTER_MATCH_A, FILTER_MATCH_B, FILTER_MATCH_C), False),
        (TOPICS_A_B, (FILTER_MATCH_B, FILTER_MATCH_C), False),
        (TOPICS_A_B, (FILTER_MATCH_B, FILTER_MATCH_C, FILTER_MATCH_A), False),
        (TOPICS_A_C, (FILTER_MATCH_A_ANY, FILTER_MATCH_ANY_A), True),
        (TOPICS_B_A, (FILTER_MATCH_A_ANY, FILTER_MATCH_ANY_A), True),
        (TOPICS_B_C, (FILTER_MATCH_A_ANY, FILTER_MATCH_ANY_A), True),
        (TOPICS_A_B_C, (FILTER_MATCH_A, FILTER_MATCH_A_B_C, FILTER_MATCH_C), True),
        (TOPICS_A_B_C, (FILTER_MATCH_A, FILTER_MATCH_A_C_B, FILTER_MATCH_C), True),
        (TOPICS_A_B_C, (FILTER_MATCH_A, FILTER_MATCH_A_C_B, TOPIC_C), True),
    ),
    ids=topic_id,
)
def test_check_if_topics_match(log_topics, filter_topics, expected):
    actual = check_if_topics_match(log_topics, filter_topics)
    assert actual is expected


ADDRESS_A = b"\x00" * 20
ADDRESS_B = b"\x00" * 19 + b"\x01"
ADDRESS_C = b"\x00" * 19 + b"\x02"
ADDRESS_D = b"\x00" * 19 + b"\x03"


@pytest.mark.parametrize(
    "address,addresses,expected",
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


def _make_log(block_number=10, topics=None, address=ADDRESS_A, _type="mined", **kwargs):
    return dict(
        block_number=block_number,
        topics=topics or tuple(),
        address=address,
        type=_type,
        **kwargs
    )


def _make_filter(from_block=None, to_block=None, topics=None, addresses=None):
    return {
        "from_block": from_block,
        "to_block": to_block,
        "topics": topics,
        "addresses": addresses,
    }


@pytest.mark.parametrize(
    "log_entry,filter_params,expected",
    (
        # block numbers
        (_make_log(), _make_filter(), True),
        (_make_log(block_number=10), _make_filter(from_block=11), False),
        (_make_log(block_number=30), _make_filter(from_block=10), True),
        (_make_log(block_number=30), _make_filter(from_block=10, to_block=20), False),
        (_make_log(block_number=30), _make_filter(to_block=20), False),
        (_make_log(block_number=20), _make_filter(to_block=20), True),
        # topics
        (_make_log(topics=(TOPIC_A,)), _make_filter(topics=FILTER_MATCH_ALL), True),
        (
            _make_log(topics=(TOPIC_A, TOPIC_B)),
            _make_filter(topics=FILTER_MATCH_ALL),
            True,
        ),
        (_make_log(topics=(TOPIC_A,)), _make_filter(topics=FILTER_MATCH_A), True),
        (_make_log(topics=(TOPIC_B,)), _make_filter(topics=FILTER_MATCH_A), False),
        (
            _make_log(topics=(TOPIC_A, TOPIC_A)),
            _make_filter(topics=FILTER_MATCH_A_ANY),
            True,
        ),
        (
            _make_log(topics=(TOPIC_A, TOPIC_B)),
            _make_filter(topics=FILTER_MATCH_A_ANY),
            True,
        ),
        (
            _make_log(topics=(TOPIC_B, TOPIC_A)),
            _make_filter(topics=FILTER_MATCH_A_ANY),
            False,
        ),
        (_make_log(topics=TOPICS_A_B), _make_filter(topics=FILTER_MATCH_A_ANY), True),
        (_make_log(topics=TOPICS_B_A), _make_filter(topics=FILTER_MATCH_A_ANY), False),
        (
            _make_log(topics=TOPICS_A_B),
            _make_filter(topics=(FILTER_MATCH_A_B, FILTER_MATCH_B_C)),
            True,
        ),
        (
            _make_log(topics=TOPICS_B_A),
            _make_filter(topics=(FILTER_MATCH_A_B, FILTER_MATCH_B_C)),
            False,
        ),
        (
            _make_log(topics=TOPICS_B_C),
            _make_filter(topics=(FILTER_MATCH_A_B, FILTER_MATCH_B_C)),
            True,
        ),
    ),
)
def test_check_if_log_matches(log_entry, filter_params, expected):
    actual = check_if_log_matches(log_entry, **filter_params)
    assert actual == expected


@pytest.mark.parametrize(
    "topic_list_input,expected_flat_topics",
    (
        (
            ("A", ("A", "B"), "A"),
            (("A", "A", "A"), ("A", "B", "A")),
        ),
        (
            ("A", ("A", "B", "C"), ("A", "B")),
            (
                ("A", "A", "A"),
                ("A", "A", "B"),
                ("A", "B", "A"),
                ("A", "B", "B"),
                ("A", "C", "A"),
                ("A", "C", "B"),
            ),
        ),
    ),
)
def test_extrapolate_flat_topic_from_topic_list(topic_list_input, expected_flat_topics):
    assert (
        tuple(extrapolate_flat_topic_from_topic_list(topic_list_input))
        == expected_flat_topics
    )
