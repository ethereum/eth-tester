from queue import (
    Queue,
    Empty,
)

from eth_utils import (
    to_tuple,
    is_string,
    is_address,
    is_same_address,
    is_integer,
)


class Filter(object):
    values = None
    queue = None

    def __init__(self):
        self.values = []
        self.queue = Queue()

    @to_tuple
    def get_changes(self):
        while True:
            try:
                yield self.queue.get_nowait()
            except Empty:
                break

    def get_all(self):
        return tuple(self.values)

    def add(self, *values):
        for item in values:
            self.values.append(item)
            self.queue.put_nowait(item)


def is_array(value):
    return isinstance(value, (list, tuple))


def is_string_or_none(value):
    return is_string(value) or value is None


def is_flat_topic_array(value):
    return is_array(value) and all(is_string_or_none(item) for item in value)


def is_nested_topic_array(value):
    return is_array(value) and all((is_topic_array(item) for item in value))


def is_topic_array(value):
    return is_flat_topic_array(value) or is_nested_topic_array(value)


def check_topic_match(filter_topic, log_topic):
    if filter_topic is None:
        return True
    return filter_topic == log_topic


def check_if_log_matches_from_block(log_entry, from_block):
    if from_block is None:
        return True
    elif from_block == "latest":
        return True
    elif from_block in {"earliest", "pending"} and log_entry["type"] == "pending":
        return True
    elif is_integer(from_block) and log_entry["block_number"] >= from_block:
        return True
    else:
        return False


def check_if_log_matches_to_block(log_entry, to_block):
    if to_block is None:
        return True
    elif to_block == "latest":
        return True
    elif to_block in {"earliest", "pending"} and log_entry["type"] == "pending":
        return True
    elif is_integer(to_block) and log_entry["block_number"] <= to_block:
        return True
    else:
        return False


def check_if_log_matches_flat_topics(log_topics, filter_topics):
    if len(log_topics) != len(filter_topics):
        return False
    return all(
        check_topic_match(left, right)
        for left, right
        in zip(log_topics, filter_topics)
    )


def check_if_log_matches_topics(log_entry, filter_topics):
    if is_flat_topic_array(filter_topics):
        return check_if_log_matches_flat_topics(log_entry['topics'], filter_topics)
    elif is_nested_topic_array(filter_topics):
        return any(
            check_if_log_matches_flat_topics(log_entry['topics'], sub_filter_topics)
            for sub_filter_topics
            in filter_topics
        )
    else:
        raise ValueError("Unrecognized topics format: {0}".format(filter_topics))


def check_if_log_matches_addresses(log_entry, addresses):
    if is_array(addresses):
        return any(
            is_same_address(log_entry['address'], item)
            for item
            in addresses
        )
    elif is_address(addresses):
        return is_same_address(addresses, log_entry['address'])
    else:
        raise ValueError("Unrecognized address format: {0}".format(addresses))


def check_if_log_matches(log_entry,
                         from_block,
                         to_block,
                         addresses,
                         topics):
    return all((
        check_if_log_matches_from_block(log_entry, from_block),
        check_if_log_matches_to_block(log_entry, to_block),
        check_if_log_matches_addresses(log_entry, addresses),
        check_if_log_matches_topics(log_entry, topics),
    ))
