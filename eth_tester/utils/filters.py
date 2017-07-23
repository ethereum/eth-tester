import functools
from queue import (
    Queue,
    Empty,
)

from eth_utils import (
    to_tuple,
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


def is_empty_array(value):
    return is_array(value) and not value


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


# TODO: update the rest of these helpers.

def check_if_topics_match(filter_topics, log_topics):
    if is_empty_array(filter_topics):
        return True
    elif is_topic_array(filter_topics):
        if len(filter_topics) > len(log_topics):
            return False
        return all(
            check_topic_match(filter_topic, log_topic)
            for filter_topic, log_topic
            in zip(filter_topics, log_topics)
        )
    elif is_nested_topic_array(filter_topics):
        return any(
            check_if_topics_match(sub_topics, log_topics)
            for sub_topics in filter_topics
        )
    else:
        raise ValueError("Invalid filter topics format")


@coerce_args_to_bytes
def check_if_log_matches(log_entry, from_block, to_block,
                         addresses, filter_topics):
    log_block_number = int(log_entry['blockNumber'], 16)

    #
    # validate `from_block` (left bound)
    #
    if from_block is None or is_string(from_block):
        pass
    elif is_numeric(from_block):
        if from_block > log_block_number:
            return False
    else:
        raise TypeError("Invalid `from_block`")

    #
    # validate `to_block` (left bound)
    #
    if to_block is None or is_string(to_block):
        pass
    elif is_numeric(to_block):
        if to_block < log_block_number:
            return False
    else:
        raise TypeError("Invalid `to_block`")

    if log_entry['type'] == "pending":
        if to_block != "pending":
            return False
    elif from_block == "pending":
        return False

    #
    # validate `addresses`
    #
    if addresses and log_entry['address'] not in addresses:
        return False

    #
    # validate `topics`
    if not check_if_topics_match(filter_topics, log_entry['topics']):
        return False

    return True


def process_block(block, from_block, to_block, addresses, filter_topics):
    is_filter_match_fn = functools.partial(
        check_if_log_matches,
        from_block=from_block,
        to_block=to_block,
        addresses=addresses,
        filter_topics=filter_topics,
    )

    # TODO: this is really inneficient since many of the early exit conditions
    # can be identified prior to serializing the log entry.  Revamp this so
    # that the functionality in `check_if_log_matches` is more granular and
    # each piece can be checked at the earliers entry point.

    for txn_index, txn in enumerate(block.transaction_list):
        txn_receipt = block.get_receipt(txn_index)
        for log_index, log in enumerate(txn_receipt.logs):
            log_entry = serialize_log(block, txn, txn_index, log, log_index)
            if is_filter_match_fn(log_entry):
                yield log_entry


def get_filter_bounds(from_block, to_block, bookmark=None):
    if bookmark is not None:
        left_bound = bookmark
    elif from_block is None:
        left_bound = None
    elif from_block == "latest":
        left_bound = -1
    elif from_block == "earliest":
        left_bound = None
    elif from_block == "pending":
        left_bound = None
    else:
        left_bound = from_block

    if to_block is None:
        right_bound = None
    elif to_block == "latest":
        right_bound = None
    elif to_block == "earliest":
        right_bound = 1
    elif to_block == "pending":
        right_bound = None
    else:
        right_bound = to_block + 1

    return slice(left_bound, right_bound)
