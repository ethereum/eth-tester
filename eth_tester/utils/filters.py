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
        for value in values:
            self.values.append(value)
            self.queue.put_nowait(value)
