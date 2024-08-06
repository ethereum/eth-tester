def eels_is_available():
    try:
        import ethereum  # noqa: F401

        return True
    except ImportError:
        return False


class EELSStateContext:
    def __init__(self, chain, transactions_map, receipts_map):
        self.chain = chain
        self.transactions_map = transactions_map
        self.receipts_map = receipts_map
