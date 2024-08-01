def is_eels_available():
    try:
        pass

        return True
    except ImportError:
        return False


class EELSStateContext:
    def __init__(self, chain, transactions_map, receipts_map):
        self.chain = chain
        self.transactions_map = transactions_map
        self.receipts_map = receipts_map
