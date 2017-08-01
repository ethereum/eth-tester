class BaseNormalizationBackend(object):
    def normalize_address(self, value):
        raise NotImplementedError("must be implemented by subclasses")
