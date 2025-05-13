INVALID_INTEGER_VALUE = "Value must be a positive integer.  Got: {}"
INVALID_HASH_LENGTH = "Must be of length 32.  Got: {} of length {}"
INVALID_BYTE_STRING = "Value must be a byte string.  Got type: <class '{}'>"
INVALID_KEYS = "The following keys failed to validate\n- {}: {}"
INVALID_ITEMS = "The following items failed to validate\n- {}: {}"

INVALID_TRANSACTION_MISSING_KEYS = "Transaction is missing the required keys: '{}'"
INVALID_TRANSACTION_BLOB_PARAMS = "Transaction contains blob-specific parameters. Blob transactions are only supported via `eth_sendRawTransaction`, rlp encoding the blob sidecar data along with the transaction as per the EIP-4844 `PooledTransaction` model."  # noqa: E501
INVALID_TRANSACTION_EXTRA_KEYS = "Only the keys '{}' are allowed.  Got extra keys: '{}'"
INVALID_ADDRESS_PARAM = "Address must be 20 bytes encoded as hexadecimal - address: {}"
INVALID_TRANSACTION_DATA_PARAM = (
    "Transaction 'data' must be a hexadecimal encoded string.  Got: {}"
)
INVALID_BLOCK_NUMBER = "Block number must be a positive integer or one of the strings 'latest', 'earliest', or 'pending'.  Got: {}"  # noqa: E501
INVALID_BLOCK_NUMBER_VALUE_TYPE = (
    "Value must be a text string.  Got type: <class 'bytes'>"
)
