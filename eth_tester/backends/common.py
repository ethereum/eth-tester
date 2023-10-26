from eth_utils.toolz import (
    merge,
)


def merge_genesis_overrides(defaults, overrides):
    allowed_fields = set(defaults.keys())
    override_fields = set(overrides.keys())
    unexpected_fields = tuple(sorted(override_fields.difference(allowed_fields)))

    if unexpected_fields:
        err = (
            "The following invalid fields were supplied to "
            f"override default genesis values: {unexpected_fields}."
        )
        raise ValueError(err)

    merged_params = merge(defaults, overrides)
    return merged_params
