from typing import (
    Any,
    Dict,
)


def snake_case_to_lower_camel_case(snake_case_string: str) -> str:
    return "".join(
        word.capitalize() if i > 0 else word
        for i, word in enumerate(snake_case_string.split("_"))
    )


def lower_camel_case_to_snake_case(lower_camel_case_string: str) -> str:
    return "".join(
        f"_{char.lower()}" if char.isupper() else char
        for char in lower_camel_case_string
    )


def dict_keys_to_lower_camel_case(d: Dict[str, Any]) -> Dict[str, Any]:
    serialized = {}
    for key in d:
        serialized[snake_case_to_lower_camel_case(key)] = d[key]

    return serialized
