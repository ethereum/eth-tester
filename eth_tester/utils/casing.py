def snake_case_to_lower_camel_case(snake_case_string: str) -> str:
    return "".join(
        word.capitalize() if i > 0 else word
        for i, word in enumerate(snake_case_string.split("_"))
    )
