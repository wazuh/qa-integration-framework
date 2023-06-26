"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import re

from typing import Callable, Tuple, Union


def replace_values_in_dynamic_regex(regex: str, replacement: dict = None) -> str:
    """Replace custom values in a regex with "dynamic fields" ("dynamic regex").

    For instance:
        - A regex with a "dynamic field" look like this: `r'Regex with a dynamic field whose value is {x}'`
        - A replacement that will override the "dynamic field" with its value look like this: `{'x': 3}`

    The final result is: `r"Regex with a dynamic field whose value is 3"`

    Args:
        regex (str): A regex pattern with "dynamic fields" to be replaced by real values with `replacement`.
        replacement (dict): Field-value pair used to make a replacement in the "dynamic regex".

    Returns:
        regex (str): A regex pattern represented by a string.
    """
    if replacement is None:
        return regex

    for key in replacement:
        regex = regex.replace(f"{{{key}}}", replacement[key])

    return regex


def generate_callback(regex: str, replacement: dict = None) -> Callable:
    """Returns a callback function that searches for a regular expression in a given line.

    Args:
        regex (str): A string representing the regular expression pattern to search for.
        replacement (dict): Field-value pair used to make a replacement in the regex.

    Returns:
        new_callback (Callable): Searches for a match in a string given an specific regex.
    """
    regex = replace_values_in_dynamic_regex(regex, replacement)
    print("regex: ", regex)

    def new_callback(line: str) -> Union[Tuple[str], None]:
        """Callback function that looks for the specified regular expression pattern in a string.

        Args:
            line (str): The string to search for a match.

        Returns:
            tuple[str] | None: A tuple containing the matched substring if found, otherwise `None`.
        """
        # Match the received line.
        match = re.match(regex, line)
        if match:
            # Return the matched line or match groups.
            return line if len(match.groups()) == 0 else match.groups()

        return None

    return new_callback
