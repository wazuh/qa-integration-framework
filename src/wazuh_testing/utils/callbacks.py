# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re

from typing import Callable, Tuple, Union


def generate_callback(regex: str, keyword: str = None) -> Callable[[str], Union[Tuple[str], None]]:
    """
    Returns a callback function that searches for a specified pattern in a given string.

    The returned function takes a single argument, `line`, which should be a string.
    It searches for the pattern specified by the `regex` argument in `line`.
    If the pattern is found, it will return a tuple containing the whole line that
    matched the pattern.
    If the pattern is not found, the function returns `None`.

    Args:
        regex (str): A string representing the regular expression pattern to search for.

    Returns:
        function: Callback function that takes the line and return the matched substring
                  if found, or `None` otherwise.
    """
    def new_callback(line: str) -> Union[Tuple[str], None]:
        """
        Callback function that looks for the specified regular expression pattern in a string.

        Args:
            line (str): The string to search for a match.

        Returns:
            tuple[str] | None: A tuple containing the matched substring if found, otherwise `None`.
        """
        # Match the received line.
        if keyword is None or keyword in line:
            match = re.match(regex, line)
            # Return the matched string.
            return match.groups() if match else None
        else:
            return None

    return new_callback
