"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""


def generate_string(stringLength=10, character='0'):
    """Generate a string with line breaks.

    Parameters
    ----------
    stringLength : int, optional
        Number of characters to add in the string. Default `10`
    character : str, optional
        Character to be added. Default `'0'`

    Returns
    -------
    random_str : str
        String with line breaks.
    """
    generated_string = ''

    for i in range(stringLength):
        generated_string += character

        if i % 127 == 0:
            generated_string += '\n'

    return generated_string
