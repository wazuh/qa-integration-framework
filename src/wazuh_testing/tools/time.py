# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

def parse_date_time_format(date_time: str):
    """Parse the specified date_time to return a common format.

    Args:
        date_time (str): Date time to parse.

    Returns:
        str: Date time in format '%Y-%m-%d %H:%M:%S'

    Raises:
        ValueError: If could not parse the specified date_time
    """
    regex_list = [
        {'regex': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})Z', 'append': ':00'},  # CPE format
        {'regex': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})', 'append': ''},  # RHEL Canonical, ALAS, MSU, Debian, NVD
        {'regex': r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})', 'append': ''}  # Arch
    ]

    for item in regex_list:
        match = re.compile(item['regex']).match(date_time)

        if match:
            return f"{match.group(1)} {match.group(2)}{item['append']}"

    ValueError(f"Could not parse the {date_time} datetime.")


def time_to_seconds(time_value: str) -> int:
    """Convert a string with format (1s, 1m, 1h, 1d, 1w) in number of seconds.

    Args:
        time_value (str): String (1s, 1m, 1h, 1d, 1w).

    Returns:
        time_value (int): Number of seconds.
    """
    time_unit = time_value[len(time_value) - 1:]

    time_value = int(time_value[:len(time_value) - 1])

    units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}

    return time_value * units[time_unit]