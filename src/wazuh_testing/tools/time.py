# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

def parse_date_time_format(date_time):
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