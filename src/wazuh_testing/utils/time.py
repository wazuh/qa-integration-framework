
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re
import numbers
from datetime import datetime, timedelta


def reformat_time(scan_time):
    """
    Transform scan_time to readable time.

    Args:
        scan_time (str): Time string.

    Returns:
        datetime: Datetime object with the string translated.
    """
    hour_format = '%H'
    colon = ''
    locale = ''
    if ':' in scan_time:
        colon = ':%M'
    if re.search('[a-zA-Z]', scan_time):
        locale = '%p'
        hour_format = '%I'
    cd = datetime.now()
    return datetime.replace(datetime.strptime(scan_time, hour_format + colon + locale),
                            year=cd.year, month=cd.month, day=cd.day)


def time_to_timedelta(time_):
    """
    Convert a string with time in seconds with `smhdw` suffixes allowed to `datetime.timedelta`.

    Args:
        time_ (str): String with time in seconds.
    Returns:
        timedelta: Timedelta object.
    """
    time_unit = time_[len(time_) - 1:]

    if time_unit.isnumeric():
        return timedelta(seconds=int(time_))

    time_value = int(time_[:len(time_) - 1])

    if time_unit == "s":
        return timedelta(seconds=time_value)
    elif time_unit == "m":
        return timedelta(minutes=time_value)
    elif time_unit == "h":
        return timedelta(hours=time_value)
    elif time_unit == "d":
        return timedelta(days=time_value)
    elif time_unit == "w":
        return timedelta(weeks=time_value)


def time_to_human_readable(time_):
    """
    Convert a time string like 5s or 2d into a human-readable string such as 5 seconds or 2 days

    Args:

    time_ (str): String with the time and the measurement unit

    Returns:
        human_readable_time (str): String in the new format, for example: 5 seconds
    """

    time_unit = time_[-1]

    human_readable_string = {
        's': ' seconds',
        'm': ' minutes',
        'h': ' houres',
        'd': ' days'
    }

    human_readable_time = time_.replace(time_unit, human_readable_string[time_unit])

    return human_readable_time


def unit_to_seconds(time_):
    """
    Convert a time string like 9m or 2d into another similar string in seconds

    Args:
        time_ (str): String with the time and the measurement unit

    Returns:
        seconds_time: String in the same format with units converted to seconds
    """

    seconds_equivalent = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400
    }

    time_unit = time_[-1]
    time_value = time_[:-1]

    new_value = int(time_value) * seconds_equivalent[time_unit]

    seconds_time = f'{new_value}s'

    return seconds_time


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


def get_current_timestamp() -> int:
    """Get the current timestamp. For example: 1627028708.303002
    Returns:
        int: current timestamp.
    """
    return datetime.now().timestamp()


def interval_to_time_modifier(interval):
    """Convert a string with format (1s, 1m, 1h, 1d) to SQLite date modifier.

    Args:
        interval (str): Time interval string.

    Returns:
          str: SQLite date modifier.
    """
    interval_units_dict = {'s': 'seconds', 'm': 'minutes', 'h': 'hours', 'd': 'days'}
    time_value = interval[:-1]
    time_unit = interval[-1]
    return f"{time_value} {interval_units_dict[time_unit]}"


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


def validate_interval_format(interval):
    """Validate that the interval passed has the format in which the last digit is a letter from those passed and
       the other characters are between 0-9."""
    if interval == '':
        return False
    if interval[-1] not in ['s', 'm', 'h', 'd', 'w', 'y'] or not isinstance(int(interval[0:-1]), numbers.Number):
        return False
    return True
