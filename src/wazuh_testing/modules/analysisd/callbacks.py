# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re
import json

from .patterns import ANALYSISD_QUEUE_DB_MESSSAGE


def callback_analysisd_message(line):
    if isinstance(line, bytes):
        line = line.decode()
    match = re.match(ANALYSISD_QUEUE_DB_MESSSAGE, line)
    if match:
        try:
            body = json.loads(match.group(3))
        except json.decoder.JSONDecodeError:
            body = match.group(3)
        return match.group(1), match.group(2), body
    return None


def callback_wazuh_db_message(item):
    data, _ = item
    match = re.match(ANALYSISD_QUEUE_DB_MESSSAGE, data.decode())
    if match:
        try:
            body = json.loads(match.group(3))
        except json.decoder.JSONDecodeError:
            body = match.group(3)
        return match.group(1), match.group(2), body
    return None
