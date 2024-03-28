# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re

from .patterns import FIM_EVENT_JSON


def get_fim_event_data(message: str) -> dict:
    """
    Extracts the JSON data from the callback result of a FIM event.

    Args:
        message (str): The callback result of a FIM event.

    Returns:
        dict: The JSON data of the FIM event.
    """
    to_json = re.match(FIM_EVENT_JSON, message)
    return json.loads(to_json.group(1)).get('data')
