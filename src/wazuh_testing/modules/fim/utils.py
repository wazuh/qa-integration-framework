import json
import re

from .patterns import EXTRACT_FIM_EVENT_JSON


def get_fim_event_data(message: str) -> dict:
    """
    Extracts the JSON data from the callback result of a FIM event.

    Args:
        message (str): The callback result of a FIM event.

    Returns:
        dict: The JSON data of the FIM event.
    """
    to_json = re.match(EXTRACT_FIM_EVENT_JSON, message)
    return json.loads(to_json.group(1)).get('data')
