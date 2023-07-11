import os
import requests
from jsonschema import validate
from typing import Union

from wazuh_testing.utils.file import read_json_file


def validate_statistics(response: requests.Response, schema_path: Union[str, os.PathLike]):
    """Validate statistics coming from the response object.

    Args:
        response (requests.Response): API response containing the statistics.
        schema_path (str or os.PathLike): Path of the schema from which the response will be validated.
    """
    stats_schema = read_json_file(schema_path)
    validate(instance=response.json(), schema=stats_schema)
