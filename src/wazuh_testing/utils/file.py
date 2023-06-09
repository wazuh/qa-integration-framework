# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import chardet
import os
import json
import yaml

from typing import Union, List


def write_file(file_path: str, data: Union[List[str], str] = ''):
    """
    Write the specified data to the specified file.

    Args:
        file_path (str): The path to the file to write to.
        data (List[str], str): The data to write to the file. This can either
                               be a string or a list of strings.

    Returns:
        None
    """
    with open(file_path, 'w') as f:
        f.writelines(data)


def read_file_lines(path: str) -> List[str]:
    """
    Read the lines of a file and return them as a list of strings.

    Args:
        path (str): The path to the file to read.

    Returns:
        List[str]: A list of strings, each containing a line from the file.
    """
    with open(path, "r+") as f:
        lines = f.readlines()
    return lines


def read_file(file_path):
    """
    Read the data in a file and return it

    Args:
        path (str): The path to the file to read.

    Returns:
        data: The data in the file in the format it is comming.
    """
    with open(file_path) as f:
        data = f.read()
    return data


def copy(source, destination):
    """
    Copy file with metadata and ownership to a specific destination.

    Args:
        source (str): Source file path to copy.
        destination (str): Destination file.
    """
    shutil.copy2(source, destination)
    source_stats = os.stat(source)

    if sys.platform != 'win32':
        os.chown(destination, source_stats[stat.ST_UID], source_stats[stat.ST_GID])


def read_yaml(file_path):
    """Read a YAML file from a given path, return a dictionary with the YAML data

    Args:
        file_path (str): Path of the YAML file to be readed

    Returns:
       dict: Yaml structure.
    """
    with open(file_path) as f:
        return yaml.safe_load(f)


def truncate_file(file_path: str) -> None:
    """
    Truncates the specified file.

    Args:
        file_path (str): The path to the file to be truncated.

    Returns:
        None
    """
    with open(file_path, "w") as f:
        f.truncate()


def get_file_encoding(file_path):
    """Detect and return the file encoding.

    Args:
        file_path (str): File path to check.

    Returns:
        str: File encoding.

    Raises:
        ValueError: If could not find the file_path or is not a file.
        TypeError: If could not detect the file encoding.
    """
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        raise ValueError(f"{file_path} was not found or is not a file.")

    # Read the file as bytes
    with open(file_path, 'rb') as _file:
        data = _file.read()

    # Detect the content encoding
    encoding = chardet.detect(data)['encoding']

    if len(data) == 0:
        return 'utf-8'

    if encoding is None:
        raise TypeError(f"Could not detect the {file_path} encoding")

    return encoding


def read_json_file(file_path):
    """
    Write dict data to JSON file

    Args:
        file_path (str): File path where is located the JSON file to write.
    
    Returns:
        str: JSON file data.
    """
    return json.loads(read_file(file_path))


def write_json_file(file_path, data, ensure_ascii=False):
    """
    Write dict data to JSON file

    Args:
        file_path (str): File path where is located the JSON file to write.
        data (dict): Data to write.
        ensure_ascii (boolean) : If ensure_ascii is true, the output is guaranteed to have all incoming
                                 non-ASCII characters escaped. If ensure_ascii is false, these characters will
                                 be output as-is.
    """
    write_file(file_path, json.dumps(data, indent=4, ensure_ascii=ensure_ascii))
