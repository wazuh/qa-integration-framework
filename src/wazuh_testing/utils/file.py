# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import bz2
import gzip
import filetype
import chardet
import os
import sys
import shutil
import stat
import json
import time
import yaml
import xml.etree.ElementTree as ET
import requests

from typing import Union, List
from datetime import datetime


def write_file(file_path: str, data: Union[List[str], str] = '') -> None:
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


def read_file(file_path: str):
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


def copy(source: str, destination: str) -> None:
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


def download_file(source_url: str, dest_path: str) -> None:
    """Download file to destination path.

    Args:
        source_url (str): Source url of file to download.
        dest_path (str): Destination where file will be downloaded to.
    """
    request = requests.get(source_url, allow_redirects=True)
    with open(dest_path, 'wb') as dest_file:
        dest_file.write(request.content)


def remove_file(file_path: str) -> None:
    """Remove a file or a directory path.

    Args:
        file_path (str): File or directory path to remove.
    """
    if os.path.exists(file_path):
        if os.path.isfile(file_path):
            os.remove(file_path)
        elif os.path.isdir(file_path):
            delete_path_recursively(file_path)


def delete_path_recursively(path: str) -> None:
    '''Remove a directory recursively.

    Args:
        path (str): Directory path.
    '''
    if os.path.exists(path):
        shutil.rmtree(path, onerror=on_write_error)


def on_write_error(function, path, exc_info) -> None:
    """ Error handler for functions that try to modify a file. If the error is due to an access error (read only file),
    it attempts to add write permission and then retries. If the error is for another reason it re-raises the error.

    Args:
        function (function): function that called the handler.
        path (str): Path to the file the function is trying to modify
        exc_info (object): function instance execution information. Passed in by function in runtime.

    Example:
        > shutil.rmtree(path, onerror=on_write_error)
    """
    import stat
    # Check if the error is an access error for Write permissions.
    if not os.access(path, os.W_OK):
        # Add write permissions so file can be edited and execute function.
        os.chmod(path, 0o0777)
        function(path)
    # If error is not Write access error, raise the error
    else:
        raise


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


def get_file_encoding(file_path: str) -> str:
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


def get_file_info(file_path, info_type="extension") -> str:
    """Gets a file extension

    Args:
        file_path (str): File path to check.
        info_type (str): expected extension type. Default: 'extension'

    Returns:
        str: File extension or mime type.
    """
    if os.path.exists(file_path) and filetype.guess(file_path) is not None:
        file = filetype.guess(file_path)
        return file.extension if info_type == "extension" else file.mime


def decompress_file(file_path, dest_file_path, compression_type="gzip") -> None:
    """Decompresses file to destination

    Args:
        file_path (str): path of file to decompress
        dest_file_path (str): path where to decompress the file
        compression_type (str): type of compression. Default: 'gzip'. Values: 'gzip', 'zip', 'bz2'
    """
    if compression_type == "gzip":
        with gzip.open(file_path, 'rb') as source, open(dest_file_path, 'wb') as dest:
            dest.write(source.read())
    elif compression_type == "zip":
        with zipfile.ZipFile(file_path, 'r') as zip_reference:
            zip_reference.extractall(dest_file_path)
    elif compression_type == "bz2":
        with open(file_path, 'rb') as source, open(dest_file_path, 'wb') as dest:
            dest.write(bz2.decompress(source.read()))


def read_json_file(file_path: str) -> str:
    """
    Write dict data to JSON file

    Args:
        file_path (str): File path where is located the JSON file to write.

    Returns:
        str: JSON file data.
    """
    return json.loads(read_file(file_path))


def write_json_file(file_path: str, data: dict[str, str], ensure_ascii: bool = False) -> None:
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


def wait_mtime(path, time_step=5, timeout=-1):
    """
    Wait until the monitored log is not being modified.

    Args:
        path (str): Path to the file.
        time_step (int, optional): Time step between checks of mtime. Default `5`
        timeout (int, optional): Timeout for function to fail. Default `-1`

    Raises:
        FileNotFoundError: Raised when the file does not exist.
        TimeoutError: Raised when timeout is reached.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found.")

    last_mtime = 0.0
    tic = datetime.now().timestamp()

    while last_mtime != os.path.getmtime(path):
        last_mtime = os.path.getmtime(path)
        time.sleep(time_step)

        if last_mtime - tic >= timeout:
            raise TimeoutError("Reached timeout.")


def validate_json_file(file_path: str) -> bool:
    """Validates a file is in JSON format

    Args:
        file_path (str): File path where is located the JSON file to read.

    Returns:
        Boolean: returns True if the file is in JSON format, False otherwise.
    """
    try:
        with open(file_path) as file:
            json.loads(file.read())
        return True
    except json.decoder.JSONDecodeError:
        return False


def validate_xml_file(file_path: str) -> bool:
    """Validates a file is in JSON format

    Args:
        file_path (str): File path where is located the XML file to read.

    Returns:
        Boolean: returns True if the file is in XML format, False otherwise.
    """
    try:
        ET.parse(file_path)
        return True
    except ET.ParseError:
        return False
