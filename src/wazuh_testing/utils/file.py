# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import bz2
import gzip
import json
import os
import re
import shutil
import stat
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Union, List

import chardet
import filetype
import requests
import yaml
from wazuh_testing.constants import platforms
from wazuh_testing.constants.platforms import WINDOWS

def write_file(file_path: str, data: Union[List[str], str] = '') -> None:
    """
    Write the specified data to the specified file.

    Args:
        file_path (str): The path to the file to write to.
        data (List[str], str): The data to write to the file. This can either
                               be a string or a list of strings.
    """
    with open(file_path, 'w') as f:
        f.writelines(data)


def read_file(path: str) -> str:
    """
    Read a file and return its content.

    Args:
        path (str): The path to the file to read.

    Returns:
        str: A string with the content of the file.
    """
    with open(path) as f:
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

    if sys.platform != platforms.WINDOWS:
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


def read_yaml(file_path):
    """Read a YAML file from a given path, return a dictionary with the YAML data

    Args:
        file_path (str): Path of the YAML file to be read.

    Returns:
       dict: Yaml structure.
    """
    with open(file_path) as f:
        return yaml.safe_load(f)


def read_json_file(file_path: Union[str, os.PathLike]) -> dict:
    """Read a JSON file from a given path, return a dictionary with the JSON data

    Args:
        file_path (str): Path of the JSON file to be read.

    Returns:
       dict: JSON data.
    """
    return json.loads(read_file(file_path))


def append_content_to_yaml(path: Union[str, os.PathLike], content: dict) -> None:
    """Write content at the end of a file or clear its content if `content` is None.

    Args:
        path (str | PathLike): Path to the target file.
    """
    with open(path, 'w+') as file:
        yaml.dump(content, file)


def truncate_file(file_path: str) -> None:
    """
    Truncates the specified file.

    Args:
        file_path (str): The path to the file to be truncated.
    """
    with open(file_path, "w") as f:
        f.truncate()


def replace_regex_in_file(search_regex: List[str], replace_regex: List[str], file_path: str) -> None:
    """Perform replacements in a file data according to the specified regex.

    Args:
        search_regex (List[str]): Search regex list.
        replace_regex (List[str]): Replacements regex list.
        file_path (str): File path to read and update.
    """
    if (len(search_regex) != len(replace_regex)):
        raise ValueError('search_regex has to have the same number of items than replace_regex. '
                         f"{len(search_regex)} != {len(replace_regex)}")

    # Read the file content
    file_data = read_file(file_path)

    # Perform the replacements
    for search, replace in zip(search_regex, replace_regex):
        file_data = re.sub(search, replace, file_data)

    # Write the file data
    write_file(file_path, file_data)


def get_file_encoding(file_path: Union[str, os.PathLike]) -> str:
    """Detect and return the file encoding.

    Args:
        file_path (str): File path to check.

    Returns:
        encoding (str): File encoding.

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


def on_write_error(function, path, exc_info):
    """ Error handler for functions that try to modify a file. If the error is due to an access error (read only file),
    it attempts to add write permission and then retries. If the error is for another reason it re-raises the error.

    Args:
        function (function): function that called the handler.
        path (str): Path to the file the function is trying to modify
        exc_info (object): function instance execution information. Passed in by function in runtime.

    Example:
        > shutil.rmtree(path, onerror=on_write_error)
    """
    # Check if the error is an access error for Write permissions.
    if not os.access(path, os.W_OK):
        # Add write permissions so file can be edited and execute function.
        os.chmod(path, 0o0777)
        function(path)
    # If error is not Write access error, raise the error
    else:
        raise


def delete_path_recursively(path: str) -> None:
    '''Remove a directory recursively.

    Args:
        path (str): Directory path.
    '''
    if os.path.exists(path):
        shutil.rmtree(path, onerror=on_write_error)


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


def exists_and_is_file(path: str) -> bool:
    """Check if a file exists at the given path.

    Args:
        path (str): The path to the file.

    Returns:
        bool: True if the file exists and is a regular file, False otherwise.
    """
    return os.path.exists(path) and os.path.isfile(path)


def create_parent_directories(path: os.PathLike) -> list:
    """Create parent directories and return ONLY the created ones.

    Args:
        path (os.PathLike): Path of the file or directory with parents

    Returns:
        created_parents (list): List of created parents (maybe not all of the parents were created)
    """
    created_parents = []

    for parent in reversed(path.parents):
        # If the folder exist do not add it to the `created_files` list, otherwise add it
        try:
            parent.mkdir(exist_ok=False)
            created_parents.append(parent)
        except FileExistsError:
            pass

    return created_parents


def recursive_directory_creation(path):
    """Recursive function to create folders.

    Args:
        path (str): Path to create. If a folder doesn't exists, it will create it.
    """
    parent, _ = os.path.split(path)
    if parent != '' and not os.path.exists(parent):
        split = os.path.split(parent)
        recursive_directory_creation(split[0])
        os.mkdir(parent, mode=0o0777)

    if not os.path.exists(path):
        os.mkdir(path, mode=0o0777)


def create_files(files: list[Union[str, os.PathLike]]) -> list:
    """Create multiple files/directories. Return the list of created files/directories.

    If the list contains a file, it must have at least 1 suffix, for example: `file.txt`; else it's considered as dir.

    Args:
        files (list(str | os.PathLike)): Paths of files to be created.

    Returns:
        created_files (list): List of files/directories created during the process.

    Raises:
        FileExistsError: When a file already exists.
    """
    if not isinstance(file, list):
        raise TypeError(f"`file` should be a 'list', not a '{type(file)}'")

    created_files = []
    for file in files:
        file = Path(file)
        if file.exists():
            raise FileExistsError(f"`{file}` already exists.")

        # If file does not have suffixes, consider it a directory
        if file.suffixes == []:
            # Add a dummy file to the target directory to create the directory
            created_files.extend(create_parent_directories(Path(file).joinpath('dummy.file')))
            return create_files

        created_files.extend(create_parent_directories(file))

        write_file(file_path=file, data='')
        created_files.append(file)

    return created_files


def delete_files(files: list[Union[str, os.PathLike]]) -> None:
    """Delete a list of files.

    Args:
        files (list(str | os.PathLike)): Paths of files to be deleted.
    """
    for file in files:
        remove_file(file)


def copy(source, destination):
    """
    Copy file with metadata and ownership to a specific destination.

    Args:
        source (str): Source file path to copy.
        destination (str): Destination file.
    """
    shutil.copy2(source, destination)
    source_stats = os.stat(source)

    if sys.platform != WINDOWS:
        os.chown(destination, source_stats[stat.ST_UID], source_stats[stat.ST_GID])


def copy_files_in_folder(src_folder, dst_folder='/tmp', files_to_move=None):
    """Copy files from a folder to target folder
    Args:
        src_folder (str): directory path from where to copy files.
        dst_folder (str): directory path where files will be copied to.
        files_to_move (list): List with files to move copy from a folder.
    """
    file_list = []
    if os.path.isdir(src_folder):
        if files_to_move is None:
            for file in os.listdir(src_folder):
                file_list.append(file)
                copy(os.path.join(src_folder, file), dst_folder)
                remove_file(os.path.join(src_folder, file))
        else:
            for file in files_to_move:
                if os.path.isfile(os.path.join(src_folder, file)):
                    file_list.append(file)
                    copy(os.path.join(src_folder, file), dst_folder)
                    remove_file(os.path.join(src_folder, file))
    return file_list


def get_list_of_content_yml(file_path, separator='_'):
    """Read a YAML file from a given path, return a list with the YAML data
    after apply filter

    Args:
        file_path (str): Path of the YAML file to be readed
        separator (str): filder to extract some part of yaml

    Returns:
       list: Yaml structure.
    """
    value_list = []
    with open(file_path) as f:
        value_list.append((yaml.safe_load(f), file_path.split(separator)[0]))

    return value_list

def recursive_directory_creation(path):
    """Recursive function to create folders.

    Args:
        path (str): Path to create. If a folder doesn't exists, it will create it.
    """
    parent, _ = os.path.split(path)
    if parent != '' and not os.path.exists(parent):
        split = os.path.split(parent)
        recursive_directory_creation(split[0])
        os.mkdir(parent, mode=0o0777)

    if not os.path.exists(path):
        os.mkdir(path, mode=0o0777)
