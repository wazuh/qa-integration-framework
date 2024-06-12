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
from wazuh_testing.constants.platforms import LINUX
from wazuh_testing.utils import commands


def write_file(file_path: str, data: Union[List[str], str, bytes] = '') -> None:
    """
    Write the specified data to the specified file.

    Args:
        file_path (str): The path to the file to write to.
        data (List[str], str): The data to write to the file. This can either
                               be a string or a list of strings.
    """

    if isinstance(data, bytes):
        with open(file_path, 'wb') as f:
            f.write(data)
    else:
        with open(file_path, 'w') as f:
            f.writelines(data)


def write_file_write(file_path, content=''):
    """
    Write the specified data to the specified file using only write.

    Args:
        file_path (str): The path to the file to write to.
        content: The data to write to the file.
    """
    mode = 'wb' if isinstance(content, bytes) else 'w'

    with open(file_path, mode) as f:
        f.write(content)


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
        return yaml.load(f, yaml.Loader)


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


def replace_regex_in_file(search_regex: List[str], replace_regex: List[str], file_path: str, use_dotall: bool = False) -> None:
    """Perform replacements in a file data according to the specified regex.

    Args:
        search_regex (List[str]): Search regex list.
        replace_regex (List[str]): Replacements regex list.
        file_path (str): File path to read and update.
        use_dotall (bool, optional): Whether to use re.DOTALL flag for the regex operation. Defaults to False.
    """
    if (len(search_regex) != len(replace_regex)):
        raise ValueError('search_regex has to have the same number of items than replace_regex. '
                         f"{len(search_regex)} != {len(replace_regex)}")

    # Read the file content
    file_data = read_file(file_path)

    # Perform the replacements
    flags = re.DOTALL if use_dotall else 0
    for search, replace in zip(search_regex, replace_regex):
        file_data = re.sub(search, replace, file_data, flags=flags)

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
    if os.path.islink(file_path):
        os.unlink(file_path)
    elif os.path.exists(file_path):
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
            parent.mkdir(exist_ok=True)
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
    if not isinstance(files, list):
        raise TypeError(f"`files` should be a 'list', not a '{type(files)}'")

    created_files = []
    for file in files:
        file = Path(file)
        if file.exists():
            raise FileExistsError(f"`{file}` already exists.")

        # If file does not have suffixes, consider it a directory
        if file.suffixes == []:
            # Add a dummy file to the target directory to create the directory
            created_files.extend(create_parent_directories(
                Path(file).joinpath('dummy.file')))
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
        value_list.append(yaml.safe_load(f), file_path.split(separator)[0])

    return value_list


def delete_files_in_folder(folder_path):
    """Delete all files in a folder.

    Args:
        folder_path (str): Path of the folder containing the files to be deleted.
    """
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')


def move(source_path: str, destination_path: str) -> None:
    try:
        # Check if the source path exists
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source path '{source_path}' does not exist.")

        # Check if the destination path exists
        if os.path.exists(destination_path):
            raise FileExistsError(f"Destination path '{destination_path}' already exists.")

        # Move the file or folder
        shutil.move(source_path, destination_path)
    except Exception as e:
        print(f"An error occurred: {e}")


def rename(source_path: str, destination_path: str) -> None:
    # Check if the source path exists
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source path '{source_path}' does not exist.")

    # Check if the destination path exists
    if os.path.exists(destination_path):
        raise FileExistsError(f"Destination path '{destination_path}' already exists.")

    # Rename the file or folder
    os.rename(source_path, destination_path)


def modify_symlink_target(target:str, link_path: str) -> None:
    if sys.platform == LINUX:
        commands.run(['ln', '-sfn', target, link_path])
    else:
        if os.path.exists(link_path):
            os.remove(link_path)
        os.symlink(target, link_path)


def exists_in_directory(file_or_folder_name: str, directory_path: str) -> bool:
    """Check if a file or folder is inside a certain directory.

    Args:
        file_or_folder_name (str): The name of the file or folder to check.
        directory_path (str): The path to the directory to check in.

    Returns:
        bool: True if the file or folder is inside the directory, False otherwise.
    """
    # Get the absolute path of the directory
    directory_path = os.path.abspath(directory_path)

    # Get the absolute path of the file or folder
    file_or_folder_path = os.path.join(directory_path, file_or_folder_name)

    # Check if the file or folder exists and is not a symbolic link
    return os.path.exists(file_or_folder_path) and not os.path.islink(file_or_folder_path)


def exists(path:str) -> bool:
    return os.path.exists(path) or os.path.islink(path)


def translate_size(configured_size='1KB'):
    """
    Translate the configured size from string to number in bytes.

    Parameters
    ----------
    configured_size: str, optional
        Configured size to translate. Default `'1KB'`

    Returns
    -------
    translated_size: int
        Configured value in bytes.
    """
    translated_size = 0
    configured_value = int(configured_size[:-2])  # Store value ignoring the data unit
    data_unit = str(configured_size[-2:])

    if data_unit == 'KB':
        translated_size = configured_value * 1024
    elif data_unit == 'MB':
        translated_size = configured_value * 1024 * 1024
    elif data_unit == 'GB':
        translated_size = configured_value * 1024 * 1024 * 1024

    return translated_size
