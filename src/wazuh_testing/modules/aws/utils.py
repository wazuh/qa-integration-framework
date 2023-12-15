# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    File contains all utils used in the AWS test suite.
"""

import subprocess
import gzip
import boto3

from pathlib import Path
from time import time
from uuid import uuid4
from botocore.exceptions import ClientError

# Local imports
from wazuh_testing.constants.aws import (PERMANENT_CLOUDWATCH_LOG_GROUP, US_EAST_1_REGION, AWS_MODULE_CALL,
                                         RESULTS_FOUND, RESULTS_EXPECTED)
from wazuh_testing.constants.paths.aws import (AWS_MODULE_PATH, AWS_BINARY_PATH, S3_CLOUDTRAIL_DB_PATH,
                                               AWS_SERVICES_DB_PATH)
from wazuh_testing.logger import logger
from wazuh_testing.modules.aws.data_generator import get_data_generator


# Session setup
session = boto3.Session(profile_name='qa')
s3 = session.resource('s3')
logs = session.client('logs', region_name=US_EAST_1_REGION)


# Custom exception
class OutputAnalysisError(Exception):
    pass


"""S3 utils"""


def upload_file(bucket_type, bucket_name):
    """Upload a file to an S3 bucket.

    Args:
        bucket_type (str): Bucket type to generate the data.
        bucket_name (str): Bucket to upload.

    Returns:
        str: The name of the file if was uploaded, else ''.
    """
    dg = get_data_generator(bucket_type, bucket_name)
    filename = dg.get_filename()
    obj = s3.Object(bucket_name, filename)

    data = dg.get_data_sample().encode() if not dg.compress else gzip.compress(data=dg.get_data_sample().encode())

    # Upload the file
    try:
        obj.put(Body=data)
    except ClientError as e:
        logger.error(e)
        filename = ''
    return filename


def delete_file(filename, bucket_name):
    """Delete a given file from the bucket.

    Args:
        filename (str): Full filename to delete.
        bucket_name (str): Bucket that contains the file.
    """
    s3.Object(bucket_name, filename).delete()


def file_exists(filename, bucket_name):
    """Check if a file exists in a bucket.

    Args:
        filename (str): Full filename to check.
        bucket_name (str): Bucket that contains the file.
    Returns:
        bool: True if exists else False.
    """
    exists = True
    try:
        s3.Object(bucket_name, filename).load()
    except ClientError as error:
        if error.response['Error']['Code'] == '404':
            exists = False

    return exists


def get_last_file_key(bucket_type, bucket_name, execution_datetime):
    """Return the last file key contained in a default path of a bucket.

    Args:
        bucket_type (str): Bucket type to obtain the data generator.
        bucket_name (str): Bucket that contains the file.
        execution_datetime (datetime): Datetime to use as prefix.

    Returns:
        str: The last key in the bucket.
    """

    dg = get_data_generator(bucket_type, bucket_name)
    bucket = s3.Bucket(bucket_name)
    last_key = None

    try:
        *_, last_item = bucket.objects.filter(Prefix=dg.BASE_PATH or str(execution_datetime.year))
        last_key = last_item.key
    except ValueError:
        last_key = ''
    return last_key


"""AWS CloudWatch related utils"""


def create_log_group(log_group_name):
    """Create a log group.

    Args:
        log_group_name (str): Log group name to create.
    """
    logs.create_log_group(logGroupName=log_group_name)


def delete_log_group(log_group_name):
    """Delete the given log group.

    Args:
        log_group_name (str): Log group name to delete.
    """
    logs.delete_log_group(logGroupName=log_group_name)


def create_log_stream(log_group=PERMANENT_CLOUDWATCH_LOG_GROUP):
    """Create a log stream within the given log group.

    Args:
        log_group (str, optional): Log group to store the stream. Defaults to PERMANENT_CLOUDWATCH_LOG_GROUP.

    Returns:
        str: The name of the created log stream.
    """
    log_stream_name = str(uuid4())
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream_name)

    return log_stream_name


def delete_log_stream(log_stream, log_group=PERMANENT_CLOUDWATCH_LOG_GROUP):
    """Delete a log stream from the given log group.

    Args:
        log_stream (str): The log stream to delete.
        log_group (str, optional): Log group to delete the stream. Defaults to PERMANENT_CLOUDWATCH_LOG_GROUP.
    """
    logs.delete_log_stream(logGroupName=log_group, logStreamName=log_stream)


def create_log_events(log_stream, log_group=PERMANENT_CLOUDWATCH_LOG_GROUP, event_number=1):
    """Create a log event within the given log stream and group.

    Args:
        log_stream (str): The log stream to delete.
        log_group (str, optional): Log group to delete the stream. Defaults to PERMANENT_CLOUDWATCH_LOG_GROUP.
        event_number (int, optional): Number of events to create. Defaults to 1.
    """

    events = [
        {'timestamp': int(time() * 1000), 'message': f"Test event number {i}"} for i in range(event_number)
    ]

    logs.put_log_events(
        logGroupName=log_group, logStreamName=log_stream, logEvents=events,
    )


def log_stream_exists(log_group, log_stream) -> bool:
    """Check if a log stream exists in a group.

    Args:
        log_group (str): Log group to search within.
        log_stream (str): Log stream to search.

    Returns:
        bool: True if exists else False
    """
    response = logs.describe_log_streams(logGroupName=log_group)
    log_streams = [item['logStreamName'] for item in response['logStreams']]

    return log_stream in log_streams


"""CLI utils"""


def call_aws_module(*parameters):
    """Given some parameters call the AWS module and return the output.

    Returns:
        str: The command output.
    """
    command = [AWS_BINARY_PATH, *parameters]
    logger.debug(AWS_MODULE_CALL, command)
    command_result = subprocess.run(command, capture_output=True)

    return command_result.stdout.decode()


def _default_callback(line: str):
    print(line)
    return line


def analyze_command_output(
        command_output, callback=_default_callback, expected_results=1, error_message=''
):
    """Analyze the given command output searching for a pattern.

    Args:
        command_output (str): The output to analyze.
        callback (Callable, optional): A callback to process each line. Defaults to _default_callback.
        expected_results (int, optional): Number of expected results. Defaults to 1.
        error_message (str, optional): Message to show with the exception. Defaults to ''.

    Raises:
        OutputAnalysisError: When the expected results are not correct.
    """

    results = []

    for line in command_output.splitlines():
        logger.debug(line)
        item = callback(line)

        if item is not None:
            results.append(item)

    results_len = len(results)

    if results_len != expected_results:
        if error_message:
            logger.error(error_message)
            logger.error(RESULTS_FOUND, results_len)
            logger.error(RESULTS_EXPECTED, expected_results)
            raise OutputAnalysisError(error_message)


"""Database utils"""


def s3_db_exists():
    """Check if `s3_cloudtrail.db` exists.

    Returns:
        bool: True if exists else False.
    """
    return S3_CLOUDTRAIL_DB_PATH.exists()


def delete_s3_db() -> None:
    """Delete `s3_cloudtrail.db` file."""
    if path_exist(S3_CLOUDTRAIL_DB_PATH):
        S3_CLOUDTRAIL_DB_PATH.unlink()


def delete_services_db() -> None:
    """Delete `aws_services.db` file."""
    if path_exist(AWS_SERVICES_DB_PATH):
        AWS_SERVICES_DB_PATH.unlink()


"""Common utils"""


def path_exist(path: Path) -> bool:
    """Check if given path exists

    Return:
        bool: True if exist else False
    """
    return path.exists()
