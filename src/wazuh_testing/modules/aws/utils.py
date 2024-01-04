# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    File contains all utils used in the AWS test suite.
"""

import subprocess
import gzip
from datetime import datetime

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

import os

# Use the environment variable or default to 'dev'
profile = os.environ.get('AWS_PROFILE', 'default')

# Session setup
session = boto3.Session(profile_name=f'{profile}')
s3 = session.resource('s3')
logs = session.client('logs', region_name=US_EAST_1_REGION)


# Custom exception
class OutputAnalysisError(Exception):
    pass


"""S3 utils"""


def create_bucket(bucket_name: str, bucket_type: str):
    """Create a S3 bucket.

    Args:
        bucket_name (str): The bucket to create.
        bucket_type (str): The type of bucket.

    Returns:
        str: The bucket name
    """
    try:
        bucket = s3.client.create_bucket(
            Bucket=f'{bucket_name}',
            CreateBucketConfiguration={
                'LocationConstraint': f'{US_EAST_1_REGION}',
                'Bucket': {
                    'Type': f'{bucket_type}'
                }
            }
        )

        # @todo check if needed
        return bucket

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'BucketAlreadyExists':
            logger.error(f"Bucket {bucket_name} already exist")
            pass
        else:
            raise error

    except Exception as error:
        raise error


def delete_bucket(bucket_name: str):
    """Delete a S3 bucket

    Args:
        bucket_name (str): Bucket to delete.

    Returns:
        bool: True if bucket is deleted else False.
    """
    try:
        s3.client.delete_bucket(
            Bucket=bucket_name
        )
    except ClientError as error:
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"Bucket {bucket_name} not found.")
            pass
        else:
            raise error


def generate_file(bucket_type: str, bucket_name: str):
    """ Generate a file for a specific bucket type.

    Args:
        bucket_type (str): The type of bucket.
        bucket_name (str): The bucket name.

    Returns:
        da: True if bucket is deleted else False.

    """

    dg = get_data_generator(bucket_type, bucket_name)
    filename = dg.get_filename()
    data = dg.get_data_sample().encode() if not dg.compress else gzip.compress(data=dg.get_data_sample().encode())

    return data, filename


def upload_bucket_file(bucket_name: str, data: str, filename: str):
    """Upload a file to an S3 bucket.

    Args:
        bucket_name (str): Bucket to upload.
        data (str): Data to upload in bucket
        filename (str): Name of file uploaded.

    Returns:
        bool: True if uploaded.
    """
    obj = s3.Object(bucket_name, filename)

    # Upload the file
    try:
        obj.put(Body=data)
        return True
    except ClientError as error:
        logger.error(error)
        raise error


def delete_bucket_file(filename: str, bucket_name: str):
    """Delete a given file from the bucket.

    Args:
        filename (str): Full filename to delete.
        bucket_name (str): Bucket that contains the file.
    """
    s3.Object(bucket_name, filename).delete()


def file_exists(filename: str, bucket_name: str):
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


def get_last_file_key(bucket_type: str, bucket_name: str, execution_datetime: datetime):
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


def create_log_group(log_group_name: str):
    """Create a log group.

    Args:
        log_group_name (str): Log group name to create.
    """
    try:
        logs.create_log_group(logGroupName=log_group_name)

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceAlreadyExists':
            logger.error(f"Log group {log_group_name} already exist")
            pass
        else:
            raise error


def delete_log_group(log_group_name):
    """Delete the given log group.

    Args:
        log_group_name (str): Log group name to delete.
    """
    try:
        logs.delete_log_group(logGroupName=log_group_name)

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"Log group {log_group_name} not found")
            pass
        else:
            raise error


def create_log_stream(log_group: str):
    """Create a log stream within the given log group.

    Args:
        log_group (str, optional): Log group to store the stream. Defaults to PERMANENT_CLOUDWATCH_LOG_GROUP.

    Returns:
        str: The name of the created log stream.
    """
    log_stream_name = str(uuid4())
    try:

        logs.create_log_stream(logGroupName=log_group,
                               logStreamName=log_stream_name)

        return log_stream_name

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceAlreadyExists':
            logger.error(f"Log Stream {log_stream_name} im {log_group} already exist.")
            pass
        else:
            raise error


def delete_log_stream(log_stream, log_group: str):
    """Delete a log stream from the given log group.

    Args:
        log_stream (str): The log stream to delete.
        log_group (str, optional): Log group to delete the stream. Defaults to PERMANENT_CLOUDWATCH_LOG_GROUP.
    """
    try:

        logs.delete_log_stream(logGroupName=log_group, logStreamName=log_stream)
    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"Log Stream {log_stream} in {log_group} not found.")
            pass
        else:
            raise error


def create_log_events(log_stream, log_group: str, event_number=1):
    """Create a log event within the given log stream and group.

    Args:
        log_stream (str): The log stream to delete.
        log_group (str, optional): Log group to delete the stream.
        event_number (int, optional): Number of events to create. Defaults to 1.
    """
    events = [
        {'timestamp': int(time() * 1000), 'message': f"Test event number {i}"} for i in range(event_number)
    ]
    try:

        logs.put_log_events(
            logGroupName=log_group, logStreamName=log_stream, logEvents=events,
        )

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'DataAlreadyAccepted':
            logger.error(f"Event {events} already accepted in log stream: {log_stream} inside log_group: {log_group}.")
            pass
        else:
            raise error


def log_stream_exists(log_group, log_stream) -> bool:
    """Check if a log stream exists in a group.

    Args:
        log_group (str): Log group to search within.
        log_stream (str): Log stream to search.

    Returns:
        bool: True if exists else False
    """
    try:
        response = logs.describe_log_streams(logGroupName=log_group)
        log_streams = [item['logStreamName'] for item in response['logStreams']]

        return log_stream in log_streams
    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"Log stream {log_stream} not found in log group {log_group}")
            pass
        else:
            raise error


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


def delete_resources(resource: dict):
    """Delete the given resource from AWS.

    Args:
        resource (str): Resource to delete.

    Return:
        None
    """

    try:

        if resource["type"] is "bucket":
            delete_bucket(bucket_name=resource["name"])
        elif resource["type"] is "log_group":
            delete_log_group(log_group_name=resource["name"])

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"Resource {resource['type'], resource['name']} not found.")
            pass
        else:
            raise error
