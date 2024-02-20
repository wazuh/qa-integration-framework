# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    File contains all utils used in the AWS test suite.
"""

import subprocess
import gzip
import json
import os
from datetime import datetime

import boto3

from pathlib import Path
from botocore.exceptions import ClientError

# Local imports
from wazuh_testing.constants.aws import (PERMANENT_CLOUDWATCH_LOG_GROUP, US_EAST_1_REGION, AWS_MODULE_CALL,
                                         RESULTS_FOUND, RESULTS_EXPECTED)
from wazuh_testing.constants.paths.aws import (AWS_MODULE_PATH, AWS_BINARY_PATH, S3_CLOUDTRAIL_DB_PATH,
                                               AWS_SERVICES_DB_PATH)
from wazuh_testing.logger import logger
from wazuh_testing.modules.aws.data_generator import get_data_generator

# Use the environment variable or default to 'dev'
aws_profile = os.environ.get("AWS_PROFILE", "dev")

# Session setup
session = boto3.Session(profile_name=f'{aws_profile}')
s3 = session.client(service_name="s3")
logs = session.client(service_name="logs", region_name=US_EAST_1_REGION)
sqs = session.client(service_name="sqs", region_name=US_EAST_1_REGION)
sts = session.client(service_name="sts")


# Custom exception
class OutputAnalysisError(Exception):
    pass


"""S3 utils"""


def create_bucket(bucket_name: str):
    """Create a S3 bucket.

    Args:
        bucket_name (str): The bucket to create.

    Returns
        str: The bucket name
    """
    try:
        s3.create_bucket(
            Bucket=bucket_name
        )

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'BucketAlreadyExists':
            logger.warning(f"Bucket {bucket_name} already exist")
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
        s3.delete_bucket(
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


# def file_exists(filename: str, bucket_name: str):
#     """Check if a file exists in a bucket.
#
#     Args:
#         filename (str): Full filename to check.
#         bucket_name (str): Bucket that contains the file.
#     Returns:
#         bool: True if exists else False.
#     """
#     exists = True
#     try:
#         s3.Object(bucket_name, filename).load()
#     except ClientError as error:
#         if error.response['Error']['Code'] == '404':
#             exists = False
#
#     return exists


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

    except Exception as error:
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

    except Exception as error:
        raise error


def create_log_stream(log_group: str, log_stream: str):
    """Create a log stream within the given log group.

    Parameters
    ----------
        log_group (str): Log group to store the stream.
        log_stream (str):

    Returns
    --------
        None
    """
    try:

        logs.create_log_stream(logGroupName=log_group,
                               logStreamName=log_stream)

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceAlreadyExists':
            logger.error(f"Log Stream {log_stream} im {log_group} already exist.")
            pass
        else:
            raise error

    except Exception as error:
        raise error


def delete_log_stream(log_stream, log_group: str):
    """Delete a log stream from the given log group.

    Parameters
    ----------
        log_stream (str): The log stream to delete.
        log_group (str): Log group to delete the stream.
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

    except Exception as error:
        raise error


def upload_log_events(log_stream: str, log_group: str, events: list) -> None:
    """Upload a log event within the given log stream and group.

    Parameters
    ----------
        log_group (str): Log group where the stream is located.
        log_stream (str): The log stream to delete.
        events (list): Log events to create in log stream.

    Returns
    -------
        None
    """
    # Put events
    for event in events:
        try:
            logs.put_log_events(
                logGroupName=log_group, logStreamName=log_stream, logEvents=events,
            )
        except ClientError as error:
            # Check if the resource exist
            if error.response['Error']['Code'] == 'DataAlreadyAccepted':
                logger.error(
                    f"Event {event} already uploaded in log stream: {log_stream} withi log_group: {log_group}.")
                pass
            else:
                raise error

        except Exception as error:
            raise error


def log_stream_exists(log_group, log_stream) -> bool:
    """Check if a log stream exists in a group.

    Parameters
    ----------
    log_group : str
        Log group to search within.
    log_stream : str
        Log stream to search.

    Returns
    -------
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


"""SQS utils"""


def create_sqs_queue(sqs_name: str) -> str:
    """Create a sqs queue.

    Parameters
    ----------
    sqs_name : str
        The name of the sqs queue.

    Returns
    -------
    sqs_url: str
        Sqs queue url.
    """
    try:
        response = sqs.create_queue(
            QueueName=sqs_name
        )
        return response["QueueUrl"]

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"SQS Queue {sqs_name} already exists")
            pass
        else:
            raise error

    except Exception as error:
        raise error


def get_sqs_queue_arn(sqs_url: str) -> str:
    """Get SQS Queue ARN.

    Parameters
    ----------
    sqs_url : str
        The SQS Queue URL.

    Returns
    -------
    sqs_queue_arn : str
        The SQS queue ARN.
    """
    try:
        # Fetch queue's ARN
        response = sqs.get_queue_attributes(
            QueueUrl=sqs_url,
            AttributeNames=["QueueArn"]
        )
        return response["Attributes"]["QueueArn"]

    except ClientError as error:
        raise error

    except Exception as error:
        raise error


def set_sqs_policy(bucket_name: str, sqs_queue_url: str) -> None:
    """Set a policy for the SQS queue

    Parameters
    ----------
    bucket_name : str
        The bucket name.
    sqs_queue_url : str
        The SQS queue Url to apply policy.
    """
    # Get account id
    account_id = sts.get_caller_identiity()["Account"]

    # Get date
    today_date = datetime.now().date().strftime("%Y-%m-%d")

    # Create Policy
    policy = {
        "Version": today_date,
        "Id": "wazuh-integration-test-policy-ID",
        "Statement": [
            {
                "Sid": "wazuh-integration-test-policy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "s3.amazonaws.com"
                },
                "Action": "SQS:SendMessage",
                "Resource": f"arn:aws:sqs:{US_EAST_1_REGION}:{account_id}:{bucket_name}",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:s3:*:*:{bucket_name}"
                    }
                }
            }
        ]
    }
    # Set policy
    try:
        sqs.set_queue_attributes(
            QueueUrl=sqs_queue_url,
            Attributes={
                'Policy': json.dumps(policy)
            }
        )

    except ClientError as error:
        raise error

    except Exception as error:
        raise error


def set_bucket_event_notification_configuration(bucket_name: str, sqs_queue_arn: str) ->None:
    """Configure bucket for event notification.

    Parameters
    ----------
    bucket_name : str
        The name of the bucket.
    sqs_queue_arn : str
        The SQS Queue
    """
    # Create notification config dict
    notification_configuration = {
        'QueueConfigurations': [
            {
                'QueueArn': sqs_queue_arn,
                'Events': ['s3:ObjectCreated:*']
            }
        ]
    }
    try:
        s3.put_bucket_notification_configuration(
            bucket=bucket_name,
            NotificationConfiguration=notification_configuration
        )

    except ClientError as error:
        raise error

    except Exception as error:
        raise error


def delete_sqs_queue(sqs_queue_url: str) -> None:
    """Delete the SQS queue.

    Parameters
    ----------
    sqs_queue_url : str
        The SQS queue url
    """
    try:
        sqs.delete_queue(
            QueueUrl=sqs_queue_url
        )

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"SQS Queue {sqs_queue_url} not found")
            pass
        else:
            raise error

    except Exception as error:
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
