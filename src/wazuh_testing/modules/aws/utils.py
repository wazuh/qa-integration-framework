# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    File contains all utils used in the AWS test suite.
"""

import subprocess
import gzip
import json
from datetime import datetime, timedelta

from pathlib import Path
from botocore.exceptions import ClientError
from typing import Tuple

# Local imports
from wazuh_testing.constants.aws import (AWS_MODULE_CALL,
                                         RESULTS_FOUND, RESULTS_EXPECTED, ONLY_LOGS_AFTER_FORMAT)
from wazuh_testing.constants.paths.aws import (AWS_MODULE_PATH, AWS_BINARY_PATH, S3_CLOUDTRAIL_DB_PATH,
                                               AWS_SERVICES_DB_PATH)
from wazuh_testing.logger import logger
from wazuh_testing.modules.aws.data_generator import get_data_generator


# Custom exception
class OutputAnalysisError(Exception):
    pass

# CloudWatch Logs maximum creation delta time
CLOUDWATCH_LOG_MAX_DAYS = 14

"""S3 utils"""


def create_bucket(bucket_name: str, client):
    """Create an S3 bucket.

    Args:
        bucket_name (str): The bucket name.
        client (boto3.resources.base.ServiceResource): S3 client used to create the bucket.
    """
    try:
        client.create_bucket(
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


def delete_bucket(bucket_name: str, client):
    """Delete an S3 bucket.

    Args:
        bucket_name (str): Bucket to delete.
        client (boto3.resources.base.ServiceResource): S3 client used to delete the bucket.
    """
    try:
        # Get bucket
        bucket = client.Bucket(name=bucket_name)

        # Delete bucket
        bucket.delete()

    except ClientError as error:
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"Bucket {bucket_name} not found.")
            pass
        else:
            raise error


def delete_bucket_files(bucket_name: str, client):
    """Delete all files in the bucket.

    Args:
        bucket_name (str): The bucket name.
        client (boto3.resources.base.ServiceResource): S3 client used to delete the bucket files.
    """
    try:
        # Get bucket
        bucket = client.Bucket(name=bucket_name)

        # Delete all objects
        bucket.objects.all().delete()
    except ClientError as error:
        raise error
    except Exception as error:
        raise error


def generate_file(bucket_type: str, bucket_name: str, date: str, region: str, 
                  prefix: str, suffix: str, **kwargs) -> Tuple[str, str]:
    """ Generate a file for a specific bucket type.

    Args:
        bucket_type (str): The type of bucket.
        bucket_name (str): The bucket name.
        date (str): Date to use for data generation.
        prefix (str): Path prefix.
        suffix (str): Path suffix.

    Returns:
        data (str): The encoded data content.
        filename (str): The name of the generated file.
    """
    files_creation_date = datetime.strptime(date, ONLY_LOGS_AFTER_FORMAT) if date \
                            else datetime.now()

    dg = get_data_generator(bucket_type, bucket_name, creation_date=files_creation_date, 
                            prefix=prefix, suffix=suffix, region=region)
    filename = dg.get_filename(**kwargs)
    data = dg.get_data_sample().encode() if not dg.compress else gzip.compress(data=dg.get_data_sample().encode())

    return data, filename


def upload_bucket_file(bucket_name: str, data: str, key: str, client):
    """Upload a file to an S3 bucket.

    Args:
        bucket_name (str): Bucket to upload.
        data (str): Data to upload in bucket.
        key (str): Bucket key.
        client (boto3.resources.base.ServiceResource): S3 client used to upload file to the bucket.
    """
    # Set bucket
    try:
        # Get bucket
        bucket = client.Bucket(name=bucket_name)

        # Upload the file
        bucket.put_object(
            Key=key,
            Body=data
        )
    except ClientError as error:
        raise error
    except Exception as error:
        raise error


def delete_bucket_file(filename: str, bucket_name: str, client):
    """Delete a given file from the bucket.

    Args:
        filename (str): Full filename to delete.
        bucket_name (str): Bucket that contains the file.
        client (boto3.resources.base.ServiceResource): S3 client used to delete the file from the bucket.
    """
    client.Object(bucket_name, filename).delete()


def get_last_file_key(bucket_type: str, bucket_name: str, execution_datetime: datetime, region: str, 
                      client, **kwargs):
    """Return the last file key contained in a default path of a bucket.

    Args:
        bucket_type (str): Bucket type to obtain the data generator.
        bucket_name (str): Bucket that contains the file.
        execution_datetime (datetime): Datetime to use as prefix.
        region (str): Expected region in the path of the bucket.
        client (boto3.resources.base.ServiceResource): S3 client to access the bucket.

    Returns:
        str: The last key in the bucket.
    """

    dg = get_data_generator(bucket_type, bucket_name, creation_date=execution_datetime, region=region, **kwargs)
    bucket = client.Bucket(bucket_name)
    last_key = None

    try:
        *_, last_item = bucket.objects.filter(Prefix=dg.base_path or str(execution_datetime.year))
        last_key = last_item.key
    except ValueError:
        last_key = ''
    return last_key

"""VPC related utils"""

def create_vpc(vpc_name: str, client) -> str:
    """Create a VPC.
    
    Args:
        vpc_name (str): Name to tag the created VPC.
        client (Service client instance): EC2 client to create a VPC.
        
    Returns:
        vpc_id (str): ID of the VPC created.
    """
    try:
        vpc = client.create_vpc(CidrBlock='10.0.0.0/16',
                             TagSpecifications=[
                                {   
                                    'ResourceType': 'vpc',
                                    'Tags': [
                                        {
                                            'Key': 'Name',
                                            'Value': vpc_name
                                        },
                                    ]
                                },
                            ]
        )
        return vpc['Vpc']['VpcId']
    except ClientError as error:
        raise error
    except Exception as error:
        logger.error(f"Found a problem creating a VPC: {error}.")


def delete_vpc(vpc_id: str, client) -> None:
    """Delete a VPC.
    
    Args:
        vpc_id (str): Id of the VPC to delete.
        client (Service client instance): EC2 client to delete the VPC and its inner resources.
    """
    try:
        client.delete_vpc(VpcId=vpc_id)
    except ClientError as error:
        raise error
    except Exception as error:
        logger.error(f"Found a problem deleting VPC related resources: {error}.")


def create_flow_log(vpc_name: str, bucket_name: str, client):
    """Create a Flow Log and the VPC to which it will belong.

    Args:
        vpc_name (str): Name to tag the created VPC.
        bucket_name (str): Name of the bucket to define as destination of the logs.
        client (Service client instance): EC2 client to create the flow log and the VPC.
    
    Returns:
        flow_log_id (str): Created flow log ID.
        vpc_id (str): Created VPC ID.
    """
    try:
        vpc_id = create_vpc(vpc_name, client)
        flow_log_id = client.create_flow_logs(ResourceIds=[vpc_id], 
                                           ResourceType='VPC',
                                           TrafficType='REJECT',
                                           LogDestinationType='s3',
                                           LogDestination=f'arn:aws:s3:::{bucket_name}')['FlowLogIds'][0]

        return flow_log_id, vpc_id
    
    except ClientError as error:
        raise error
    except Exception as error:
        logger.error(f"Found a problem creating VPC related resources: {error}.")



"""AWS CloudWatch related utils"""


def create_log_group(log_group_name: str, client):
    """Create a log group.

    Args:
        log_group_name (str): The name of the log group.
        client (Service client instance): CloudWatch Logs client to create the log group.
    """
    try:
        client.create_log_group(logGroupName=log_group_name)

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceAlreadyExists':
            logger.error(f"Log group {log_group_name} already exist")
            pass
        else:
            raise error

    except Exception as error:
        raise error


def delete_log_group(log_group_name: str, client):
    """Delete a log group.

    Args:
        log_group_name (str): The name of the log group.
        client (Service client instance): CloudWatch Logs client to delete the log group.
    """
    try:
        client.delete_log_group(logGroupName=log_group_name)

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"Log group {log_group_name} not found")
            pass
        else:
            raise error

    except Exception as error:
        raise error


def create_log_stream(log_group: str, log_stream: str, client):
    """Create a log stream within the log group.

    Args:
        log_group (str): The name of the log group.
        log_stream (str): The name of the log stream.
        client (Service client instance): CloudWatch Logs client to create the log stream.
    """
    try:

        client.create_log_stream(logGroupName=log_group,
                               logStreamName=log_stream)

    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceAlreadyExists':
            logger.error(f"Log Stream {log_stream} in {log_group} already exists.")
            pass
        else:
            raise error

    except Exception as error:
        raise error


def delete_log_stream(log_group: str, log_stream: str, client):
    """Delete a log stream from a log group.

    Args:
        log_group (str): The name of the log group.
        log_stream (str): The name of the log stream.
        client (Service client instance): CloudWatch Logs client to delete the log stream.
    """
    try:

        client.delete_log_stream(logGroupName=log_group, logStreamName=log_stream)
    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"Log Stream {log_stream} in {log_group} not found.")
            pass
        else:
            raise error

    except Exception as error:
        raise error


def upload_log_events(log_stream: str, log_group: str, date : str, type_json: bool, events_number: int, 
                      client) -> None:
    """Create one or more log events within the given log stream and group in a determined date.

    Args:
        log_group (str): The name of the log group.
        log_stream (str): The name of the log stream.
        date (str): The date to transform into timestamp of the uploaded messages.
        type_json (bool): Whether the messages to create are JSON or simple text.
        events_number (int): Number of messages to generate and upload to the log stream.
        client (Service client instance): CloudWatch Logs client to upload log.
    """
    today_date = datetime.now()

    # This variable was used as the max date allowed to put log events but 
    # the service does not behave as expected when using other dates that are not the execution one.
    max_allowed_past_date = today_date - timedelta(days = CLOUDWATCH_LOG_MAX_DAYS)

    log_date = datetime.strptime(date, ONLY_LOGS_AFTER_FORMAT) if date \
                    else today_date
    
    log_timestamp = datetime.timestamp(today_date) \
                        if (today_date - log_date).days > CLOUDWATCH_LOG_MAX_DAYS \
                        else datetime.timestamp(log_date)
    # Generate event information
    if type_json:
        events = [
            {'timestamp': int(log_timestamp * 1000 + i*100),
             'message': f'{{"message":"Test event number {i}"}}'} for i in range(events_number)
                   ]
    else:
        events = [
            {'timestamp': int(log_timestamp * 1000 + i) ,
             'message': f'Test event number {i}'} for i in range(events_number)
        ]

    # Put events
    try:
        client.put_log_events(
            logGroupName=log_group, logStreamName=log_stream, logEvents=events,
        )
    except ClientError as error:
        # Check if the resource exist
        if error.response['Error']['Code'] == 'DataAlreadyAccepted':
            logger.error(
                f"Event already uploaded in log stream: {log_stream} within log_group: {log_group}.")
            raise error
        else:
            raise error

    except Exception as error:
        raise error


def log_stream_exists(log_group, log_stream, client) -> bool:
    """Check if a log stream exists in a group.

    Args:
        log_group (str): The name of the log group.
        log_stream (str): The name of the log stream.
        client (Service client instance): CloudWatch Logs client to check log stream existence.

    Returns:
        bool: True if exists else False.
    """
    try:
        response = client.describe_log_streams(logGroupName=log_group)
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


def create_sqs_queue(sqs_name: str, client) -> str:
    """Create a sqs queue.

    Args:
        sqs_name (str): The name of the sqs queue.
        client (Service client instance): SQS client to create the SQS queue.

    Returns:
        sqs_url (str): SQS queue url.
    """
    try:
        response = client.create_queue(
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


def get_sqs_queue_arn(sqs_url: str, client) -> str:
    """Get the SQS Queue ARN.

    Args:
        sqs_url (str): The SQS Queue URL.
        client (Service client instance): SQS client to get the SQS queue ARN.

    Returns:
        sqs_queue_arn (str): The SQS queue ARN.
    """
    try:
        # Fetch queue's ARN
        response = client.get_queue_attributes(
            QueueUrl=sqs_url,
            AttributeNames=["QueueArn"]
        )
        return response["Attributes"]["QueueArn"]

    except ClientError as error:
        raise error

    except Exception as error:
        raise error


def set_sqs_policy(bucket_name: str, sqs_queue_url: str, sqs_queue_arn: str, client) -> None:
    """Set a policy for the SQS queue

    Args:
        bucket_name (str): The bucket name.
        sqs_queue_url (str): The SQS queue Url to apply policy.
        sqs_queue_arn (str): The SQS queue ARN.
        client (Service client instance): SQS client to set the SQS queue policy.
    """
    # Get account id
    account_id = sqs_queue_arn.split(':')[4]

    # Create Policy
    policy = {
        "Version": "2012-10-17",
        "Id": "wazuh-integration-test-policy-ID",
        "Statement": [
            {
                "Sid": "wazuh-integration-test-policy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "s3.amazonaws.com"
                },
                "Action": "SQS:SendMessage",
                "Resource": sqs_queue_arn,
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
        client.set_queue_attributes(
            QueueUrl=sqs_queue_url,
            Attributes={
                'Policy': json.dumps(policy)
            }
        )

    except ClientError as error:
        raise error

    except Exception as error:
        raise error


def set_bucket_event_notification_configuration(bucket_name: str, sqs_queue_arn: str, client) ->None:
    """Configure a bucket for event notification.

    Args:
        bucket_name (str): The name of the bucket.
        sqs_queue_arn (str): The SQS queue arn.
        client (boto3.resources.base.ServiceResource): S3 client used to set the bucket notification config.
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
        # Get bucket
        bucket = client.Bucket(name=bucket_name)

        bucket.Notification().put(NotificationConfiguration=notification_configuration)

    except ClientError as error:
        raise error

    except Exception as error:
        raise error


def delete_sqs_queue(sqs_queue_url: str, client) -> None:
    """Delete a SQS queue.

    Args:
        sqs_queue_url (str): The SQS queue url.
        client (Service client instance): SQS client to delete the SQS queue.
    """
    try:
        client.delete_queue(
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
    """Analyze a given command output searching for a pattern.

    Args:
        command_output (str): The output to analyze.
        callback (Callable): A callback to process each line. Defaults to _default_callback.
        expected_results (int): Number of expected results. Defaults to 1.
        error_message (str): Message to show with the exception. Defaults to ''.

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
    """Check if given path exists.

    Args:
        path (Path): The path to check.

    Returns:
        bool: True if exist else False.
    """
    return path.exists()
