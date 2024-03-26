# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module will contain data structures, queries and db utils to manage AWS services and buckets databases.
"""

# Local imports
from wazuh_testing.utils.database import get_sqlite_query_result, get_fetch_one_query_result
from wazuh_testing.constants.paths.aws import S3_CLOUDTRAIL_DB_PATH, AWS_SERVICES_DB_PATH

""" Database data structures  """

import sqlite3
from collections import namedtuple

from wazuh_testing.constants.aws import (
    ALB_TYPE,
    CISCO_UMBRELLA_TYPE,
    CLB_TYPE,
    CLOUD_TRAIL_TYPE,
    CUSTOM_TYPE,
    GUARD_DUTY_TYPE,
    NLB_TYPE,
    SERVER_ACCESS_TABLE_NAME,
    VPC_FLOW_TYPE,
    WAF_TYPE,
)

# Databases
SELECT_QUERY_TEMPLATE = 'SELECT * FROM {table_name}'

S3CloudTrailRow = namedtuple(
    'S3CloudTrailRow', 'bucket_path aws_account_id aws_region log_key processed_date created_date'
)

S3VPCFlowRow = namedtuple(
    'S3VPCFlowRow', 'bucket_path aws_account_id aws_region flowlog_id log_key processed_date created_date'
)

S3ALBRow = namedtuple(
    'S3ALBRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

S3CustomRow = namedtuple(
    'S3CustomRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

S3GuardDutyRow = namedtuple(
    'S3GuardDutyRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

S3WAFRow = namedtuple(
    'S3WAFRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

S3ServerAccessRow = namedtuple(
    'S3ServerAccessRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

ServiceInspectorRow = namedtuple(
    'ServiceInspectorRow', 'service account_id region timestamp'
)

ServiceCloudWatchRow = namedtuple(
    'ServiceCloudWatchRow', 'aws_region aws_log_group aws_log_stream next_token start_time end_time'
)

S3UmbrellaRow = namedtuple(
    'S3UmbrellaRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

s3_rows_map = {
    CLOUD_TRAIL_TYPE: S3CloudTrailRow,
    VPC_FLOW_TYPE: S3VPCFlowRow,
    ALB_TYPE: S3ALBRow,
    CLB_TYPE: S3ALBRow,
    NLB_TYPE: S3ALBRow,
    CUSTOM_TYPE: S3CustomRow,
    GUARD_DUTY_TYPE: S3GuardDutyRow,
    WAF_TYPE: S3WAFRow,
    SERVER_ACCESS_TABLE_NAME: S3ServerAccessRow,
    CISCO_UMBRELLA_TYPE: S3UmbrellaRow
}

service_rows_map = {
    'cloudwatch_logs': ServiceCloudWatchRow,
    'aws_services': ServiceInspectorRow
}

""" Database AWS utils"""


def _get_s3_row_type(bucket_type):
    """Get row type for bucket integration.

    Args:
        bucket_type (str): The name of the bucket.

    Returns:
        Type[S3CloudTrailRow]: The type that match or a default one.
    """
    return s3_rows_map.get(bucket_type, S3CloudTrailRow)


def _get_service_row_type(table_name):
    """Get row type for service integration.

    Args:
        table_name (str): Table name to match.

    Returns:
        Type[ServiceCloudWatchRow]: The type that match or a default one.
    """
    return service_rows_map.get(table_name, ServiceCloudWatchRow)


"""Database queries"""


# cloudtrail.db utils
def get_s3_db_row(table_name) -> S3CloudTrailRow:
    """Return one row from the given table name.

    Args:
        table_name (str): Table name to search into.

    Returns:
        S3CloudTrailRow: The first row of the table.
    """
    row_type = _get_s3_row_type(table_name)
    query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
    row = get_fetch_one_query_result(S3_CLOUDTRAIL_DB_PATH, query)

    return row_type(*row)


def get_multiple_s3_db_row(table_name):
    """Return all rows from the given table name.

    Args:
        table_name (str): Table name to search into.

    Yields:
        Iterator[S3CloudTrailRow]: All the rows in the table.
    """
    row_type = _get_s3_row_type(table_name)
    query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
    rows = get_sqlite_query_result(S3_CLOUDTRAIL_DB_PATH, query)

    for row in rows:
        yield row_type(*row)


def table_exists(table_name, db_path=S3_CLOUDTRAIL_DB_PATH):
    """Check if the given table name exists.

    Args:
        table_name (str): Table name to search for.
        db_path (str, optional): Path to the SQLite database. Defaults to S3_CLOUDTRAIL_DB_PATH.

    Returns:
        bool: True if exists else False.
    """
    query = """
            SELECT
                name
            FROM
                sqlite_master
            WHERE
                type ='table' AND
                name NOT LIKE 'sqlite_%';
            """
    results = get_sqlite_query_result(db_path, query)

    return table_name in [result[0] for result in results]


def table_exists_or_has_values(table_name, db_path=S3_CLOUDTRAIL_DB_PATH):
    """Check if the given table name exists. If it exists, check if it has values.

    Args:
        table_name (str): Table name to search for.
        db_path (str, optional): Path to the SQLite database. Defaults to S3_CLOUDTRAIL_DB_PATH.

    Returns:
        bool: True if exists or has values else False.
    """
    try:
        query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
        result = get_sqlite_query_result(db_path, query)
        return bool(result)
    except sqlite3.OperationalError:
        return False


# aws_services.db utils

def get_service_db_row(table_name):
    """Return one row from the given table name.

    Args:
        table_name (str): Table name to search into.

    Returns:
        ServiceInspectorRow: The first row of the table.
    """
    row_type = _get_service_row_type(table_name)

    query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
    row = get_fetch_one_query_result(AWS_SERVICES_DB_PATH, query)

    return row_type(*row)


def get_multiple_service_db_row(table_name):
    """Return all rows from the given table name.

    Args:
        table_name (str): Table name to search into.

    Yields:
        Iterator[ServiceInspectorRow]: All the rows in the table.
    """
    row_type = _get_service_row_type(table_name)

    query = SELECT_QUERY_TEMPLATE.format(table_name=table_name)
    rows = get_sqlite_query_result(AWS_SERVICES_DB_PATH, query)

    for row in rows:
        yield row_type(*row)
