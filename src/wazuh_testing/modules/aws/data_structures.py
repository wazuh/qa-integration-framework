import sqlite3
from collections import namedtuple

from wazuh_testing.constants.aws import (
    ALB_TYPE,
    AWS_SERVICES_DB_PATH,
    CISCO_UMBRELLA_TYPE,
    CLB_TYPE,
    CLOUD_TRAIL_TYPE,
    CUSTOM_TYPE,
    GUARD_DUTY_TYPE,
    NLB_TYPE,
    S3_CLOUDTRAIL_DB_PATH,
    SERVER_ACCESS_TABLE_NAME,
    VPC_FLOW_TYPE,
    WAF_TYPE,
)


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
