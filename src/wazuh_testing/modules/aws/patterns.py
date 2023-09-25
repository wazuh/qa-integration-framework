# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    File contains regex patterns used in AWS module.
"""

# Errors
PARSER_ERROR = r'.*wm_aws_read\(\): ERROR:.*'
MODULE_ERROR = r'.*wm_aws_run_s3\(\): ERROR: .*'
INVALID_EMPTY_TYPE_ERROR = r".*ERROR: Invalid \w+ type ''"
EMPTY_CONTENT_ERROR = r".*ERROR: Empty content for tag '\w+' at module 'aws-s3'."
INVALID_TAG_CONTENT_ERROR = r'.*ERROR: Invalid content for tag*'
INVALID_EMPTY_SERVICE_TYPE_ERROR = r".*ERROR: Invalid \w+ type '\w+'.*"
AWS_UNDEFINED_SERVICE_TYPE = r".*ERROR: Undefined type for service."

# Warnings
EMPTY_CONTENT_WARNING = r".*WARNING: Empty content for tag '\w+' at module 'aws-s3'."
PARSING_BUCKET_ERROR_WARNING = r'.*WARNING: Bucket:  -  Error parsing arguments.*'
PARSING_SERVICE_ERROR_WARNING = r'.*WARNING: Service:  -  Error parsing arguments.*'
AWS_DEPRECATED_CONFIG_DEFINED = (r".*WARNING: Deprecated config defined; "
                                 r"please use current config definition at module 'aws-s3'.")
AWS_NO_SERVICE_WARNING = r".*WARNING: No buckets, services or subscribers definitions found at module 'aws-s3'."

# Info
SERVICE_ANALYSIS = r".*INFO: Executing Service Analysis:*"
BUCKET_ANALYSIS = r'.*INFO: Executing Bucket Analysis:*'
MODULE_START = r'.*INFO: Module AWS started*'

# Debug
DEBUG_MESSAGE = r"DEBUG: \+\+\+"
DEBUG_ANALYSISD_MESSAGE = r"DEBUG: \+\+\+ Sent"
NO_LOG_PROCESSED = r'.*DEBUG: \+\+\+ No logs to process for .*'
NO_BUCKET_LOG_PROCESSED = r'.*DEBUG: \+\+\+ No logs to process in bucket: '
NO_NEW_EVENTS = r'DEBUG: \+\+\+ There are no new events in .*'
EVENT_SENT = r'DEBUG: \+\+\+ Sent \d+ events to Analysisd'
MARKER = r".*DEBUG: \+\+\+ Marker: "
AWS_MODULE_STARTED = r'.*DEBUG: Launching S3 Command: .*'
AWS_MODULE_STARTED_PARAMETRIZED = fr'.*DEBUG: Launching S3 Command: '

# Logs
NEW_LOG_FOUND = r'.*Found new log: .*'
AWS_EVENT_HEADER = b'0:Wazuh-AWS:'
EVENTS_COLLECTED = "events collected and processed in"
ANALYSISD_EVENT = "events to Analysisd"

# Match characters
WHITESPACE_MATCH = r'\s+'
CURLY_BRACE_MATCH = r'{}{}'
