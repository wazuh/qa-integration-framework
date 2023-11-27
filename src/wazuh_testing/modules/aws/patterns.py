# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    File contains regex patterns used in AWS test suite.
"""

# Errors
PARSER_ERROR = ".*wm_aws_read\(\): ERROR:.*"
MODULE_ERROR = ".*wm_aws_run_s3\(\): ERROR: .*"
INVALID_EMPTY_TYPE_ERROR = ".*ERROR: Invalid \w+ type ''"
EMPTY_CONTENT_ERROR = ".*ERROR: Empty content for tag '\w+' at module 'aws-s3'."
INVALID_TAG_CONTENT_ERROR = ".*ERROR: Invalid content for tag*"
INVALID_EMPTY_SERVICE_TYPE_ERROR = ".*ERROR: Invalid \w+ type '\w+'.*"
AWS_UNDEFINED_SERVICE_TYPE = ".*ERROR: Undefined type for service."

# Warnings
EMPTY_CONTENT_WARNING = ".*WARNING: Empty content for tag '\w+' at module 'aws-s3'."
PARSING_BUCKET_ERROR_WARNING = ".*WARNING: Bucket:  -  Error parsing arguments.*"
PARSING_SERVICE_ERROR_WARNING = ".*WARNING: Service:  -  Error parsing arguments.*"
AWS_DEPRECATED_CONFIG_DEFINED = (".*WARNING: Deprecated config defined; "
                                 "please use current config definition at module 'aws-s3'.")
AWS_NO_SERVICE_WARNING = ".*WARNING: No buckets, services or subscribers definitions found at module 'aws-s3'."

# Info
SERVICE_ANALYSIS = ".*INFO: Executing Service Analysis:*"
BUCKET_ANALYSIS = ".*INFO: Executing Bucket Analysis:*"
MODULE_START = ".*INFO: Module AWS started*"

# Debug
DEBUG_MESSAGE = "DEBUG: \+\+\+"
DEBUG_ANALYSISD_MESSAGE = "DEBUG: \+\+\+ Sent"
NO_LOG_PROCESSED = ".*DEBUG: \+\+\+ No logs to process for .*"
NO_BUCKET_LOG_PROCESSED = ".*DEBUG: \+\+\+ No logs to process in bucket: "
NO_NEW_EVENTS = "DEBUG: \+\+\+ There are no new events in .*"
EVENT_SENT = "DEBUG: \+\+\+ Sent \d+ events to Analysisd"
MARKER = ".*DEBUG: \+\+\+ Marker: "
AWS_MODULE_STARTED = ".*DEBUG: Launching S3 Command: .*"
AWS_MODULE_STARTED_PARAMETRIZED = ".*DEBUG: Launching S3 Command: "

# Logs
NEW_LOG_FOUND = ".*Found new log: .*"
AWS_EVENT_HEADER = b"1:Wazuh-AWS:"
EVENTS_COLLECTED = "events collected and processed in"
ANALYSISD_EVENT = "events to Analysisd"
NON_EXISTENT_SPECIFIED_LOG_GROUPS = ".*The specified log group does not exist."
