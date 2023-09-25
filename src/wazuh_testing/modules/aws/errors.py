# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    This file contains error messages to be used in the AWS integration test module.
"""

# CONSTANTS
FAILED_START = "The AWS module did not start as expected"
INCORRECT_PARAMETERS = "The AWS module was not called with the correct parameters"
ERROR_FOUND = "Found error message on AWS module"
INCORRECT_EVENT_NUMBER = "The AWS module did not process the expected number of events"
INCORRECT_NON_EXISTENT_REGION_MESSAGE = "The AWS module did not show correct message about non-existent region"
INCORRECT_NO_EXISTENT_LOG_GROUP = "The AWS module did not show correct message non-existent log group"
INCORRECT_EMPTY_PATH_MESSAGE = "The AWS module did not show correct message about empty path"
INCORRECT_EMPTY_PATH_SUFFIX_MESSAGE = "The AWS module did not show correct message about empty path_suffix"
INCORRECT_ERROR_MESSAGE = "The AWS module did not show the expected error message"
INCORRECT_EMPTY_VALUE_MESSAGE = "The AWS module did not show the expected message about empty value"
INCORRECT_LEGACY_WARNING = "The AWS module did not show the expected legacy warning"
INCORRECT_WARNING = "The AWS module did not show the expected warning"
INCORRECT_INVALID_VALUE_MESSAGE = "The AWS module did not show the expected message about invalid value"
INCORRECT_MARKER = "The AWS module did not use the correct marker"
INCORRECT_SERVICE_CALLS_AMOUNT = "The AWS module was not called for bucket or service the right amount of times"
UNEXPECTED_NUMBER_OF_EVENTS_FOUND = "Some logs may were processed or the results found are more than expected"
POSSIBLY_PROCESSED_LOGS = "Some logs may were processed"