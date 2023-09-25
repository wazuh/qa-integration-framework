# AWS Constants
AWS_LOGS = 'AWSLogs'
AWS_MODULE_CALL = "Calling AWS module with: '%s'"

RANDOM_ACCOUNT_ID = '819751203817'
VPC_FLOW_LOGS = 'vpcflowlogs'
FLOW_LOG_ID = 'fl-0755d951c16f517fa'
CONFIG = 'Config'
ELASTIC_LOAD_BALANCING = 'elasticloadbalancing'
SERVER_ACCESS_TABLE_NAME = 's3_server_access'
PERMANENT_CLOUDWATCH_LOG_GROUP = 'wazuh-cloudwatchlogs-integration-tests'
TEMPORARY_CLOUDWATCH_LOG_GROUP = 'temporary-log-group'
FAKE_CLOUDWATCH_LOG_GROUP = 'fake-log-group'

# Log messages
RESULTS_FOUND = 'Results found: %s'
RESULTS_EXPECTED = 'Results expected: %s'

# Formats
EVENT_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
PATH_DATE_FORMAT = '%Y/%m/%d'
PATH_DATE_NO_PADED_FORMAT = '%Y/%-m/%-d'
FILENAME_DATE_FORMAT = '%Y%m%dT%H%MZ'
ALB_DATE_FORMAT = '%Y-%m-%dT%H:%M:%fZ'

# Regions
US_EAST_1_REGION = 'us-east-1'

# Extensions
JSON_EXT = '.json'
LOG_EXT = '.log'
JSON_GZ_EXT = '.jsonl.gz'
CSV_EXT = '.csv'

# Bucket types
CLOUD_TRAIL_TYPE = 'cloudtrail'
VPC_FLOW_TYPE = 'vpcflow'
CONFIG_TYPE = 'config'
ALB_TYPE = 'alb'
CLB_TYPE = 'clb'
NLB_TYPE = 'nlb'
KMS_TYPE = 'kms'
MACIE_TYPE = 'macie'
KMS_TYPE = 'kms'
TRUSTED_ADVISOR_TYPE = 'trusted'
CUSTOM_TYPE = 'custom'
GUARD_DUTY_TYPE = 'guardduty'
NATIVE_GUARD_DUTY_TYPE = 'native-guardduty'
WAF_TYPE = 'waf'
SERVER_ACCESS = 'server_access'
CISCO_UMBRELLA_TYPE = 'cisco_umbrella'

# Services types
INSPECTOR_TYPE = 'inspector'

# Params
ONLY_LOGS_AFTER_PARAM = '--only_logs_after'

# Databases
SELECT_QUERY_TEMPLATE = 'SELECT * FROM {table_name}'

# Errors
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
