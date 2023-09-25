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
