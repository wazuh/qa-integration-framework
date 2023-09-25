from pathlib import Path

# Local imports
from . import WAZUH_PATH

AWS_MODULE_PATH = Path(WAZUH_PATH, 'wodles', 'aws')
S3_CLOUDTRAIL_DB_PATH = Path(AWS_MODULE_PATH, 's3_cloudtrail.db')
AWS_SERVICES_DB_PATH = Path(AWS_MODULE_PATH, 'aws_services.db')
AWS_BINARY_PATH = Path(AWS_MODULE_PATH, 'aws-s3')