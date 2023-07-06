# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys

from wazuh_testing.constants.platforms import WINDOWS


if sys.platform == WINDOWS:
    PREFIX = r'.*execd.*'
else:
    PREFIX = r'.*wazuh-execd.*'
