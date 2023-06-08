# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import platform


PREFIX = r'.*wazuh-execd.*'

if platform.system() == 'Windows':
    EXECD_DEBUG_CONFIG = {'windows.debug': '2'}
else:
    EXECD_DEBUG_CONFIG = {'execd.debug': '2'}
