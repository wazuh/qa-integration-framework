# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import sys
import os

from wazuh_testing.constants.platforms import MACOS, WINDOWS

TEMP_FILE_PATH = '/tmp'

if sys.platform == WINDOWS:
    WAZUH_PATH = os.path.join("C:", os.sep, "Program Files (x86)", "ossec-agent")
    ROOT_PREFIX = os.path.join('c:', os.sep)

elif sys.platform == MACOS:
    WAZUH_PATH = os.path.join("/", "Library", "Ossec")
    ROOT_PREFIX = os.path.join('/', 'private', 'var', 'root')

else:
    WAZUH_PATH = os.path.join("/", "var", "ossec")
    ROOT_PREFIX = os.sep
