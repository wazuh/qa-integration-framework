"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os

from . import WAZUH_PATH


# Paths that are mainly used by the Analysisd module but serves to other modules too
DEFAULT_RULESET_PATH = os.path.join(WAZUH_PATH, 'ruleset')
DEFAULT_RULES_PATH = os.path.join(DEFAULT_RULESET_PATH, 'rules')
DEFAULT_DECODERS_PATH = os.path.join(DEFAULT_RULESET_PATH, 'decoders')
CIS_RULESET_PATH = os.path.join(WAZUH_PATH, 'ruleset', 'sca')