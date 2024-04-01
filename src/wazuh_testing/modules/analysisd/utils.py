# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
import json
from copy import deepcopy
from datetime import datetime
from jsonschema import validate, exceptions

from .patterns import *
from wazuh_testing import DATA_PATH
from wazuh_testing.constants.paths.variables import ANALYSISD_STATE
from wazuh_testing.constants.platforms import LINUX, WINDOWS


with open(os.path.join(DATA_PATH, 'alerts_template', 'analysis_alert.json'), 'r') as f:
    linux_schema = json.load(f)

with open(os.path.join(DATA_PATH, 'alerts_template', 'analysis_alert_windows.json'), 'r') as f:
    win32_schema = json.load(f)


def validate_analysis_alert(alert, schema=LINUX):
    """Check if an Analysis event is properly formatted.

    Args:
        alert (dict): Dictionary that represent an alert
        schema (str, optional): String with the platform to validate the alert from. Default `linux`
    """
    if schema == WINDOWS:
        _schema = win32_schema
    else:
        _schema = linux_schema
    validate(schema=_schema, instance=alert)


def validate_analysis_alert_syscheck(alert, event, schema=LINUX):
    """Check if an Analysis alert is properly formatted in reference to its Syscheck event.

    Args:
        alert (dict): Dictionary that represents an alert
        event (dict): Dictionary that represents an event
        schema (str, optional): String with the schema to apply. Default `linux`
    """

    def validate_attributes(syscheck_alert, syscheck_event, event_field, suffix):
        for attribute, value in syscheck_event[SYSCHECK_DATA][event_field].items():
            # Skip certain attributes since their alerts will not have them
            if attribute in [SYSCHECK_ATTRIBUTES_TYPE, SYSCHECK_ATTRIBUTES_CHECKSUM, SYSCHECK_ATTRIBUTES, SYSCHECK_VALUE_TYPE] or \
                            (SYSCHECK_ATTRIBUTES_INODE in attribute and schema == WINDOWS):
                continue
            # Change `mtime` format to match with alerts
            elif attribute == SYSCHECK_ATTRIBUTES_MTIME:
                value = datetime.utcfromtimestamp(value).isoformat()
            # Remove `hash_` from hash attributes since alerts do not have them
            elif SYSCHECK_ATTRIBUTES_HASH in attribute:
                attribute = attribute.split('_')[-1]
            # `perm` attribute has a different format on Windows
            elif SYSCHECK_ATTRIBUTES_PERM in attribute and schema == WINDOWS:
                if SYSCHECK_ATTRIBUTES_TYPE_REGISTRY in str(syscheck_event):
                    continue

                attribute = 'win_perm'
                win_perm_list = []

                for win_perm in value.split(','):
                    user, effect, permissions = re.match(r'^(.+?) \((.+?)\): (.+?)$', win_perm).groups()
                    win_perm_list.append({'name': user.strip(' '), effect: permissions.upper().split('|')})

                value = win_perm_list

            attrs = [SYSCHECK_ATTRIBUTES_GROUP_NAME, SYSCHECK_ATTRIBUTES_MTIME]
            if SYSCHECK_ATTRIBUTES_TYPE_REGISTRY in str(syscheck_event) and attribute in attrs:
                continue

            attrs = [SYSCHECK_ATTRIBUTES_USER_NAME, SYSCHECK_ATTRIBUTES_GROUP_NAME]
            attribute = '{}name'.format(attribute[0]) if attribute in attrs else attribute

            assert str(value) == str(syscheck_alert['{}_{}'.format(attribute, suffix)]), \
                f"{value} not equal to {syscheck_alert['{}_{}'.format(attribute, suffix)]}"

        if SYSCHECK_TAGS in event[SYSCHECK_DATA]:
            assert event[SYSCHECK_DATA][SYSCHECK_TAGS] == syscheck_alert[SYSCHECK_TAGS][0], 'Tags not in alert or ' \
                                                                                            'with different value'

        if SYSCHECK_CONTENT_CHANGES in event[SYSCHECK_DATA]:
            assert event[SYSCHECK_DATA][SYSCHECK_CONTENT_CHANGES] == syscheck_alert[ALERTS_SYSCHECK_DIFF]

    try:
        validate_analysis_alert(alert, schema)
    except exceptions.ValidationError as e:
        raise e
    try:
        validate_attributes(deepcopy(alert[ALERTS_SYSCHECK]), deepcopy(event), SYSCHECK_ATTRIBUTES, 'after')
        if event[SYSCHECK_DATA][SYSCHECK_TYPE] == SYSCHECK_TYPE_MODIFIED and \
           SYSCHECK_ATTRIBUTES_TYPE_REGISTRY not in str(event):
            validate_attributes(deepcopy(alert[ALERTS_SYSCHECK]), deepcopy(event), SYSCHECK_OLD_ATTRIBUTES, 'before')
    except KeyError:
        raise KeyError('Alert does not have the same keys as the event.')
    # Full log validation:
    # Check that if the path is too long, it is displayed correctly.
    if len(event[SYSCHECK_DATA][SYSCHECK_PATH]) > 756:
        full_log = alert[ALERTS_FULL_LOG]
        file_name = event[SYSCHECK_DATA][SYSCHECK_PATH].rsplit('/', 1)[1]
        # Separation token that marks the part of the path that is lost
        assert '[...]' in full_log
        # File name is displayed correctly.
        assert file_name in full_log


def validate_mitre_event(event):
    """
    Check if a Mitre event is properly formatted.

    Args:
        event (dict): event generated by rule enhanced by MITRE.
    """
    with open(os.path.join(DATA_PATH, 'alerts_template', 'mitre_event.json'), 'r') as f:
        schema = json.load(f)
    validate(schema=schema, instance=event)


class CallbackWithContext(object):
    """Class to handle callbacks with variable arguments.

    Args:
        function (function): callback function.
        ctxt (*args): callback function non-keyword variable arguments.

    Attributes:
        function (function): callback function.
        ctxt (*args): callback function non-keyword variable arguments.
    """
    def __init__(self, function, *ctxt):
        self.ctxt = ctxt
        self.function = function

    def __call__(self, param):
        return self.function(param, *self.ctxt)


def callback_check_alert(alert, expected_alert):
    """Check if an alert meet certain criteria and values.
    Args:
        line (str): alert (json) to check.
        expected_alert (dict): values to check.
    Returns:
        True if line match the criteria. None otherwise
    """
    try:
        alert = json.loads(alert)
    except Exception:
        return None

    def dotget(dotdict, k):
        """Get value from dict using dot notation keys

        Args:
            dotdict (dict): dict to get value from
            k (str): dot-separated key.

        Returns:
            value of specified key. None otherwise
        """
        if '.' in k:
            key = k.split('.', 1)
            return dotget(dotdict[key[0]], key[1])
        else:
            return dotdict.get(k)

    for field in expected_alert.keys():
        current_value = dotget(alert, field)
        try:
            expected_value = json.loads(expected_alert[field])
            expected_value = expected_value if type(expected_value) is dict else str(expected_value)
        except ValueError as e:
            expected_value = str(expected_alert[field])

        if current_value != expected_value:
            return None

    return True


def get_analysisd_state():
    """Get the states values of wazuh-analysisd.state file

    Returns:
        dict: Dictionary with all analysisd state
    """
    data = ""
    with open(ANALYSISD_STATE, 'r') as file:
        for line in file.readlines():
            if not line.startswith("#") and not line.startswith('\n'):
                data = data + line.replace('\'', '')
    data = data[:-1]
    analysisd_state = dict((a.strip(), b.strip()) for a, b in (element.split('=') for element in data.split('\n')))

    return analysisd_state
