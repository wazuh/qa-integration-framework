# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from time import sleep
from wazuh_testing.constants.paths.sockets import LOGCOLLECTOR_SOCKET_PATH
from wazuh_testing.utils import sockets
from wazuh_testing.modules.logcollector import patterns
from wazuh_testing.tools.socket_controller import SocketController


def validate_test_config_with_module_config(test_configuration):
    """Assert if configuration values provided are the same that configuration provided for module response.

    Args:
        configuration (dict): Dictionary with test configuration.
    """

    for section in test_configuration['sections']:
        test_section = section['section']
        test_elements = section['elements']
        msg_request = f'getconfig {test_section}'
        response = sockets.send_request_socket(query = msg_request, socket_path = LOGCOLLECTOR_SOCKET_PATH)
        json_response = json.loads(response[3:])
        configuration_in_module = False

        test_config = dict()

        for I in test_elements:
            for key in I:
                if key == 'out_format':
                    out_format_list = list()
                    out_format_dict = dict()
                    if I[key].get('value'):
                        out_format_dict['format'] = I[key].pop('value')

                    if I[key].get('attributes'):
                        var = I[key].get('attributes')
                        out_format_dict = out_format_dict | var[0]

                    out_format_list.append(out_format_dict)
                    test_config[key] = out_format_list
                elif key == 'label':
                    label_dict = dict()
                    label_value = None
                    label_key = None
                    if I[key].get('value'):
                        label_value = I[key].pop('value')

                    if I[key].get('attributes'):
                        var = I[key].get('attributes')
                        label_key = var[0]['key']
                    label_dict[label_key] = label_value
                    test_config['labels'] = label_dict
                else:
                    test_config[key] = I[key]['value']

        if test_section == 'localfile':
            if test_config.get('target'):
                list_target = list()
                list_target.append(test_config.pop('target'))
                test_config['target'] = list_target

            for config in json_response[test_section]:

                if config.get('logformat'):
                    config['log_format'] = config.pop('logformat')
                if config.get('file'):
                    config['location'] = config.pop('file')
                if config.get('frequency'):
                    config['frequency'] = str(config.pop('frequency'))

                if all([config.get(key) == value for key, value in test_config.items()]):
                    configuration_in_module = True
        elif test_section == 'socket':
            for config in json_response['socket']:
                if all([config.get(key) == value for key, value in test_config.items()]):
                    configuration_in_module = True

        assert configuration_in_module, patterns.ERROR_CONFIGURATION


def check_logcollector_socket(timeout=10):
    """Assert if the internal logcollector socket is ready.

    Args:
        timeout: maximum time to wait for the socket to be ready.
    """
    socket_ready = False
    for i in range(0, timeout):
        try:
            connection = SocketController(address=LOGCOLLECTOR_SOCKET_PATH, family='AF_UNIX', timeout=timeout - i)
            connection.close()
            socket_ready = True
            break
        except (FileNotFoundError, ConnectionRefusedError):
            sleep(1)
        except TimeoutError:
            break

    assert socket_ready, "Logcollector socket is not ready"
