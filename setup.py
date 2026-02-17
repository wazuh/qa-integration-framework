"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import shutil

import json
from pathlib import Path
from setuptools import setup, find_packages
from typing import List


# Extra data.
package_data_list = [
    'data/alerts_template/analysis_alert.json',
    'data/alerts_template/analysis_alert_windows.json',
    'data/alerts_template/mitre_event.json',
    'data/configuration_template/all_disabled_ossec.conf',
    'data/configuration_template/agent.conf',
    'data/events_template/keepalives.txt',
    'data/events_template/rootcheck.txt',
    'data/statistics_template/agent_statistics_format_test_module/wazuh-manager-analysisd_template.json',
    'data/statistics_template/agent_statistics_format_test_module/wazuh-manager-remoted_template.json',
    'data/statistics_template/cluster_statistics_format_test_module/wazuh-manager-analysisd_template.json',
    'data/statistics_template/cluster_statistics_format_test_module/wazuh-manager-db_template.json',
    'data/statistics_template/cluster_statistics_format_test_module/wazuh-manager-remoted_template.json',
]

# Entry point scripts.
scripts_list = []


def get_install_requires() -> List[str]:
    """Returns requirements.txt parsed to a list"""
    fname = Path(__file__).parent / 'requirements.txt'
    targets = []
    if fname.exists():
        with open(fname, 'r') as f:
            targets = f.read().splitlines()
    return targets


def get_version_from_json() -> str:
    version_file = 'VERSION.json'

    fname = Path(__file__).parent / version_file
    with open(fname, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data.get("version", "")


setup(
    name='wazuh_testing',
    version=get_version_from_json(),
    description='Wazuh testing utilities to help programmers automate tests',
    url='https://github.com/wazuh',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    packages=find_packages(where='src'),
    package_dir={'wazuh_testing': 'src/wazuh_testing'},
    package_data={'wazuh_testing': package_data_list},
    python_requires='>=3.8',
    install_requires=get_install_requires(),
    entry_points={'console_scripts': scripts_list},
    include_package_data=True,
    zip_safe=False
)

# Clean build files
shutil.rmtree('src/dist', ignore_errors=True)
shutil.rmtree('src/build', ignore_errors=True)
shutil.rmtree('src/wazuh_testing.egg-info', ignore_errors=True)
