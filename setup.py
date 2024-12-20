"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import shutil

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
    'data/statistics_template/agent_statistics_format_test_module/wazuh-analysisd_template.json',
    'data/statistics_template/agent_statistics_format_test_module/wazuh-remoted_template.json',
    'data/statistics_template/manager_statistics_format_test_module/wazuh-analysisd_template.json',
    'data/statistics_template/manager_statistics_format_test_module/wazuh-db_template.json',
    'data/statistics_template/manager_statistics_format_test_module/wazuh-remoted_template.json',
    'data/feeds/alas/custom_alas2_feed.json',
    'data/feeds/alas/custom_alas_2022_feed.json',
    'data/feeds/alas/custom_alas_feed.json',
    'data/feeds/arch/custom_archlinux_feed.json',
    'data/feeds/canonical/custom_canonical_oval_feed.xml',
    'data/feeds/cpe_helper/custom_cpe_helper_template.json',
    'data/feeds/cpe_helper/custom_cpe_helper.json',
    'data/feeds/cpe_helper/custom_generic_cpe_helper_one_package.json',
    'data/feeds/debian/custom_debian_json_feed.json',
    'data/feeds/debian/custom_debian_oval_feed.xml',
    'data/feeds/msu/custom_msu.json',
    'data/feeds/nvd/custom_nvd_alternative_feed.json',
    'data/feeds/nvd/custom_nvd_feed.json',
    'data/feeds/nvd/real_nvd_feed.json',
    'data/feeds/redhat/custom_redhat_json_feed.json',
    'data/feeds/redhat/custom_redhat_oval_feed.xml',
    'data/feeds/suse/custom_suse_oval_feed.xml',
    'data/feeds/suse/custom_suse_oval_feed.xml.bz2',
    'data/feeds/suse/custom_suse_oval_feed.xml.gz',
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


setup(
    name='wazuh_testing',
    version='4.12.0',
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
