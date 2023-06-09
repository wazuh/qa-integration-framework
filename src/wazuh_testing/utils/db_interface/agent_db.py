import datetime
from time import time

from wazuh_testing.utils.db_interface.basic_queries import query_wdb


def insert_package(agent_id='000', scan_id=int(time()), format='rpm', name='custom-package-0',
                   priority='', section='Unspecified', size=99, vendor='wazuh-mocking', version='1.0.0-1.el7',
                   architecture='x64', multiarch='', description='Wazuh mocking packages', source='Wazuh QA tests',
                   location='', triaged='0', install_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                   scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"), checksum='dummychecksum',
                   item_id='dummyitemid'):
    """Insert a package in the agent DB.

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Last scan ID.
        format (str): Package format (deb, rpm, ...).
        name (str): Package name.
        priority (str): Released package priority.
        section (str): Package section.
        size (int): Package size.
        vendor (str): Package vendor.
        version (str): Package version.
        architecture (str): Package architecture.
        multiarch (str): Define if a package may be installed in different architectures.
        description (str): Package description.
        source (str): Package source.
        location (str): Package location.
        triaged (str): Times that the package has been installed.
        install_time (str): Installation timestamp.
        scan_time (str): Scan timestamp.
        checksum (str): Package checksum.
        item_id (str): Package ID.
    """
    arguments = locals()
    for key, value in arguments.items():
        if type(value) is str:
            if value != 'NULL':
                arguments[key] = f"'{value}'"

    query_wdb(f"agent {agent_id} sql INSERT INTO sys_programs (scan_id, scan_time, format, name, priority, section, "
              f"size, vendor, install_time, version, architecture, multiarch, source, description, location, triaged,"
              f"checksum, item_id) VALUES ({arguments['scan_id']}, {arguments['scan_time']}, {arguments['format']},"
              f"{arguments['name']}, {arguments['priority']}, {arguments['section']}, {arguments['size']},"
              f"{arguments['vendor']}, {arguments['install_time']}, {arguments['version']},"
              f"{arguments['architecture']}, {arguments['multiarch']}, {arguments['source']}, "
              f"{arguments['description']}, {arguments['location']}, {arguments['triaged']}, {arguments['checksum']},"
              f"{arguments['item_id']})")


def update_sync_info(agent_id='000', component='syscollector-packages', last_attempt=1, last_completion=1,
                     n_attempts=0, n_completions=0, last_agent_checksum=''):
    """Update the sync_info table of the specified agent for the selected component.

    Args:
        agent_id (str): Agent ID.
        component (str): Name of the component package.
        last_attempt (int): Last attempt of query
        last_completion (int): Last completion package
        n_attempts (int): Number of attempt.
        n_completions (int): Number of completion packets.
        last_agent_checksum (str): Checksum of the last agent registered.
    """
    query_wdb(f"agent {agent_id} sql UPDATE sync_info SET last_attempt = {last_attempt},"
              f"last_completion = {last_completion}, n_attempts = {n_attempts}, n_completions = {n_completions},"
              f"last_agent_checksum = '{last_agent_checksum}' where component = '{component}'")


def insert_vulnerability_in_agent_inventory(agent_id='000', name='', version='', architecture='', cve='',
                                            detection_time='', severity='None', cvss2_score=0, cvss3_score=0,
                                            reference='', type='PACKAGE', status='PENDING', external_references='',
                                            condition='', title='', published='', updated=''):
    """Insert a vulnerability in the agent vulnerabilities inventory.

    Args:
        agent_id (str): Agent ID.
        name (str): Vulnerability name.
        version (str): Version.
        architecture (str): Architecture.
        cve (str): Vulnerability CVE.
        detection_time (str): Vulnerability detection time.
        severity (str): Vulnerability severity.
        cvss2_score (float): CVSS2 score.
        cvss3_score (float): CVSS3 score
        reference (str): Vulnerability reference.
        type (str): Vulnerability type.
        status (str): Vulnerability status.
        external_references (str): Vulnerability external reference.
        condition (str): Vulnerability condition.
        title (str): Vulnerability title.
        published (str): Vulnerability published.
        updated (str): Vulnerability updated.
    """
    query_wdb(f"agent {agent_id} sql INSERT OR REPLACE INTO vuln_cves (name, version, architecture, cve, "
              f"detection_time, severity, cvss2_score, cvss3_score, reference, type, status, external_references,"
              f" condition, title, published, updated) VALUES ('{name}', '{version}', '{architecture}', '{cve}', "
              f"'{detection_time}', '{severity}', {cvss2_score}, {cvss3_score},'{reference}', '{type}', '{status}', "
              f"'{external_references}', '{condition}', '{title}', '{published}', '{updated}')")