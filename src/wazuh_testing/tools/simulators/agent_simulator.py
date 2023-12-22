#!/usr/bin/python
# Wazuh agents load simulator
# Copyright (C) 2015-2023, Wazuh Inc.
# January 28, 2020.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Python 3.7 or greater
# Dependencies: pip3 install pycryptodome
import json
import logging
import os
import socket
import ssl
import threading
import subprocess as sb
from pathlib import Path
from datetime import date
from itertools import cycle
from queue import Queue
from random import randint, sample, choice, getrandbits
from stat import S_IFLNK, S_IFREG, S_IRWXU, S_IRWXG, S_IRWXO
from string import ascii_letters, digits
from struct import pack
from sys import getsizeof
from time import mktime, localtime, sleep, time
from typing import Tuple

from wazuh_testing import DATA_PATH
from wazuh_testing.utils import secure_message
from wazuh_testing.utils.database import query_wdb
from wazuh_testing.utils.decorators import retry
from wazuh_testing.utils.network import TCP, UDP, is_udp, is_tcp
from wazuh_testing.utils.random import get_random_ip, get_random_string
from wazuh_testing.constants.paths import WAZUH_PATH

os_list = ["debian7", "debian8", "debian9", "debian10", "ubuntu12.04",
           "ubuntu14.04", "ubuntu16.04", "ubuntu18.04", "mojave", "solaris11"]
agent_count = 1

SYSCOLLECTOR_HEADER = '{"type":"<syscollector_type>",' \
                      '"ID":<random_int>,"timestamp":"<timestamp>"'

SYSCOLLECTOR_OS_EVENT_TEMPLATE = ',"inventory":{"os_name":"<random_string>",' \
                                 '"os_major":"8","os_minor":"3","os_version":"8.3",' \
                                 '"os_platform":"centos","sysname":"Linux",' \
                                 '"hostname":"centos3","release":"4.18.0-240.1.1.el8_3.x86_64",' \
                                 '"version":"#1 SMP Thu Nov 19 17:20:08 UTC 2020","architecture":"x86_64"}}'

SYSCOLLECTOR_HARDWARE_EVENT_TEMPLATE = ',"inventory":{"board_serial":"0",' \
                                       '"cpu_name":"AMD Ryzen 7 3750H with Radeon Vega Mobile Gfx",' \
                                       '"cpu_cores":<random_int>,"cpu_MHz":2295.686,"ram_total":828084,' \
                                       '"ram_free":60488,"ram_usage":93}}'

SYSCOLLECTOR_PACKAGES_EVENT_TEMPLATE = ',"program":{"format":"rpm","name":"<random_string>",' \
                                       '"description":"JSON::XS compatible pure-Perl module",' \
                                       '"size":126,"vendor":"CentOS","group":"Unspecified",' \
                                       '"architecture":"noarch","source":"perl-JSON-PP-2.97.001-3.el8.src.rpm",' \
                                       '"install_time":"2021/03/12 12:23:17"' \
                                       ',"version":"1:2.97.001-3.el8"}}'

SYSCOLLECTOR_PROCESS_EVENT_TEMPLATE = ',"process":{"pid":3150,"name":"<random_string>","state":"R",' \
                                      '"ppid":2965,"utime":58,' \
                                      '"stime":2,"cmd":"rpm","argvs":["-qa","xorg-x11*"],' \
                                      '"euser":"root","ruser":"root","suser":"root","egroup":"ossec",' \
                                      '"rgroup":"ossec","sgroup":"ossec",' \
                                      '"fgroup":"ossec","priority":30,' \
                                      '"nice":10,"size":22681,"vm_size":90724,' \
                                      '"resident":5626,"share":2262,' \
                                      '"start_time":21863,"pgrp":3150,' \
                                      '"session":3150,"nlwp":1,' \
                                      '"tgid":3150,"tty":0,"processor":0}}'

SYSCOLLECTOR_NETWORK_EVENT_TEMPLATE = ',"iface":{"name":"<random_string>","type":"ethernet","state":"up",' \
                                      '"MAC":"08:00:27:be:ce:3a","tx_packets":2135,' \
                                      '"rx_packets":9091,"tx_bytes":210748,' \
                                      '"rx_bytes":10134272,"tx_errors":0,' \
                                      '"rx_errors":0,"tx_dropped":0,"rx_dropped":0,' \
                                      '"MTU":1500,"IPv4":{"address":["10.0.2.15"],' \
                                      '"netmask":["255.255.255.0"],"broadcast":["10.0.2.255"],' \
                                      '"metric":100,"gateway":"10.0.2.2","DHCP":"enabled"}}}'

SYSCOLLECTOR_PORT_EVENT_TEMPLATE = ',"port":{"protocol":"tcp","local_ip":"0.0.0.0",' \
                                   '"local_port":<random_int>,"remote_ip":"0.0.0.0",' \
                                   '"remote_port":0,"tx_queue":0,' \
                                   '"rx_queue":0,"inode":22273,"state":"listening"}}'

SYSCOLLECTOR_HOTFIX_EVENT_TEMPLATE = ',"hotfix":"<random_string>"}'

WINEVT_SECURITY = "{\"Message\":\"System audit policy was changed.\r\n\r\nSubject:\r\n\t" \
                  "Security ID:\t\tS-1-5-21-1331263578-1683884876-2739179494-500\r\n\t" \
                  "Account Name:\t\tAdministrator\r\n\tAccount Domain:\t\tWIN-ACL01C4DS88\r\n\t" \
                  "Logon ID:\t\t0x372C7\r\n\r\nAudit Policy Change:\r\n\t" \
                  "Category:\t\tPolicy Change\r\n\tSubcategory:\t\t" \
                  "Filtering Platform Policy Change\r\n\t" \
                  "Subcategory GUID:\t{0cce9233-69ae-11d9-bed3-505054503030}\r\n\t" \
                  "Changes:\t\tSuccess Added, Failure added\"," \
                  "\"Event\":\"<Event xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'>" \
                  "<System><Provider Name=\'Microsoft-Windows-Security-Auditing\' " \
                  "Guid=\'{54849625-5478-4994-a5ba-3e3b0328c30d}\'/>" \
                  f"<EventID><random_int></EventID><Version>0</Version><Level>0</Level>" \
                  "<Task>13568</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords>" \
                  "<TimeCreated SystemTime=\'2019-05-28T09:29:41.443963000Z\'/><EventRecordID>965047" \
                  "</EventRecordID><Correlation ActivityID=\'{1115b961-1535-0000-8bbb-15113515d501}\'/>" \
                  "<Execution ProcessID=\'556\' ThreadID=\'6024\'/><Channel>Security</Channel>" \
                  "<Computer>WIN-ACL01C4DS88</Computer><Security/></System><EventData>" \
                  "<Data Name=\'SubjectUserSid\'>S-1-5-21-1331263578-1683884876-2739179494-500</Data>" \
                  "<Data Name=\'SubjectUserName\'>Administrator</Data>" \
                  "<Data Name=\'SubjectDomainName\'>WIN-ACL01C4DS88</Data>" \
                  "<Data Name=\'SubjectLogonId\'>0x372c7</Data>" \
                  "<Data Name=\'CategoryId\'>%%8277" \
                  "</Data><Data Name=\'SubcategoryId\'>%%13572</Data>" \
                  "<Data Name=\'SubcategoryGuid\'>{0cce9233-69ae-11d9-bed3-505054503030}</Data" \
                  "><Data Name=\'AuditPolicyChanges\'>%%8449, %%8451</Data></EventData></Event>\"}"

WINEVT_APPLICATION = "{\"Message\":\"The Desktop Window Manager has registered the session port.\",\"Event\":\"" \
                     "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" \
                     "<Provider Name='Desktop Window Manager'/><EventID Qualifiers='16384'><random_int></EventID>" \
                     "<Level>4</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated " \
                     "SystemTime='2021-03-26T09:41:26.382493000Z'/><EventRecordID>946</EventRecordID>" \
                     "<Channel>Application</Channel><Computer>vagrant-2016</Computer><Security/></System>" \
                     "<EventData></EventData></Event>\"}"

WINEVT_SYSTEM = "{\"Message\":\"The sppsvc service entered the running state.\",\"Event\":\"<Event " \
                  "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" \
                  "<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' " \
                  "EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'><random_int></EventID>" \
                  "<Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000" \
                  "</Keywords><TimeCreated SystemTime='2021-03-25T15:01:00.656299500Z'/><EventRecordID>3946" \
                  "</EventRecordID><Correlation/><Execution ProcessID='572' ThreadID='652'/><Channel>" \
                  "System</Channel><Computer>vagrant-2016</Computer><Security/></System><EventData>" \
                  "<Data Name='param1'>sppsvc</Data><Data Name='param2'>running</Data><Binary>" \
                  "7300700070007300760063002F0034000000</Binary></EventData></Event>\"}"

WINEVT_SYSMON = "{\"Message\":\"File creation time changed:\r\nRuleName: T1099\r\nUtcTime: " \
                "2021-03-25 15:04:03.302\r\nProcessGuid: {A5A24D70-A630-605C-8C00-000000000F00}\r\nProcessId: " \
                r"2020\r\nImage: C:\\Users\\Administrator\\AppData\\Local\\Programs\\Opera\\74.0.3911.232\\opera.exe" \
                "\r\nTargetFilename: " r"C:\\Users\\Administrator\\AppData\\Roaming\\Opera Software\\Opera Stable" \
                r"\\" "bc0808a3-2f49-487c-8ae3-325cf7658646.tmp\r\nCreationUtcTime: 2021-03-23 07:56:11.597" \
                "\r\nPreviousCreationUtcTime: 2021-03-25 15:04:03.302\",\"Event\":\"<Event " \
                "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" \
                "<System><Provider Name='Microsoft-Windows-Sysmon' " \
                "Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>" \
                "<EventID><random_int></EventID><Version>5</Version><Level>4</Level><Task>2</Task>" \
                "<Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated " \
                "SystemTime='2021-03-25T15:04:03.320848900Z'/><EventRecordID>4033</EventRecordID>" \
                "<Correlation/><Execution ProcessID='2044' ThreadID='2692'/>" \
                "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>" \
                "<Computer>vagrant-2016</Computer><Security UserID='S-1-5-18'/>" \
                "</System><EventData><Data Name='RuleName'>T1099</Data><Data Name='UtcTime'>2021-03-25 " \
                "15:04:03.302</Data><Data Name='ProcessGuid'>{A5A24D70-A630-605C-8C00-000000000F00}" \
                "</Data><Data Name='ProcessId'>2020</Data><Data Name='Image'>" \
                r"C:\\Users\\Administrator\\AppData\\Local\\Programs\\Opera\\74.0.3911.232\\opera.exe" \
                r"</Data><Data Name='TargetFilename'>C:\\Users\\Administrator\\AppData\\Roaming\\Opera Software\\" \
                r"Opera Stable\\bc0808a3-2f49-487c-8ae3-325cf7658646.tmp</Data><Data Name='CreationUtcTime'>" \
                "2021-03-23 07:56:11.597</Data><Data Name='PreviousCreationUtcTime'>2021-03-25 15:04:03.302" \
                "</Data></EventData></Event>\"}"

WINEVT_WINDOWS_DEFENDER = "{\"Message\":\"Windows Defender scan has started.\r\n \tScan ID: " \
                           "{6E6187EE-21DF-4CC6-B0FA-42E2ADF201DE}\r\n \tScan Type: " \
                           "Antimalware\r\n \tScan Parameters: Quick Scan\r\n \tScan " \
                           r"Resources: \r\n \tUser: VAGRANT-2016\\Administrator" "\"," \
                           "\"Event\":\"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" \
                           "<System><Provider Name='Microsoft-Windows-Windows Defender' " \
                           "Guid='{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}'/><EventID><random_int>" \
                           "</EventID><Version>0</Version><Level>4</Level>" \
                           "<Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>" \
                           "<TimeCreated SystemTime='2021-03-25T15:07:51.586512400Z'/>" \
                           "<EventRecordID>76</EventRecordID><Correlation/>" \
                           "<Execution ProcessID='1856' ThreadID='3960'/>" \
                           "<Channel>Microsoft-Windows-Windows Defender/Operational" \
                           "</Channel><Computer>vagrant-2016</Computer><Security UserID='S-1-5-18'/></System>" \
                           "<EventData><Data Name='Product Name'>%%827</Data>" \
                           "<Data Name='Product Version'>4.10.14393.1198</Data>" \
                           "<Data Name='Scan ID'>{6E6187EE-21DF-4CC6-B0FA-42E2ADF201DE}</Data>" \
                           "<Data Name='Scan Type Index'>1</Data><Data Name='Scan Type'>%%802" \
                           "</Data><Data Name='Scan Parameters Index'>1</Data>" \
                           "<Data Name='Scan Parameters'>%%806</Data>" \
                           "<Data Name='Domain'>VAGRANT-2016</Data><Data Name='User'>Administrator</Data>" \
                           "<Data Name='SID'>S-1-5-21-3914780927-2846412080-4247273094-500</Data>" \
                           "<Data Name='Scan Resources'></Data></EventData></Event>\"}"


class Agent:
    """Class that allows us to simulate an agent registered in a manager.
    This simulated agent allows sending-receiving messages and commands. In order to simulate
    syscollector, FIM, FIM Integrity, rootcheck, hostinfo, winevt and logcollector modules the following classes have
    been created: GeneratorSyscollector, GeneratorFIM, GeneratorIntegrityFIM, Rootcheck,
    GeneratorHostinfo, GeneratorWinevt, Logcollector.
    Args:
        manager_address (str): Manager IP address.
        cypher (str, optional): Cypher method. It can be [aes, blowfish]. Default aes.
        os (str, optional): Agent operating system. Default None for choosing randomly.
        rootcheck_sample (str, optional): File where are sample rootcheck messages.
        id (str, optional): ID of the agent. Specify only if it already exists.
        name (str, optional): Agent name. Specify only if it already exists.
        key (str, optional): Client key. Specify only if it already exists.
        version (str, optional): Wazuh agent version. Default v3.12.0.
        labels (dict, optional): Wazuh agent labels. Each dict key will be a new label.
        fim_eps (int, optional): Set the maximum event reporting throughput. Events are messages that will produce an
                                 alert.
        fim_integrity_eps (int, optional): Set the maximum database synchronization message throughput.
        authd_password (str), optional: Password for registration if needed.
        registration_address (str, optional): Manager registration IP address.
        retry_enrollment (bool, optional): retry then enrollment in case of error.
        logcollector_msg_number (bool, optional): insert in the logcollector message the message number.
        custom_logcollector_message (str): Custom logcollector message to be sent by the agent.
    Attributes:
        id (str): ID of the agent.
        name (str): Agent name.
        key (str): Agent key. Used for creating an encryption_key.
        long_version (str): Agent version in format x.y.z
        short_version (str): Agent version in format x.y
        cypher (str): Encryption method for message communication.
        os (str): Agent operating system.
        fim_eps (int): Fim's maximum event reporting throughput. Default `1000`.
        fim_integrity_eps (int): Fim integrity's maximum event reporting throughput. Default `100`.
        syscollector_eps (int): Syscollector's maximum event reporting throughput. Default `100`.
        rootcheck_eps (int): Rootcheck's maximum event reporting throughput. Default `100`.
        hostinfo_eps (int): Hostinfo's maximum event reporting throughput. Default `100`.
        winevt_eps (float): Winevt's maximum event reporting throughput. Default `100`.
        logcollector_eps (float): Logcollector's maximum event reporting throughput. Default `100`.
        sca_eps (float): sca_label's maximum event reporting throughput. Default `100`.
        manager_address (str): Manager IP address.
        encryption_key (bytes): Encryption key used for encrypt and decrypt the message.
        keep_alive_event (bytes): Keep alive event (read from template data according to OS and parsed to an event).
        keep_alive_raw_msg (string): Keep alive event in plain text.
        merged_checksum (string): Checksum of agent's merge.mg file.
        startup_msg (bytes): Startup event sent before the first keep alive event.
        authd_password (str): Password for manager registration.
        rootcheck_sample (str): File where are sample rootcheck messages.
        rootcheck (Rootcheck): Object to simulate rootcheck message events.
        fim (GeneratorFIM): Object to simulate FIM message events.
        fim_integrity (GeneratorIntegrityFIM): Object to simulate FIM integrity message events.
        modules (dict): Agent modules with their associated configuration info.
        sha_key (str): Shared key between manager and agent for remote upgrading.
        upgrade_exec_result (int): Upgrade result status code.
        send_upgrade_notification (boolean): If True, it will be sent the upgrade status message after "upgrading".
        upgrade_script_result (int): Variable to mock the upgrade script result. Used for simulating a remote upgrade.
        stop_receive (int): Flag to determine when to activate and deactivate the agent event listener.
        stage_disconnect (str): WPK process state variable.
        rcv_msg_limit (int): max elements for the received message queue.
        rcv_msg_queue (queue.Queue): Queue to store received messages in the agent.
        disable_all_modules (boolean): Disable all simulated modules for this agent.
        rootcheck_frequency (int): frequency to run rootcheck scans. 0 to continuously send rootcheck events.
        syscollector_frequency (int): frequency to run syscollector scans. 0 to continuously send syscollector events.
        keepalive_frequency (int): frequency to send keepalive messages. 0 to continuously send keepalive messages.
        sca_frequency (int): frequency to run sca_label scans. 0 to continuously send sca_label events.
        syscollector_batch_size (int): Size of the syscollector type batch events.
        fixed_message_size (int): Fixed size of the agent modules messages in KB.
        registration_address (str): Manager registration IP address.
    """
    def __init__(self, manager_address, cypher="aes", os=None, rootcheck_sample=None, id=None, name=None, key=None,
                 version="v4.3.0", fim_eps=100, fim_integrity_eps=100, sca_eps=100, syscollector_eps=100, labels=None,
                 rootcheck_eps=100, logcollector_eps=100, authd_password=None, disable_all_modules=False,
                 rootcheck_frequency=60.0, rcv_msg_limit=0, keepalive_frequency=10.0, sca_frequency=60,
                 syscollector_frequency=60.0, syscollector_batch_size=10, hostinfo_eps=100, winevt_eps=100,
                 fixed_message_size=None, registration_address=None, retry_enrollment=False,
                 logcollector_msg_number=None, custom_logcollector_message=''):
        self.id = id
        self.name = name
        self.key = key
        if version is None:
            version = "v3.13.2"
        self.long_version = version
        ver_split = version.replace("v", "").split(".")
        self.short_version = f"{'.'.join(ver_split[:2])}"
        self.labels = labels
        self.cypher = cypher
        self.os = os
        self.fim_eps = fim_eps
        self.fim_integrity_eps = fim_integrity_eps
        self.syscollector_eps = syscollector_eps
        self.rootcheck_eps = rootcheck_eps
        self.logcollector_eps = logcollector_eps
        self.winevt_eps = winevt_eps
        self.sca_eps = sca_eps
        self.hostinfo_eps = hostinfo_eps
        self.rootcheck_frequency = rootcheck_frequency
        self.sca_frequency = sca_frequency
        self.keepalive_frequency = keepalive_frequency
        self.syscollector_frequency = syscollector_frequency
        self.manager_address = manager_address
        self.registration_address = manager_address if registration_address is None else registration_address
        self.encryption_key = ""
        self.keep_alive_event = ""
        self.keep_alive_raw_msg = ""
        self.merged_checksum = 'd6e3ac3e75ca0319af3e7c262776f331'
        self.startup_msg = ""
        self.authd_password = authd_password
        self.sca = None
        self.logcollector = None
        self.syscollector_batch_size = syscollector_batch_size
        self.rootcheck_sample = rootcheck_sample
        self.rootcheck = None
        self.hostinfo = None
        self.winevt = None
        self.fim = None
        self.fim_integrity = None
        self.syscollector = None
        self.modules = {
            'keepalive': {'status': 'enabled', 'frequency': self.keepalive_frequency},
            'fim': {'status': 'enabled', 'eps': self.fim_eps},
            'fim_integrity': {'status': 'disabled', 'eps': self.fim_integrity_eps},
            'syscollector': {'status': 'disabled', 'frequency': self.syscollector_frequency,
                             'eps': self.syscollector_eps},
            'rootcheck': {'status': 'disabled', 'frequency': self.rootcheck_frequency, 'eps': self.rootcheck_eps},
            'sca': {'status': 'disabled', 'frequency': self.sca_frequency, 'eps': self.sca_eps},
            'hostinfo': {'status': 'disabled', 'eps': self.hostinfo_eps},
            'winevt': {'status': 'disabled', 'eps': self.winevt_eps},
            'logcollector': {'status': 'disabled', 'eps': self.logcollector_eps},
            'receive_messages': {'status': 'enabled'},
        }
        self.sha_key = None
        self.upgrade_exec_result = None
        self.send_upgrade_notification = False
        self.upgrade_script_result = 0
        self.stop_receive = 0
        self.stage_disconnect = None
        self.retry_enrollment = retry_enrollment
        self.rcv_msg_queue = Queue(rcv_msg_limit)
        self.fixed_message_size = fixed_message_size * 1024 if fixed_message_size is not None else None
        self.logcollector_msg_number = logcollector_msg_number
        self.custom_logcollector_message = custom_logcollector_message
        self.setup(disable_all_modules=disable_all_modules)

    def update_checksum(self, new_checksum):
        self.keep_alive_raw_msg = self.keep_alive_raw_msg.replace(self.merged_checksum, new_checksum)
        self.keep_alive_event = self.create_event(self.keep_alive_raw_msg)
        self.merged_checksum = new_checksum

    def setup(self, disable_all_modules):
        """Set up agent: os, registration, encryption key, start up msg and activate modules."""
        self.set_os()

        if self.id is None and self.name is None and self.key is None:
            self.set_name()
            self.register()
        elif any([self.id, self.name, self.key]) and not all([self.id, self.name, self.key]):
            raise ValueError("All the parameters [id, name, key] have to be specified together")

        self.encryption_key = secure_message.get_encryption_key(self.id, self.name, self.key)
        self.create_keep_alive()
        self.create_hc_startup()
        self.initialize_modules(disable_all_modules)

    def set_os(self):
        """Pick random OS from a custom os list."""
        if self.os is None:
            self.os = os_list[agent_count % len(os_list) - 1]

    def set_wpk_variables(self, sha=None, upgrade_exec_result=None, upgrade_notification=False, upgrade_script_result=0,
                          stage_disconnect=None):
        """Set variables related to wpk simulated responses.
        Args:
            sha (str): Shared key between manager and agent for remote upgrading.
            upgrade_exec_result (int): Upgrade result status code.
            upgrade_notification (boolean): If True, it will be sent the upgrade status message after "upgrading".
            upgrade_script_result (int): Variable to mock the upgrade script result. Used for simulating a remote
                                         upgrade.
            stage_disconnect (str): WPK process state variable.
        """
        self.sha_key = sha
        self.upgrade_exec_result = upgrade_exec_result
        self.send_upgrade_notification = upgrade_notification
        self.upgrade_script_result = upgrade_script_result
        self.stage_disconnect = stage_disconnect

    def set_name(self):
        """Set a random agent name."""
        random_string = ''.join(sample(f"0123456789{ascii_letters}", 16))
        self.name = f"{agent_count}-{random_string}-{self.os}"

    def _register_helper(self):
        """Helper function to enroll an agent."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            ssl_socket = context.wrap_socket(sock, server_hostname=self.registration_address)
            ssl_socket.connect((self.registration_address, 1515))

            if self.authd_password is None:
                event = f"OSSEC A:'{self.name}'\n".encode()
            else:
                event = f"OSSEC PASS: {self.authd_password} OSSEC A:'{self.name}'\n".encode()

            ssl_socket.send(event)
            recv = ssl_socket.recv(4096)
            registration_info = recv.decode().split("'")[1].split(" ")

            self.id = registration_info[0]
            self.key = registration_info[3]
        finally:
            ssl_socket.close()
            sock.close()

        logging.debug(f"Registration - {self.name}({self.id}) in {self.registration_address}")

    def register(self):
        """Request to register the agent in the manager.
        In addition, it sets the agent id and agent key with the response data.
        """
        if self.retry_enrollment:
            retries = 20
            while retries >= 0:
                try:
                    self._register_helper()
                except Exception:
                    retries -= 1
                    sleep(6)
                else:
                    break
            else:
                raise ValueError(f"The agent {self.name} was not correctly enrolled.")
        else:
            self._register_helper()

    def headers(self, agent_id, encrypted_event):
        """Add event headers for AES or Blowfish Cyphers.

        Args:
            agent_id (str): Agent id.
            encrypted_event (bytes): Encrypted event.
        Returns:
            bytes: Encrypted event with headers.
        """
        header = secure_message.ALGORITHM_HEADERS[self.cypher.upper()]
        header = f"!{agent_id}!{header.decode()}".encode()

        return header + encrypted_event

    def create_event(self, message):
        """Build an event from a raw string message.
        Args:
            message (str): Raw message.
        Returns:
            bytes: Built event (compressed, padded, encrypted and with headers).
        Examples:
            >>> create_event('test message')
            b'!005!#AES:\\xab\\xfa\\xcc2;\\x87\\xab\\x7fUH\\x03>_J\\xda=I\\x96\\xb5\\xa4\\x89\\xbe\\xbf`\\xd0\\xad
            \\x03\\x06\\x1aN\\x86 \\xc2\\x98\\x93U\\xcc\\xf5\\xe3@%\\xabS!\\xd3\\x9d!\\xea\\xabR\\xf9\\xd3\\x0b\\
            xcc\\xe8Y\\xe31*c\\x17g\\xa6M\\x0b&\\xc0>\\xc64\\x815\\xae\\xb8[bg\\xe3\\x83\\x0e'
        """
        encoded_message = secure_message.encode(message.encode())
        # Encrypt
        encrypted_event = secure_message.encrypt(encoded_message, self.encryption_key, self.cypher)
        # Add headers
        headers_event = self.headers(self.id, encrypted_event)

        return headers_event

    def receive_message(self, sender):
        """Agent listener to receive messages and process the accepted commands.
        Args:
            sender (Sender): Object to establish connection with the manager socket and receive/send information.
        """
        while self.stop_receive == 0:
            if is_tcp(sender.protocol):
                try:
                    rcv = sender.socket.recv(4)
                    if len(rcv) == 4:
                        data_len = secure_message.unpack(rcv)
                        buffer_array = sender.socket.recv(data_len)
                        if data_len != len(buffer_array):
                            continue
                    else:
                        continue
                except MemoryError:
                    logging.critical(f"Memory error, trying to allocate {data_len}.")
                    return
                except Exception:
                    return
            else:
                buffer_array, _ = sender.socket.recvfrom(65536)
            index = buffer_array.find(b'!')
            if index == 0:
                index = buffer_array[1:].find(b'!')
                buffer_array = buffer_array[index + 2:]
            if self.cypher == "aes":
                msg_remove_header = bytes(buffer_array[5:])
            else:
                msg_remove_header = bytes(buffer_array[1:])

            msg_decrypted = secure_message.decrypt(msg_remove_header, self.encryption_key, self.cypher)

            msg_decoded = secure_message.decode(msg_decrypted)
            self.process_message(sender, msg_decoded)

    def stop_receiver(self):
        """Stop Agent listener."""
        self.stop_receive = 1

    def process_message(self, sender, message):
        """Process agent received messages.
        If the message contains reserved words, then it will be proceed as command.
        Args:
            sender (Sender): Object to establish connection with the manager socket and receive/send information.
            message (str): Decoder message in ISO-8859-1 format.
        """
        msg_decoded_list = message.split(' ')
        self.rcv_msg_queue.put(message)
        if '#!-req' in msg_decoded_list[0]:
            self.process_command(sender, msg_decoded_list)
        elif '#!-up' in msg_decoded_list[0]:
            kind, checksum, name = msg_decoded_list[1:4]
            if kind == 'file' and "merged.mg" in name:
                self.update_checksum(checksum)
        elif '#!-force_reconnect' in msg_decoded_list[0]:
            sender.reconnect(self.startup_msg)

    def process_command(self, sender, message_list):
        """Process agent received commands through the socket.
        Args:
            sender (Sender): Object to establish connection with the manager socket and receive/send information.
            message_list (list): Message split by white spaces.
        Raises:
            ValueError: if 'sha1' command and sha_key Agent value is not defined.
            ValueError: if execution result is not configured in the Agent.
            ValueError: if command is not recognized.
        """

        req_code = message_list[1]

        if 'com' in message_list:
            """Examples:
            ['12d95abf04334f90f8dc3140031b3e7b342680000000130:5489:#!-req', '81d15486', 'com', 'close',
                'wazuh_agent_v4.2.0_linux_x86_64.wpk']
            ['dff5324c331a37d56978f7f034f2634e599120000000130:5490:#!-req', '81d15487', 'com', 'sha1',
                'wazuh_agent_v4.2.0_linux_x86_64.wpk']
            ['8c0e7a8d75fea76016040ce436f9fb41193290000000130:5491:#!-req', '81d15488', 'com', 'upgrade',
                'wazuh_agent_v4.2.0_linux_x86_64.wpk', 'upgrade.sh']
            """
            com_index = message_list.index('com')
            command = message_list[com_index + 1]

        elif 'upgrade' in message_list:
            """Examples:
            ['5e085e566814750136f3926f758349cb232030000000130:5492:#!-req', '81d15489', 'upgrade',
                '{"command":"clear_upgrade_result","parameters":{}}']
            """
            com_index = message_list.index('upgrade')
            json_command = json.loads(message_list[com_index + 1])
            command = json_command['command']
        elif 'getconfig' in message_list:
            """Examples:
            ['ececac937b8e5dead15e9096e8bd5215214970000000002:3090:#!-req', 'c2b2c9e3', 'agent', 'getconfig', 'client']
            """
            command = 'getconfig'
        elif 'getstate' in message_list:
            """Examples:
            ['ececac937b8e5dead15e9096e8bd5215214970000000002:3090:#!-req', 'c2b2c9e3', 'logcollector', 'getstate']
            """
            command = 'getstate'
        else:
            return

        logging.debug(f"Processing command: {message_list}")

        if command in ['lock_restart', 'open', 'write', 'close', 'clear_upgrade_result']:
            if command == 'lock_restart' and self.stage_disconnect == 'lock_restart':
                self.stop_receive = 1
            elif command == 'open' and self.stage_disconnect == 'open':
                self.stop_receive = 1
            elif command == 'write' and self.stage_disconnect == 'write':
                self.stop_receive = 1
            elif command == 'close' and self.stage_disconnect == 'close':
                self.stop_receive = 1
            elif command == 'clear_upgrade_result' and self.stage_disconnect == 'clear_upgrade_result':
                self.stop_receive = 1
            else:
                if self.short_version < "4.1" or command == 'lock_restart':
                    sender.send_event(self.create_event(f'#!-req {req_code} ok '))
                else:
                    sender.send_event(self.create_event(f'#!-req {req_code} '
                                                        f'{{"error":0, "message":"ok", "data":[]}} '))
        elif command == 'getconfig':
            response_json = '{"client":{"config-profile":"centos8","notify_time":10,"time-reconnect":60}}'
            sender.send_event(self.create_event(f'#!-req {req_code} ok {response_json}'))
        elif command == 'getstate':
            response_json = '{"error":0,"data":{"global":{"start":"2021-02-26, 06:41:26","end":"2021-02-26 08:49:19"}}}'
            sender.send_event(self.create_event(f'#!-req {req_code} ok {response_json}'))
        elif command == 'sha1':
            # !-req num ok {sha}
            if self.sha_key:
                if command == 'sha1' and self.stage_disconnect == 'sha1':
                    self.stop_receive = 1
                else:
                    if self.short_version < "4.1":
                        sender.send_event(self.create_event(f'#!-req {req_code} '
                                                            f'ok {self.sha_key}'))
                    else:
                        sender.send_event(self.create_event(f'#!-req {req_code} {{"error":0, '
                                                            f'"message":"{self.sha_key}", "data":[]}}'))
            else:
                raise ValueError('WPK SHA key should be configured in agent')

        elif command == 'upgrade':
            if self.upgrade_exec_result:
                if command == 'upgrade' and self.stage_disconnect == 'upgrade':
                    self.stop_receive = 1
                else:
                    if self.short_version < "4.1":
                        sender.send_event(self.create_event(f'#!-req {req_code} ok {self.upgrade_exec_result}'))
                    else:
                        sender.send_event(self.create_event(f'#!-req {req_code} {{"error":0, '
                                                            f'"message":"{self.upgrade_exec_result}", "data":[]}}'))
                    if self.send_upgrade_notification:
                        message = 'Upgrade was successful' if self.upgrade_script_result == 0 else 'Upgrade failed'
                        status = 'Done' if self.upgrade_script_result == 0 else 'Failed'
                        upgrade_update_status_message = {
                            'command': 'upgrade_update_status',
                            'parameters': {
                                'error': self.upgrade_script_result,
                                'message': message,
                                'status': status,
                            }
                        }
                        sender.send_event(self.create_event("u:upgrade_module:" +
                                                            json.dumps(upgrade_update_status_message)))
            else:
                raise ValueError(f'Execution result should be configured in agent')
        else:
            raise ValueError(f'Unrecognized command {command}')

    def create_hc_startup(self):
        """Set the agent startup event."""
        msg = "#!-agent startup "
        self.startup_msg = self.create_event(msg)

    def create_keep_alive(self):
        """Set the keep alive event from keepalives operating systemd data."""
        with open(os.path.join(DATA_PATH, 'events_template', 'keepalives.txt'), 'r') as fp:
            line = fp.readline()
            while line:
                if line.strip("\n") == self.os:
                    msg = fp.readline()
                    line = fp.readline()
                    while line and line.strip("\n") not in os_list:
                        msg = msg + line
                        line = fp.readline()
                    break
                line = fp.readline()
        try:
            msg = msg.replace("<VERSION>", self.long_version)
            msg = msg.replace("<MERGED_CHECKSUM>", self.merged_checksum)
        except UnboundLocalError:
            logging.critical("Error creating keep alive for the agent. Check if the OS is in the keepalives.txt")

        if self.labels:
            msg_as_list = msg.split('\n')
            for key, value in self.labels.items():
                msg_as_list.insert(1, f'"{key}":{value}')
            msg = '\n'.join(msg_as_list)

        logging.debug(f"Keep alive message = {msg}")

        self.keep_alive_event = self.create_event(msg)
        self.keep_alive_raw_msg = msg

    def initialize_modules(self, disable_all_modules):
        """Initialize and enable agent modules.
        Args:
            disable_all_modules (boolean): True to disable all modules, False to leave the default ones enabled.
        """
        for module in ['syscollector', 'rootcheck', 'fim', 'fim_integrity', 'receive_messages', 'keepalive']:
            if disable_all_modules:
                self.modules[module]['status'] = 'disabled'

        if self.modules['syscollector']['status'] == 'enabled':
            self.init_syscollector()
        if self.modules['rootcheck']['status'] == 'enabled':
            self.init_rootcheck()
        if self.modules['fim']['status'] == 'enabled':
            self.init_fim()
        if self.modules['fim_integrity']['status'] == 'enabled':
            self.init_fim_integrity()
        if self.modules['hostinfo']['status'] == 'enabled':
            self.init_hostinfo()
        if self.modules['winevt']['status'] == 'enabled':
            self.init_winevt()
        if self.modules['sca']['status'] == 'enabled':
            self.init_sca()
        if self.modules['logcollector']['status'] == 'enabled':
            self.init_logcollector()

    def init_logcollector(self):
        """Initialize logcollector module."""
        if self.logcollector is None:
            self.logcollector = Logcollector(enable_msg_number=self.logcollector_msg_number,
                                             custom_logcollector_message=self.custom_logcollector_message)

    def init_sca(self):
        """Initialize init_sca module."""
        if self.sca is None:
            self.sca = SCA(self.os)

    def init_syscollector(self):
        """Initialize syscollector module."""
        if self.syscollector is None:
            self.syscollector = GeneratorSyscollector(self.name, self.syscollector_batch_size)

    def init_rootcheck(self):
        """Initialize rootcheck module."""
        if self.rootcheck is None:
            self.rootcheck = Rootcheck(os=self.os, agent_name=self.name, agent_id=self.id,
                                       rootcheck_sample=self.rootcheck_sample)

    def init_fim(self):
        """Initialize fim module."""
        if self.fim is None:
            self.fim = GeneratorFIM(self.id, self.name, self.short_version)

    def init_fim_integrity(self):
        """Initialize fom integrity module."""
        if self.fim_integrity is None:
            self.fim_integrity = GeneratorIntegrityFIM(self.id, self.name, self.short_version)

    def init_hostinfo(self):
        """Initialize hostinfo module."""
        if self.hostinfo is None:
            self.hostinfo = GeneratorHostinfo()

    def init_winevt(self):
        """Initialize winevt module."""
        if self.winevt is None:
            self.winevt = GeneratorWinevt(self.name, self.id)

    def get_agent_info(self, field):
        agent_info = query_wdb(f"global get-agent-info {self.id}")

        if len(agent_info) > 0:
            field_value = agent_info[0][field]
        else:
            field_value = "Not in global.db"
        return field_value

    def get_agent_version(self):
        return self.get_agent_info('version')

    def get_connection_status(self):
        """Get agent connection status of global.db.
        Returns:
            str: Agent connection status (connected, disconnected, never_connected)
        """
        return self.get_agent_info('connection_status')

    @retry(AttributeError, attempts=10, delay=5, delay_multiplier=1)
    def wait_status_active(self):
        """Wait until agent status is active in global.db.
        Raises:
            AttributeError: If the agent is not active. Combined with the retry decorator makes a wait loop
                until the agent is active.
        """
        status = self.get_connection_status()

        if status == 'active':
            return
        raise AttributeError(f"Agent is not active yet: {status}")

    def set_module_status(self, module_name, status):
        """Set module status.
        Args:
            module_name (str): Module name.
            status (str): Module status.
        """
        self.modules[module_name]['status'] = status

    def set_module_attribute(self, module_name, attribute, value):
        """Set module attribute.
        Args:
            module_name (str): Module name.
            attribute (str): Attribute name to change.
            value: Attribute value.
        """
        self.modules[module_name][attribute] = value


class GeneratorSyscollector:
    """This class allows the generation of syscollector events.
    Create events of different syscollector event types Network, Process, Port, Packages, OS, Hardware and Hotfix.
    In order to change messages events it randomized different fields of templates specified by <random_string>.
    In order to simulate syscollector module, it send a set of the same syscollector type messages,
    which size is specified by `batch_size` attribute. Example of syscollector message:
        d:syscollector:{"type":"network","ID":18,"timestamp":"2021/03/26 00:00:00","iface":{"name":"O977Q1F55O",
        "type":"ethernet","state":"up","MAC":"08:00:27:be:ce:3a","tx_packets":2135,"rx_packets":9091,"tx_bytes":210748,
        "rx_bytes":10134272,"tx_errors":0,"rx_errors":0,"tx_dropped":0,"rx_dropped":0,"MTU":1500,"IPv4":
        {"address":["10.0.2.15"],"netmask":["255.255.255.0"],"broadcast":["10.0.2.255"],
        "metric":100,"gateway":"10.0.2.2","DHCP":"enabled"}}}
    Args:
        agent_name (str): Name of the agent.
        batch_size (int): Number of messages of the same type
    """
    def __init__(self, agent_name, batch_size):
        self.current_batch_events = -1
        self.current_batch_events_size = 0
        self.list_events = ['network', 'port', 'hotfix',
                            'process', 'packages', 'OS', 'hardware']
        self.agent_name = agent_name
        self.batch_size = batch_size
        self.syscollector_tag = 'syscollector'
        self.syscollector_mq = 'd'
        self.current_id = 1

    def format_event(self, message_type):
        """Format syscollector message of the specified type.
        Args:
            message_type (str): Syscollector event type.
        Returns:
            str: the generated syscollector event message.
        """
        message = SYSCOLLECTOR_HEADER
        if message_type == 'network':
            message += SYSCOLLECTOR_NETWORK_EVENT_TEMPLATE
        elif message_type == 'process':
            message += SYSCOLLECTOR_PROCESS_EVENT_TEMPLATE
        elif message_type == 'port':
            message += SYSCOLLECTOR_PORT_EVENT_TEMPLATE
        elif message_type == 'packages':
            message += SYSCOLLECTOR_PACKAGES_EVENT_TEMPLATE
        elif message_type == 'OS':
            message += SYSCOLLECTOR_OS_EVENT_TEMPLATE
        elif message_type == 'hardware':
            message += SYSCOLLECTOR_HARDWARE_EVENT_TEMPLATE
        elif message_type == 'hotfix':
            message += SYSCOLLECTOR_HOTFIX_EVENT_TEMPLATE
        elif 'end' in message_type:
            message += '}'

        today = date.today()
        timestamp = today.strftime("%Y/%m/%d %H:%M:%S")

        fields_to_replace = [
                        ('<agent_name>', self.agent_name), ('<random_int>', f"{self.current_id}"),
                        ('<random_string>', get_random_string(10)),
                        ('<timestamp>', timestamp), ('<syscollector_type>', message_type)
                    ]

        for variable, value in fields_to_replace:
            message = message.replace(variable, value)

        self.current_id += 1

        message = f"{self.syscollector_mq}:{self.syscollector_tag}:{message}"

        return message

    def generate_event(self):
        """Generate syscollector event.
         The event types are selected sequentially, creating a number of events of the same type specified
         in `bath_size`.
         Returns:
            str: generated event with the desired format for syscollector
        """
        if self.current_batch_events_size == 0:
            self.current_batch_events = (self.current_batch_events + 1) % len(self.list_events)
            self.current_batch_events_size = self.batch_size

        if self.list_events[self.current_batch_events] not in ['network', 'port', 'process'] \
                or self.current_batch_events_size > 1:
            event = self.list_events[self.current_batch_events]
        else:
            event = self.list_events[self.current_batch_events] + '_end'

        self.current_batch_events_size = self.current_batch_events_size - 1
        return self.format_event(event)


class SCA:
    """This class allows the generation of sca_label events.
    Create sca events, both summary and check.
    Args:
        os (str): Agent operative system.
    """
    def __init__(self, os):
        self.last_scan_id = 0
        self.os = os
        self.count = 0
        self.sca_mq = 'p'
        self.sca_label = 'sca'
        self.started_time = int(time())

    def get_message(self):
        """Alternatively creates summary and check SCA messages.
        Returns:
            str: an sca_label message formatted with the required header codes.
        """
        if self.count % 100 == 0:
            msg = self.create_sca_event('summary')
        else:
            msg = self.create_sca_event('check')
        self.count += 1

        msg = msg.strip('\n')

        sca_msg = f"{self.sca_mq}:{self.sca_label}:{msg}"

        return sca_msg

    def create_sca_event(self, event_type):
        """Create sca_label event of the desired type.
        Args:
            event_type (str): Event type summary or check.
        Returns:
            dict: SCA event.
        """
        event_data = dict()
        event_data['type'] = event_type
        event_data['scan_id'] = self.last_scan_id
        self.last_scan_id += 1

        def create_summary_sca_event(event_data):
            event_data['name'] = f"CIS Benchmark for {self.os}"
            event_data['policy_id'] = f"cis_{self.os}_linux"
            event_data['file'] = f"cis_{self.os}_linux.yml"
            event_data['description'] = 'This provides prescriptive guidance for establishing a secure configuration.'
            event_data['references'] = 'https://www.cisecurity.org/cis-benchmarks'
            total_checks = randint(0, 900)
            passed_checks = randint(0, total_checks)
            failed_checks = randint(0, total_checks - passed_checks)
            invalid_checks = total_checks - failed_checks - passed_checks
            event_data['passed'] = passed_checks
            event_data['failed'] = failed_checks
            event_data['invalid'] = invalid_checks
            event_data['total_checks'] = total_checks
            event_data['score'] = 20
            event_data['start_time'] = self.started_time
            self.started_time = int(time() + 1)
            event_data['end_time'] = self.started_time
            event_data['hash'] = getrandbits(256)
            event_data['hash_file'] = getrandbits(256)
            event_data['force_alert'] = '1'

            return event_data

        def create_check_sca_event(event_data):
            event_data['type'] = 'check'
            event_data['id'] = randint(0, 9999999999)
            event_data['policy'] = f"CIS Benchmark for {self.os}"
            event_data['policy_id'] = f"cis_{self.os}_policy"
            event_data['check'] = {}
            event_data['check']['id'] = randint(0, 99999)
            event_data['check']['title'] = 'Ensure root is the only UID 0 account'
            event_data['check']['description'] = 'Any account with UID 0 has superuser privileges on the system'
            event_data['check']['rationale'] = 'This access must be limited to only the default root account'
            event_data['check']['remediation'] = 'Remove any users other than root with UID 0'
            event_data['check']['compliance'] = {}
            event_data['check']['compliance']['cis'] = '6.2.6'
            event_data['check']['compliance']['cis_csc'] = '5.1'
            event_data['check']['compliance']['pci_dss'] = '10.2.5'
            event_data['check']['compliance']['hipaa'] = '164.312.b'
            event_data['check']['compliance']['nist_800_53'] = 'AU.14,AC.7'
            event_data['check']['compliance']['gpg_13'] = '7.8'
            event_data['check']['compliance']['gdpr_IV'] = '35.7,32.2'
            event_data['check']['compliance']['tsc'] = 'CC6.1,CC6.8,CC7.2,CC7.3,CC7.4'
            event_data['check']['rules'] = 'f:/etc/passwd -> !r:^# && !r:^\\\\s*\\\\t*root: && r:^\\\\w+:\\\\w+:0:\"]'
            event_data['check']['condition'] = 'none'
            event_data['check']['file'] = '/etc/passwd'
            event_data['check']['result'] = choice(['passed', 'failed'])

            return event_data

        if event_type == 'summary':
            event_data = create_summary_sca_event(event_data)
        elif event_type == 'check':
            event_data = create_check_sca_event(event_data)

        return json.dumps(event_data)


class Rootcheck:
    """This class allows the generation of rootcheck events.
    Creates rootcheck events by sequentially repeating the events of a sample file file.
    Args:
        agent_name (str): Name of the agent.
        agent_id (str): Id of the agent.
        rootcheck_sample (str, optional): File with the rootcheck events that are going to be used.
    """
    def __init__(self, os, agent_name, agent_id, rootcheck_sample=None):
        self.os = os
        self.agent_name = agent_name
        self.agent_id = agent_id
        self.rootcheck_tag = 'rootcheck'
        self.rootcheck_mq = '9'
        self.messages_list = []
        self.message = cycle(self.messages_list)
        self.rootcheck_path = ""
        self.rootcheck_sample = rootcheck_sample
        self.setup()

    def setup(self):
        """Initialized the list of rootcheck messages, using `rootcheck_sample` and agent information."""
        if self.rootcheck_sample is None:
            self.rootcheck_path = os.path.join(DATA_PATH, 'events_template', 'rootcheck.txt')
        else:
            self.rootcheck_path = os.path.join(DATA_PATH, self.rootcheck_sample)

        with open(self.rootcheck_path) as fp:
            line = fp.readline()
            while line:
                if not line.startswith("#"):
                    msg = "{0}:{1}:{2}".format(self.rootcheck_mq, self.rootcheck_tag, line.strip("\n"))
                    self.messages_list.append(msg)
                line = fp.readline()

    def get_message(self):
        """Returns a rootcheck message, informing when rootcheck scan starts and ends.
        Returns:
            str: a Rootcheck generated message
        """
        message = next(self.message)
        if message == 'Starting rootcheck scan.':
            logging.debug(f"Scan started - {self.agent_name}({self.agent_id}) "
                          f"- rootcheck({self.rootcheck_path})")
        if message == 'Ending rootcheck scan.':
            logging.debug(f"Scan ended - {self.agent_name}({self.agent_id}) "
                          f"- rootcheck({self.rootcheck_path})")

        return message


class Logcollector:
    """This class allows the generation of logcollector events."""
    def __init__(self, enable_msg_number=None, custom_logcollector_message=''):
        self.logcollector_tag = 'syslog'
        self.logcollector_mq = 'x'
        # Those variables were added only in logcollector module to perform EPS test that need numbered messages.
        self.message_counter = 0
        self.enable_msg_number = enable_msg_number
        self.custom_logcollector_message = custom_logcollector_message

    def generate_event(self):
        """Generate logcollector event
        Returns:
            str: a Logcollector generated message
        """
        if not self.custom_logcollector_message:
            log = 'Mar 24 10:12:36 centos8 sshd[12249]: Invalid user random_user from 172.17.1.1 port 56550'
        else:
            log = self.custom_logcollector_message

        if self.enable_msg_number:
            message_counter_info = f"Message number: {self.message_counter}"
            message = f"{self.logcollector_mq}:{self.logcollector_tag}:{log}:{message_counter_info}"
            self.message_counter = self.message_counter + 1
        else:
            message = f"{self.logcollector_mq}:{self.logcollector_tag}:{log}"

        return message


class GeneratorIntegrityFIM:
    """This class allows the generation of fim_integrity events.
    Args:
        agent_id (str): The id of the agent.
        agent_name (str): The name of the agent.
        agent_version (str): The version of the agent.
    """
    def __init__(self, agent_id, agent_name, agent_version):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.integrity_mq = "5"
        self.event_type = None
        self.fim_generator = GeneratorFIM(self.agent_id, self.agent_name, self.agent_version)

    def format_message(self, message):
        """Format FIM integrity message.
        Args:
            message (str): Integrity fim event.
        """
        return '{0}:[{1}] ({2}) any->syscheck:{3}'.format(self.integrity_mq, self.agent_id, self.agent_name, message)

    def generate_message(self):
        """Generate integrity FIM message according to `event_type` attribute.
        Returns:
            str: an IntegrityFIM formatted message
        """
        data = None
        if self.event_type in ["integrity_check_global", "integrity_check_left", "integrity_check_right"]:
            id = int(time())
            data = {"id": id,
                    "begin": self.fim_generator.random_file(),
                    "end": self.fim_generator.random_file(),
                    "checksum": self.fim_generator.random_sha1()}

        if self.event_type == "integrity_clear":
            id = int(time())
            data = {"id": id}

        if self.event_type == "state":
            timestamp = int(time())
            self.fim_generator.generate_attributes()
            attributes = self.fim_generator.get_attributes()
            data = {"path": self.fim_generator._file,
                    "timestamp": timestamp,
                    "attributes": attributes}

        message = json.dumps({"component": "syscheck", "type": self.event_type, "data": data})
        formatted_message = self.format_message(message)
        return formatted_message

    def get_message(self, event_type=None):
        """Generate a random kind of integrity FIM message according to `event_type` attribute.
        Returns:
            str: an IntegrityFIM formatted message
        """
        if event_type is not None:
            self.event_type = event_type
        else:
            self.event_type = choice(["integrity_check_global", "integrity_check_left", "integrity_check_right",
                                      "integrity_clear", "state"])

        return self.generate_message()


class GeneratorHostinfo:
    """This class allows the generation of hostinfo events.
    Creates hostinfo events, randomizing an open port detection template event on a host.
    It randomizes the host, as well as the ports and their protocol. The number of open ports of the event is a
    random number from 1 to 10. Example of hostinfo message:
        3:/var/log/nmap.log:Host: 95.211.24.108 (), open ports: 43270 (udp) 37146 (tcp) 19885 (tcp)
    """
    def __init__(self):
        self.hostinfo_mq = 3
        self.hostinfo_basic_template = 'Host: <random_ip> (), open ports: '
        self.protocols_list = ['udp', 'tcp']
        self.localfile = '/var/log/nmap.log'

    def generate_event(self):
        """"Generates an arbitrary hostinfo message
        Returns:
            str: an hostinfo formatted message
        """
        number_open_ports = randint(1, 10)
        host_ip = get_random_ip()
        message_open_port_list = ''
        for _ in range(number_open_ports):
            message_open_port_list += fr"{randint(1,65535)} ({choice(self.protocols_list)}) "

        message = self.hostinfo_basic_template.replace('<random_ip>', host_ip)
        message += message_open_port_list
        message = fr"{self.hostinfo_mq}:{self.localfile}:{message}"

        return message


class GeneratorWinevt:
    """This class allows the generation of winevt events.
    Create events of the different winevt channels: System, Security, Application, Windows-Defender and Sysmon.
    It uses template events (`data/winevt.py`) for which the `EventID` field is randomized. Message structure:
        f:EventChannel:{"Message":"<EVENTCHANNEL_MESSAGE>","Event":"<EVENT_CHANNEL_EVENT_XML>"}
    Args:
        agent_name (str): Name of the agent.
        agent_id (str): ID of the agent.
    """
    def __init__(self, agent_name, agent_id):
        self.agent_name = agent_name
        self.agent_id = agent_id
        self.winevent_mq = 'f'
        self.winevent_tag = 'Eventchannel'
        self.winevent_sources = {
            'system': WINEVT_SYSTEM,
            'security': WINEVT_SECURITY,
            'windows-defender': WINEVT_WINDOWS_DEFENDER,
            'application': WINEVT_APPLICATION,
            'sysmon': WINEVT_SYSMON
        }

        self.current_event_key = None
        self.next_event_key = cycle(self.winevent_sources.keys())

    def generate_event(self, winevt_type=None):
        """Generate Windows event.
        Generate the desired type of Windows event (winevt). If no type of winvt message is provided,
        all winvt message types will be generated sequentially.
        Args:
            winevt_type (str): Winevt type message `system, security, application, windows-defender, sysmon`.
        Returns:
            str: an windows event generated message.
        """
        self.current_event_key = next(self.next_event_key)

        eventchannel_raw_message = self.winevent_sources[self.current_event_key]
        eventchannel_raw_message = eventchannel_raw_message.replace("<random_int>", str(randint(0, 10*5)))

        winevent_msg = f"{self.winevent_mq}:{self.winevent_tag}:{eventchannel_raw_message}"

        return winevent_msg


class GeneratorFIM:
    """This class allows the generation of FIM events.
    Args:
        agent_id (str): The id of the agent.
        agent_name (str): The name of the agent.
        agent_version (str): The version of the agent.
    """
    def __init__(self, agent_id, agent_name, agent_version):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.file_root = '/root/'
        self._file = self.file_root + 'a'
        self._size = 0
        self._mode = S_IFREG | S_IRWXU
        self._uid = 0
        self._gid = 0
        self._md5 = 'xxx'
        self._sha1 = 'xxx'
        self._sha256 = 'xxx'
        self._uname = 'root'
        self._gname = 'root'
        self._mdate = int(mktime(localtime()))
        self._permissions = "rw-r--r--"
        self._inode = 0
        self._checksum = "f65b9f66c5ef257a7566b98e862732640d502b6f"
        self.syscheck_tag = 'syscheck'
        self.syscheck_mq = 8
        self.default_file_length = 10
        self.max_size = 1024
        self.users = {0: 'root', 1000: 'Dave', 1001: 'Connie'}
        self.max_timediff = 3600
        self.max_inode = 1024
        self.baseline_completed = 0
        self.event_mode = None
        self.event_type = None

    def random_file(self):
        """Initialize file attribute.
        Returns:
            str: the new randomized file for the instance
        """
        self._file = self.file_root + ''.join(sample(ascii_letters + digits, self.default_file_length))
        return self._file

    def random_size(self):
        """Initialize file size with random value
        Returns:
            str: the new randomized file size for the instance
        """
        self._size = randint(-1, self.max_size)
        return self._size

    def random_mode(self):
        """Initialize module attribute with `S_IFREG` or `S_IFLNK`
        Returns:
            self._mode: the new randomized file mode for the instance
        """
        self._mode = choice((S_IFREG, S_IFLNK))

        if self._mode == S_IFLNK:
            self._mode |= S_IRWXU | S_IRWXG | S_IRWXO
            self._md5 = 'xxx'
            self._sha1 = 'xxx'
        else:
            s = sample((S_IRWXU, S_IRWXG, S_IRWXO), 2)
            self._mode |= s[0] | s[1]

        return self._mode

    def random_uid(self):
        """Initialize uid attribute with random value.
        Returns:
            str: the new randomized file uid for the instance
        """
        self._uid = choice(list(self.users.keys()))
        self._uname = self.users[self._uid]
        return self._uid, self._uname

    def random_gid(self):
        """Initialize gid attribute with random value.
        Returns:
            str: the new randomized gid for the instance,
            str: the new randomized gname for the instance.
        """
        self._gid = choice(list(self.users.keys()))
        self._gname = self.users[self._gid]
        return self._gid, self._gname

    def random_md5(self):
        """Initialize md5 attribute with random value.
        Returns:
            str: the new randomized md5 for the instance.
        """
        if self._mode & S_IFREG == S_IFREG:
            self._md5 = ''.join(sample('0123456789abcdef' * 2, 32))

        return self._md5

    def random_sha1(self):
        """Initialize sha1 attribute with random value.
        Returns:
            str: the new randomized sha1 for the instance.
        """
        if self._mode & S_IFREG == S_IFREG:
            self._sha1 = ''.join(sample('0123456789abcdef' * 3, 40))

        return self._sha1

    def random_sha256(self):
        """Initialize sha256 attribute with random value.
        Returns:
            str: the new randomized sha256 for the instance.
        """
        if self._mode & S_IFREG == S_IFREG:
            self._sha256 = ''.join(sample('0123456789abcdef' * 4, 64))

        return self._sha256

    def random_time(self):
        """Initialize time attribute with random value.
         Returns:
            str: the new randomized mdate for the instance.
        """
        self._mdate += randint(1, self.max_timediff)
        return self._mdate

    def random_inode(self):
        """Initialize inode attribute with random value.
        Returns:
            str: the new randomized inode for the instance.
        """
        self._inode = randint(1, self.max_inode)
        return self._inode

    def generate_attributes(self):
        """Initialize GeneratorFIM attributes"""
        self.random_file()
        self.random_size()
        self.random_mode()
        self.random_uid()
        self.random_gid()
        self.random_md5()
        self.random_sha1()
        self.random_sha256()
        self.random_time()
        self.random_inode()
        self._checksum = self.random_sha1()

    def check_changed_attributes(self, attributes, old_attributes):
        """Returns attributes that have changed. """
        changed_attributes = []
        if attributes["size"] != old_attributes["size"]:
            changed_attributes.append("size")
        if attributes["perm"] != old_attributes["perm"]:
            changed_attributes.append("permission")
        if attributes["uid"] != old_attributes["uid"]:
            changed_attributes.append("uid")
        if attributes["gid"] != old_attributes["gid"]:
            changed_attributes.append("gid")
        if attributes["user_name"] != old_attributes["user_name"]:
            changed_attributes.append("user_name")
        if attributes["group_name"] != old_attributes["group_name"]:
            changed_attributes.append("group_name")
        if attributes["inode"] != old_attributes["inode"]:
            changed_attributes.append("inode")
        if attributes["mtime"] != old_attributes["mtime"]:
            changed_attributes.append("mtime")
        if attributes["hash_md5"] != old_attributes["hash_md5"]:
            changed_attributes.append("md5")
        if attributes["hash_sha1"] != old_attributes["hash_sha1"]:
            changed_attributes.append("sha1")
        if attributes["hash_sha256"] != old_attributes["hash_sha256"]:
            changed_attributes.append("sha256")

        return changed_attributes

    def get_attributes(self):
        """Return GeneratorFIM attributes.
        Returns:
            dict: instance attributes.
        """
        attributes = {
            "type": "file", "size": self._size,
            "perm": self._permissions, "uid": str(self._uid),
            "gid": str(self._gid), "user_name": self._uname,
            "group_name": self._gname, "inode": self._inode,
            "mtime": self._mdate, "hash_md5": self._md5,
            "hash_sha1": self._sha1, "hash_sha256": self._sha256,
            "checksum": self._checksum
        }
        return attributes

    def format_message(self, message):
        """Format FIM message.
        Args:
            message (str): FIM message.
        Returns:
            str: generated message with the required FIM header.
        """
        if self.agent_version >= "3.12":
            formated_message = f"{self.syscheck_mq}:({self.agent_id}) any->syscheck:{message}"
        else:
            # If first time generating. Send control message to simulate
            # end of FIM baseline.
            if self.baseline_completed == 0:
                self.baseline_completed = 1
                formated_message = f"{self.syscheck_mq}:{self.syscheck_tag}:syscheck-db-completed"
            else:
                formated_message = f"{self.syscheck_mq}:{self.syscheck_tag}:{message}"

        return formated_message

    def generate_message(self):
        """Generate FIM event based on `event_type` and `agent_version` attribute.
        Returns:
            str: generated message with the required FIM header.
        """
        if self.agent_version >= "3.12":
            if self.event_type == "added":
                timestamp = int(time())
                self.generate_attributes()
                attributes = self.get_attributes()
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes}
            elif self.event_type == "modified":
                timestamp = int(time())
                self.generate_attributes()
                attributes = self.get_attributes()
                self.generate_attributes()
                old_attributes = self.get_attributes()
                changed_attributes = self.check_changed_attributes(attributes, old_attributes)
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes,
                        "old_attributes": old_attributes,
                        "changed_attributes": changed_attributes}
            else:
                timestamp = int(time())
                self.generate_attributes()
                attributes = self.get_attributes()
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes}

            message = json.dumps({"type": "event", "data": data})

        else:
            self.generate_attributes()
            message = f'{self._size}:{self._mode}:{self._uid}:{self._gid}:{self._md5}:{self._sha1}:{self._uname}:' \
                      f'{self._gname}:{self._mdate}:{self._inode} {self._file}'

        formatted_message = self.format_message(message)
        return formatted_message

    def get_message(self, event_mode=None, event_type=None):
        """Get FIM message. If no parameters are provided, it is randomly selected among the possible values
        Args:
            event_mode (str): Event mode `real-time, whodata, scheduled`.
            event_type (str): Event type `added, modified, deleted`.
        Returns:
            str: generated message.
        """
        if event_mode is not None:
            self.event_mode = event_mode
        else:
            self.event_mode = choice(["real-time", "whodata", "scheduled"])

        if event_type is not None:
            self.event_type = event_type
        else:
            self.event_type = choice(["added", "modified", "deleted"])

        generated_message = self.generate_message()

        return generated_message


class Sender:
    """This class sends events to the manager through a socket.
    Attributes:
        manager_address (str): IP of the manager.
        manager_port (str, optional): port used by remoted in the manager.
        protocol (str, optional): protocol used by remoted. TCP or UDP.
        socket (socket): sock_stream used to connect with remoted.
    Examples:
        To create a Sender, you need to create an agent first, and then, create the sender. Finally, to send messages
        you will need to use both agent and sender to create an injector.
        >>> import wazuh_testing.tools.agent_simulator as ag
        >>> manager_address = "172.17.0.2"
        >>> agent = ag.Agent(manager_address, "aes", os="debian8", version="4.2.0")
        >>> sender = ag.Sender(manager_address, protocol=TCP)
    """
    def __init__(self, manager_address, manager_port='1514', protocol=TCP):
        self.manager_address = manager_address
        self.manager_port = manager_port
        self.protocol = protocol.upper()
        self.socket = None
        self.connect()

    def connect(self):
        if is_tcp(self.protocol):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.manager_address, int(self.manager_port)))
        if is_udp(self.protocol):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def reconnect(self, event):
        if is_tcp(self.protocol):
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.connect()
            if event:
                self.send_event(event)

    def send_event(self, event):
        if is_tcp(self.protocol):
            length = pack('<I', len(event))
            try:
                self.socket.send(length + event)
            except BrokenPipeError:
                logging.warning(f"Broken Pipe error while sending event. Creating new socket...")
                sleep(5)
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.manager_address, int(self.manager_port)))
                self.socket.send(length + event)
            except ConnectionResetError:
                logging.warning(f"Connection reset by peer. Continuing...")
        if is_udp(self.protocol):
            self.socket.sendto(event, (self.manager_address, int(self.manager_port)))


class Injector:
    """This class simulates a daemon used to send and receive messages with the manager.
    Each `Agent` needs an injector and a sender to be able to communicate with the manager. This class will create
    a thread using `InjectorThread` which will behave similarly to an UNIX daemon. The `InjectorThread` will
    send and receive the messages using the `Sender`
    Attributes:
        sender (Sender): sender used to connect to the sockets and send messages.
        agent (agent): agent owner of the injector and the sender.
        thread_number (int): total number of threads created. This may change depending on the modules used in the
                             agent.
        threads (list): list containing all the threads created.
        limit_msg (int): Maximum amount of message to be sent.
    Examples:
        To create an Injector, you need to create an agent, a sender and then, create the injector using both of them.
        >>> import wazuh_testing.tools.agent_simulator as ag
        >>> manager_address = "172.17.0.2"
        >>> agent = ag.Agent(manager_address, "aes", os="debian8", version="4.2.0")
        >>> sender = ag.Sender(manager_address, protocol=TCP)
        >>> injector = ag.Injector(sender, agent)
        >>> injector.run()
    """

    def __init__(self, sender, agent, limit=None):
        self.sender = sender
        self.agent = agent
        self.limit_msg = limit
        self.thread_number = 0
        self.threads = []
        for module, config in self.agent.modules.items():
            if config["status"] == "enabled":
                self.threads.append(
                    InjectorThread(self.thread_number, f"Thread-{self.agent.id}{module}", self.sender,
                                   self.agent, module, self.limit_msg))
                self.thread_number += 1

    def run(self):
        """Start the daemon to send and receive messages for all the threads."""
        for thread in range(self.thread_number):
            self.threads[thread].daemon = True
            self.threads[thread].start()

    def stop_receive(self):
        """Stop the daemon for all the threads."""
        for thread in range(self.thread_number):
            self.threads[thread].stop_rec()
        sleep(2)
        if is_tcp(self.sender.protocol):
            self.sender.socket.shutdown(socket.SHUT_RDWR)
        self.sender.socket.close()

    def wait(self):
        for thread in range(self.thread_number):
            self.threads[thread].join()


class InjectorThread(threading.Thread):
    """This class creates a thread who will create and send the events to the manager for each module.
    Attributes:
        thread_id (int): ID of the thread.
        name (str): name of the thread. It is composed as Thread-{agent.id}{module}.
        sender (Sender): sender used to connect to the sockets and send messages.
        agent (Agent): agent owner of the injector and the sender.
        module (str): module used to send events (fim, syscollector, etc).
        stop_thread (int): 0 if the thread is running, 1 if it is stopped.
        limit_msg (int): Maximum amount of message to be sent.
    """
    def __init__(self, thread_id, name, sender, agent, module, limit_msg=None):
        super(InjectorThread, self).__init__()
        self.thread_id = thread_id
        self.name = name
        self.sender = sender
        self.agent = agent
        self.totalMessages = 0
        self.module = module
        self.stop_thread = 0
        self.limit_msg = limit_msg

    def keep_alive(self):
        """Send a keep alive message from the agent to the manager."""
        sleep(10)
        logging.debug("Startup - {}({})".format(self.agent.name, self.agent.id))
        self.sender.send_event(self.agent.startup_msg)
        self.sender.send_event(self.agent.keep_alive_event)
        start_time = time()
        frequency = self.agent.modules["keepalive"]["frequency"]
        eps = 1
        if 'eps' in self.agent.modules["keepalive"]:
            frequency = 0
            eps = self.agent.modules["keepalive"]["eps"]
        while self.stop_thread == 0:
            # Send agent keep alive
            logging.debug(f"KeepAlive - {self.agent.name}({self.agent.id})")
            self.sender.send_event(self.agent.keep_alive_event)
            self.totalMessages += 1
            if frequency > 0:
                sleep(frequency - ((time() - start_time) % frequency))
            else:
                logging.debug('Merged checksum modified to force manager overload')
                new_checksum = str(getrandbits(128))
                self.agent.update_checksum(new_checksum)
                if self.totalMessages % eps == 0:
                    sleep(1.0 - ((time() - start_time) % 1.0))

    def run_module(self, module):
        """Send a module message from the agent to the manager.
         Args:
                module (str): Module name
        """
        module_info = self.agent.modules[module]
        eps = module_info['eps'] if 'eps' in module_info else 1
        frequency = module_info["frequency"] if 'frequency' in module_info else 1

        sleep(10)
        start_time = time()
        if frequency > 1:
            batch_messages = eps * 0.5 * frequency
        else:
            batch_messages = eps

        if module == 'hostinfo':
            self.agent.init_hostinfo()
            module_event_generator = self.agent.hostinfo.generate_event
        elif module == 'rootcheck':
            self.agent.init_rootcheck()
            module_event_generator = self.agent.rootcheck.get_message
            batch_messages = len(self.agent.rootcheck.messages_list) * eps
        elif module == 'syscollector':
            self.agent.init_syscollector()
            module_event_generator = self.agent.syscollector.generate_event
        elif module == 'fim_integrity':
            self.agent.init_fim_integrity()
            module_event_generator = self.agent.fim_integrity.get_message
        elif module == 'fim':
            module_event_generator = self.agent.fim.get_message
        elif module == 'sca':
            self.agent.init_sca()
            module_event_generator = self.agent.sca.get_message
        elif module == 'winevt':
            self.agent.init_winevt()
            module_event_generator = self.agent.winevt.generate_event
        elif module == 'logcollector':
            self.agent.init_logcollector()
            module_event_generator = self.agent.logcollector.generate_event
        else:
            raise ValueError('Invalid module selected')

        # Loop events
        while self.stop_thread == 0:
            sent_messages = 0
            while sent_messages < batch_messages:
                event_msg = module_event_generator()
                if self.agent.fixed_message_size is not None:
                    event_msg_size = getsizeof(event_msg)
                    dummy_message_size = self.agent.fixed_message_size - event_msg_size
                    char_size = getsizeof(event_msg[0]) - getsizeof('')
                    event_msg += 'A' * (dummy_message_size//char_size)

                # Add message limitiation
                if self.limit_msg:
                    if self.totalMessages >= self.limit_msg:
                        self.stop_thread = 1
                        break

                event = self.agent.create_event(event_msg)
                try:
                    self.sender.send_event(event)
                    self.totalMessages += 1
                    sent_messages += 1
                except Exception as e:
                    logging.debug(f"Send a module message - {e}")
                if self.totalMessages % eps == 0:
                    sleep(1.0 - ((time() - start_time) % 1.0))

            if frequency > 1:
                sleep(frequency - ((time() - start_time) % frequency))

    def run(self):
        """Start the thread that will send messages to the manager."""
        # message = "1:/var/log/syslog:Jan 29 10:03:41 master sshd[19635]:
        #   pam_unix(sshd:session): session opened for user vagrant by (uid=0)
        #   uid: 0"
        logging.debug(f"Starting - {self.agent.name}({self.agent.id})({self.agent.os}) - {self.module}")
        if self.module == "keepalive":
            self.keep_alive()
        elif self.module == "receive_messages":
            self.agent.receive_message(self.sender)
        else:
            self.run_module(self.module)

    def stop_rec(self):
        """Stop the thread to avoid sending any more messages."""
        if self.module == "receive_messages":
            self.agent.stop_receiver()
        else:
            self.stop_thread = 1


def create_agents(agents_number, manager_address, cypher='aes', fim_eps=100, authd_password=None, agents_os=None,
                  agents_version=None, disable_all_modules=False):
    """Create a list of generic agents
    This will create a list with `agents_number` amount of agents. All of them will be registered in the same manager.
    Args:
        agents_number (int): total number of agents.
        manager_address (str): IP address of the manager.
        cypher (str): cypher used for the communications. It may be aes or blowfish.
        fim_eps (int, optional): total number of EPS produced by FIM.
        authd_password (str, optional): password to enroll an agent.
        agents_os (list, optional): list containing different operative systems for the agents.
        agents_version (list, optional): list containing different version of the agent.
        disable_all_modules (boolean): Disable all simulated modules for this agent.
    Returns:
        list: list of the new virtual agents.
    """
    global agent_count
    # Read client.keys and create virtual agents
    agents = []
    for agent in range(agents_number):
        agent_os = agents_os[agent] if agents_os is not None else None
        agent_version = agents_version[agent] if agents_version is not None else None

        agents.append(Agent(manager_address, cypher, fim_eps=fim_eps, authd_password=authd_password,
                            os=agent_os, version=agent_version, disable_all_modules=disable_all_modules))

        agent_count = agent_count + 1

    return agents


def connect(agent,  manager_address='localhost', protocol=TCP, manager_port='1514') -> Tuple[Sender, Injector]:
    """Connects an agent to the manager
    Args:
        agent (Agent): agent to connect.
        manager_address (str): address of the manager. It can be an IP or a DNS.
        protocol (str): protocol used to connect with the manager. Defaults to 'TCP'.
        manager_port (str): port used to connect with the manager. Defaults to '1514'.
    """
    sender = Sender(manager_address, protocol=protocol, manager_port=manager_port)
    injector = Injector(sender, agent)
    injector.run()
    agent.wait_status_active()
    return sender, injector


def send_ping_pong_messages(protocol, manager_address, port):
    """Send the ping message to the manager.

    This message is the first of many between the manager and the agents. It is used to check if both of them are ready
    to send and receive other messages.

    Args:
        protocol (str): it can be UDP or TCP.
        manager_address (str): address of the manager. IP and hostname are valid options.
        port (int): port where the manager has bound the remoted port.

    Returns:
        bytes: returns the #pong message from the manager.

    Raises:
        ConnectionRefusedError: if there's a problem while sending messages to the manager.
    """
    protocol = protocol.upper()
    if protocol == UDP:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ping_msg = b'#ping'
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        msg = '#ping'
        msg_size = len(bytearray(msg, 'utf-8'))
        # Since the message size's is represented as an unsigned int32, you need to use 4 bytes to represent it
        ping_msg = msg_size.to_bytes(4, 'little') + msg.encode()

    sock.connect((manager_address, port))
    sock.send(ping_msg)
    response = sock.recv(len(ping_msg))
    sock.close()
    return response if protocol == UDP else response[-5:]



def new_agent_group(group_name='testing_group', configuration_file='agent.conf'):
    """Create a new agent group for testing purpose, must be run only on Managers."""

    data_path = Path(__file__).parents[2]/'data'/'configuration_template'
    sb.run([f"{WAZUH_PATH}/bin/agent_groups", "-q", "-a", "-g", group_name])

    agent_conf_path = os.path.join(data_path, configuration_file)

    with open(f"{WAZUH_PATH}/etc/shared/{group_name}/agent.conf", "w") as agent_conf_file:
        with open(agent_conf_path, 'r') as configuration:
            #lala = configuration
            agent_conf_file.write(configuration.read())


def remove_agent_group(group_name):
    sb.run([f"{WAZUH_PATH}/bin/agent_groups", "-q", "-r", "-g", group_name])


def add_agent_to_group(group_name, agent_id):
    sb.run([f"{WAZUH_PATH}/bin/agent_groups", "-q", "-a", "-i", agent_id, "-g", group_name])
