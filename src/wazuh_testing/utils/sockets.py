# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import socket
import ipaddress

from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.constants.paths.sockets import QUEUE_SOCKETS_PATH, WAZUH_DB_SOCKET_PATH, \
                                                  MODULESD_C_INTERNAL_SOCKET_PATH, \
                                                  ACTIVE_RESPONSE_SOCKET_PATH
from wazuh_testing.utils.network import UDP


def delete_sockets(path=None):
    """Delete a list of Wazuh socket files or all of them if None is specified.

    Args:
        path (list, optional): Absolute socket path. Default `None`.
    """
    try:
        if path is None:
            path = QUEUE_SOCKETS_PATH
            for file in os.listdir(path):
                os.remove(os.path.join(path, file))
            if os.path.exists(WAZUH_DB_SOCKET_PATH):
                os.remove(WAZUH_DB_SOCKET_PATH)
            if os.path.exists(MODULESD_C_INTERNAL_SOCKET_PATH):
                os.remove(MODULESD_C_INTERNAL_SOCKET_PATH)
        else:
            for item in path:
                os.remove(item)
    except FileNotFoundError:
        pass

def send_request_socket(query, socket_path=WAZUH_DB_SOCKET_PATH):
    """Send queries request to socket in the argument.

    Args:
        query (str): query request command. For example `agent {agent.id} rootcheck delete`.
        socket_path (str): by default use wdb socket.
    Returns:
        list: Query response data.
    """
    controller = SocketController(socket_path)
    controller.send(query, size=True)
    response = controller.receive(size=True)
    controller.close()

    return response


def send_message_to_syslog_socket(message, port, protocol, manager_address="127.0.0.1"):
    """Send a message to the syslog server of wazuh-manager-remoted.

    Args:
        message (str): string to send as a syslog event.
        protocol (str): it can be UDP or TCP.
        port (int): port where the manager has bound the remoted port.
        manager_address (str): address of the manager.

    Raises:
        ConnectionRefusedError: if there's a problem while sending messages to the manager.
    """
    ip = ipaddress.ip_address(manager_address)
    if protocol.upper() == UDP:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif isinstance(ip, ipaddress.IPv6Address):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    else:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif isinstance(ip, ipaddress.IPv6Address):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    if not message.endswith("\n"):
        message += "\n"

    sock.connect((manager_address, port))
    sock.send(message.encode())
    sock.close()


def send_active_response_message(active_response_command):
    """Send active response message to `/var/ossec/queue/alerts/ar` socket.

    Args:
        active_response_command (str): Active response message.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    sock.connect(ACTIVE_RESPONSE_SOCKET_PATH)
    sock.send(f"{active_response_command}".encode())
    sock.close()


def get_host_name():
    """
    Gets the system host name.

    Returns:
        str: The host name.
    """
    return socket.gethostname()
