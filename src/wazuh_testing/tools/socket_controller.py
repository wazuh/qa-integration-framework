# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import socket
import ssl

from wazuh_testing.utils import messages


class SocketController:

    def __init__(self, address, family='AF_UNIX', connection_protocol='TCP', timeout=30, open_at_start=True):
        """Create a new unix socket or connect to a existing one.

        Args:

            address (str or Tuple(str, int)): Address of the socket, the format of the address depends on the type.
                A regular file path for AF_UNIX or a Tuple(HOST, PORT) for AF_INET
            family (str): Family type of socket to connect to, AF_UNIX for unix sockets or AF_INET for port sockets.
            connection_protocol (str): Flag that indicates if the connection is TCP (SOCK_STREAM), UDP (SOCK_DGRAM)
                or SSL_TLSv1_2.
            timeout (int): Optional - Socket's timeout, 0 for non-blocking mode.
            open_at_start (boolean): Defines if the socket is opened at start or not. Default True

        Raises:
            Exception: If the socket connection failed.
        """
        self.address = address
        self.ssl = False
        self.connection_protocol = connection_protocol
        self.timeout = timeout
        # SSL options
        self.ciphers = None
        self.certificate = None
        self.keyfile = None

        # Set socket family
        if family == 'AF_UNIX':
            self.family = socket.AF_UNIX
        elif family == 'AF_INET':
            self.family = socket.AF_INET
        elif family == 'AF_INET6':
            self.family = socket.AF_INET6
        else:
            raise TypeError(f'Invalid family type detected: {family}. Valid ones are AF_UNIX, AF_INET or AF_INET6')

        # Set socket protocol
        if connection_protocol.lower() == 'tcp' or 'ssl' in connection_protocol.lower():
            self.protocol = socket.SOCK_STREAM
        elif connection_protocol.lower() == 'udp':
            self.protocol = socket.SOCK_DGRAM
        else:
            raise TypeError(f'Invalid connection protocol detected: {connection_protocol.lower()}. '
                            f'Valid ones are TCP, UDP or SSL versions')

        if (open_at_start):
            self.open()

    def open(self):
        """Opens socket """
        # Create socket object
        self.sock = socket.socket(family=self.family, type=self.protocol)

        if 'ssl' in self.connection_protocol.lower():
            versions_maps = {
                "ssl_v2_3": ssl.PROTOCOL_SSLv23,
                "ssl_tls": ssl.PROTOCOL_TLS,
                "ssl_tlsv1_1": ssl.PROTOCOL_TLSv1,
                "ssl_tlsv1_2": ssl.PROTOCOL_TLSv1_2,
            }
            ssl_version = versions_maps.get(self.connection_protocol.lower(), None)
            if ssl_version is None:
                raise TypeError(
                    f'Invalid or unsupported SSL version specified, valid versions are: {list(versions_maps.keys())}')
            # Wrap socket into ssl
            self.sock = ssl.wrap_socket(self.sock, ssl_version=ssl_version, ciphers=self.ciphers,
                                        certfile=self.certificate, keyfile=self.keyfile)
            self.ssl = True

        # Connect only if protocol is TCP
        if self.protocol == socket.SOCK_STREAM:
            try:
                self.sock.settimeout(self.timeout)
                self.sock.connect(self.address)
            except socket.timeout as e:
                raise TimeoutError(f'Could not connect to socket {self.address} of family {self.family}')

    def close(self):
        """Close the socket gracefully."""
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def send(self, message, size=False):
        """Send a message to the socket.

        Args:
            message (str or bytes): Message to be sent.
            size (bool, optional) : Flag that indicates if the header of the message includes the size of the message
                (For example, Analysis doesn't need the size, wazuh-db does). Default `False`
        Returns:
            (int) : Size of the sent message
        """
        msg_bytes = message.encode() if isinstance(message, str) else message
        try:
            msg_bytes = messages.wazuh_pack(len(msg_bytes)) + msg_bytes if size else msg_bytes
            if self.protocol == socket.SOCK_STREAM:  # TCP
                output = self.sock.sendall(msg_bytes)
            else:  # UDP
                output = self.sock.sendto(msg_bytes, self.address)
        except OSError as e:
            raise e

        return output

    def receive(self, size=False):
        """Receive a message from the socket.

        Args:
            size (bool): Flag that indicates if the header of the message includes the size of the message
                (For example, Analysis doesn't need the size, wazuh-db does). Default `False`
        Returns:
            bytes: Socket message.
        """
        if size:
            data = self.sock.recv(4, socket.MSG_WAITALL)
            if not data:
                output = bytes('', 'utf8')
                return output
            size = messages.wazuh_unpack(data)
            output = self.sock.recv(size, socket.MSG_WAITALL)
        else:
            output = self.sock.recv(4096)
            if len(output) == 4096:
                while 1:
                    try:  # error means no more data
                        output += self.sock.recv(4096, socket.MSG_DONTWAIT)
                    except Exception:
                        break

        return output

    def set_ssl_configuration(self, ciphers="HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH",
                              connection_protocol="SSL_TLSv1_2", certificate=None, keyfile=None):
        """Set SSL configurations (use on SSL socket only). Should be set before opening the socket

        Args:
            ciphers (str): String with supported ciphers
            connection_protocol (str): ssl version to be used
            certificate: Optional - Path to the ssl certificate
            keyfile: Optional - Path to the ssl key
        """
        self.ciphers = ciphers
        self.connection_protocol = connection_protocol
        self.certificate = certificate
        self.keyfile = keyfile
        return

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
