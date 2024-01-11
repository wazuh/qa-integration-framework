# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
try:
    import grp
    import pwd
except ModuleNotFoundError:
    pass

import os
import queue
import socket
import socketserver
import ssl
import threading

from typing import Union

from wazuh_testing.constants.users import WAZUH_UNIX_USER, WAZUH_UNIX_GROUP
from wazuh_testing.utils import secure_message


class StreamServerPort(socketserver.ThreadingTCPServer):

    def process_request(self, request: Union[socket.socket, tuple[bytes, socket.socket]],
                        client_addres: tuple[str | bytes | bytearray, int]) -> None:
        """
        overrides process_request and saves `last_address`.
        """
        self.last_address = client_addres
        super().process_request(request, client_addres)


class StreamServerPortV6(StreamServerPort):
    address_family = socket.AF_INET6


class DatagramServerPort(socketserver.ThreadingUDPServer):

    def process_request(self, request: Union[socket.socket, tuple[bytes, socket.socket]],
                        client_addres: tuple[str | bytes | bytearray, int]) -> None:
        """
        overrides process_request and saves `last_address`.
        """
        self.last_address = client_addres
        super().process_request(request, client_addres)


class DatagramServerPortV6(DatagramServerPort):
    address_family = socket.AF_INET6
    pass


class SSLStreamServerPort(socketserver.ThreadingTCPServer):
    ciphers = "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
    ssl_version = ssl.PROTOCOL_TLSv1_2
    certfile = None
    keyfile = None
    ca_cert = None
    cert_reqs = ssl.CERT_NONE
    options = None

    def set_ssl_configuration(self, ciphers=None, connection_protocol=None, certificate=None, keyfile=None,
                              cert_reqs=None, ca_cert=None, options=None):
        """Overrides SSL  default configurations.

        Args:
            ciphers(string):  String with supported ciphers
            connection_protocol(string): ssl version to be used
            certificate (str, optional): Path to the ssl certificate
            keyfile (str, optional): Path to the ssl key
            cert_reqs (str, optional): ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED. Whenever or not
                a cert is required
            ca_cert(str, optional): If cert is required show accepted certs
            options(str, optional): Add additional options
        """
        if ciphers:
            self.ciphers = ciphers
        if connection_protocol:
            self.ssl_version = connection_protocol
        if certificate:
            self.certfile = certificate
        if keyfile:
            self.keyfile = keyfile
        if cert_reqs is not None:
            self.cert_reqs = cert_reqs
        if ca_cert:
            self.ca_cert = ca_cert
        if options:
            self.options = options

        return

    def get_request(self):
        """
        overrides get_request
        """
        newsocket, fromaddr = self.socket.accept()

        if not self.certfile or not self.keyfile or not self.ssl_version:
            raise Exception('SSL configuration needs to be set in SSLStreamServer')

        try:
            context = ssl.SSLContext(self.ssl_version)
            if self.options:
                context.options = self.options
            if self.certfile:
                context.load_cert_chain(self.certfile, self.keyfile)
            if self.ca_cert is None:
                context.verify_mode = ssl.CERT_NONE
            else:
                context.verify_mode = self.cert_reqs
                context.load_verify_locations(cafile=self.ca_cert)
            context.set_ciphers(self.ciphers)
            connstream = context.wrap_socket(newsocket, server_side=True)
        except OSError as err:
            print(err)
            raise

        # Save last_address
        self.last_address = fromaddr
        return connstream, fromaddr


class SSLStreamServerPortV6(SSLStreamServerPort):
    address_family = socket.AF_INET6


if hasattr(socketserver, 'ThreadingUnixStreamServer'):
    class StreamServerUnix(socketserver.ThreadingUnixStreamServer):

        def shutdown_request(self, request):
            pass

    class DatagramServerUnix(socketserver.ThreadingUnixDatagramServer):

        def shutdown_request(self, request):
            pass


class StreamHandler(socketserver.BaseRequestHandler):

    def unix_forward(self, data):
        """Default TCP unix socket forwarder for MITM servers."""
        # Create a socket context
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as forwarded_sock:
            # Connect to server and send data
            forwarded_sock.connect(self.server.mitm.forwarded_socket_path)
            forwarded_sock.sendall(secure_message.pack(len(data)) + data)

            # Receive data from the server and shut down
            size = secure_message.unpack(self.recvall_size(forwarded_sock, 4, socket.MSG_WAITALL))
            response = self.recvall_size(forwarded_sock, size, socket.MSG_WAITALL)

            return response

    def recvall_size(self, sock: socket.socket, size: int, mask: int):
        """Recvall with known size of the message."""
        buffer = bytearray()
        while len(buffer) < size:
            try:
                data = sock.recv(size - len(buffer), mask)
                if not data:
                    break
                buffer.extend(data)
            except socket.timeout:
                if self.server.mitm.event.is_set():
                    break
        return bytes(buffer)

    def recvall(self, chunk_size: int = 4096):
        """Recvall without known size of the message."""
        received = self.request.recv(chunk_size)
        if len(received) == chunk_size:
            while 1:
                try:  # error means no more data
                    received += self.request.recv(chunk_size, socket.MSG_DONTWAIT)
                except Exception:
                    break
        return received

    def default_wazuh_handler(self):
        """Default wazuh daemons TCP handler method for MITM server."""
        self.request.settimeout(1)
        while not self.server.mitm.event.is_set():
            header = self.recvall_size(self.request, 4, socket.MSG_WAITALL)
            if not header:
                break
            size = secure_message.unpack(header)
            data = self.recvall_size(self.request, size, socket.MSG_WAITALL)
            if not data:
                break

            response = self.unix_forward(data)

            self.server.mitm.put_queue((data.rstrip(b'\x00'), response.rstrip(b'\x00')))

            self.request.sendall(secure_message.pack(len(response)) + response)

    def handle(self):
        """Overriden handle method for TCP MITM server."""
        if self.server.mitm.handler_func is None:
            self.default_wazuh_handler()
        else:
            while not self.server.mitm.event.is_set():
                received = self.recvall()
                response = self.server.mitm.handler_func(received)
                self.server.mitm.put_queue((received, response))
                self.request.sendall(response)


class DatagramHandler(socketserver.BaseRequestHandler):

    def unix_forward(self, data):
        """Default UDP unix socket forwarder for MITM servers."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as forwarded_sock:
            forwarded_sock.sendto(data, self.server.mitm.forwarded_socket_path)

    def default_wazuh_handler(self):
        """Default wazuh daemons UDP handler method for MITM server."""
        data = self.request[0]
        self.unix_forward(data)
        self.server.mitm.put_queue(data.rstrip(b'\x00'))

    def handle(self):
        """Overriden handle method for UDP MITM server."""
        if self.server.mitm.handler_func is None:
            self.default_wazuh_handler()
        else:
            data = self.request[0]
            response = self.server.mitm.handler_func(data)
            self.server.mitm.put_queue(data)
            self.request[1].sendto(response, self.client_address)


class ManInTheMiddle:

    def __init__(self, address, family='AF_UNIX', connection_protocol='TCP', func: callable = None):
        """Create a MITM server for the socket `socket_address`.

        Args:
            address (str or Tuple(str, int) ): Address of the socket, the format of the address depends on the type.
                A regular file path for AF_UNIX or a Tuple(HOST, PORT) for AF_INET
            family (str): Family type of socket to connect to, AF_UNIX for unix sockets or AF_INET for port sockets.
                Default `'AF_UNIX'`
            connection_protocol (str): It can be either 'TCP', 'UDP' or SSL. Default `'TCP'`
            func (callable): Function to be applied to every received data before sending it.
        """
        if isinstance(address, str) or (isinstance(address, tuple) and len(address) == 2
                                        and isinstance(address[0], str) and isinstance(address[1], int)):
            self.listener_socket_address = address
        else:
            raise TypeError(f"Invalid address type: {type(address)}. Valid types are str or Tuple(str, int)")

        if (connection_protocol.lower() == 'tcp' or connection_protocol.lower() == 'udp' or
                connection_protocol.lower() == 'ssl'):
            self.mode = connection_protocol.lower()
        else:
            raise TypeError(f'Invalid connection protocol detected: {connection_protocol.lower()}. '
                            f'Valid ones are TCP or UDP')

        if family in ('AF_UNIX', 'AF_INET', 'AF_INET6'):
            self.family = family
        else:
            raise TypeError('Invalid family type detected. Valid ones are AF_UNIX, AF_INET or AF_INET6')

        self.forwarded_socket_path = None

        class_tree = {
            'listener': {
                'tcp': {
                    'AF_INET': StreamServerPort,
                    'AF_INET6': StreamServerPortV6
                },
                'udp': {
                    'AF_INET': DatagramServerPort,
                    'AF_INET6': DatagramServerPortV6
                },
                'ssl': {
                    'AF_INET': SSLStreamServerPort,
                    'AF_INET6': SSLStreamServerPortV6
                }
            },
            'handler': {
                'tcp': StreamHandler,
                'udp': DatagramHandler,
                'ssl': StreamHandler
            }
        }
        if hasattr(socketserver, 'ThreadingUnixStreamServer'):
            class_tree['listener']['tcp']['AF_UNIX'] = StreamServerUnix
            class_tree['listener']['udp']['AF_UNIX'] = DatagramServerUnix

        self.listener_class = class_tree['listener'][self.mode][self.family]
        self.handler_class = class_tree['handler'][self.mode]
        self.handler_func = func
        self.listener = None
        self.thread = None
        self.event = threading.Event()
        self._queue = queue.Queue()

    def run(self, *args):
        """Run a MITM server."""
        # Rename socket if it is a file (AF_UNIX)
        if isinstance(self.listener_socket_address, str):
            self.forwarded_socket_path = f'{self.listener_socket_address}.original'
            os.rename(self.listener_socket_address, self.forwarded_socket_path)

        self.listener_class.allow_reuse_address = True
        self.listener = self.listener_class(self.listener_socket_address, self.handler_class)
        self.listener.mitm = self

        # Give proper permissions to socket
        if isinstance(self.listener_socket_address, str):
            uid = pwd.getpwnam(WAZUH_UNIX_USER).pw_uid
            gid = grp.getgrnam(WAZUH_UNIX_GROUP).gr_gid
            os.chown(self.listener_socket_address, uid, gid)
            os.chmod(self.listener_socket_address, 0o660)

        self.thread = threading.Thread(target=self.listener.serve_forever)
        self.thread.start()

    def start(self):
        self.run()

    def shutdown(self):
        """Gracefully shutdown a MITM server."""
        self.listener.shutdown()
        self.listener.socket.close()
        self.event.set()
        # Remove created unix socket and restore original
        if isinstance(self.listener_socket_address, str):
            os.remove(self.listener_socket_address)
            os.rename(self.forwarded_socket_path, self.listener_socket_address)

    @property
    def queue(self):
        return self._queue

    def put_queue(self, item):
        self._queue.put(item)
