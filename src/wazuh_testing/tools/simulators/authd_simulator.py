# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from queue import Queue
import ssl
from typing import List, Literal, Any

from wazuh_testing.constants.paths.configurations import BASE_CONF_PATH
from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.tools.certificate_controller import CertificateController

from .base_simulator import BaseSimulator


class AuthdSimulator(BaseSimulator):
    """
    A class that simulates an Authd service.

    This class inherits from BaseSimulator and implements methods to send and receive messages
    from a Wazuh server using a ManInTheMiddle object. It also allows to specify different modes of
    operation to simulate different scenarios.

    Attributes:
        server_ip (str): The IP address of the Authd server. Defaults: '127.0.0.1'.
        port (int): The port number of the Authd server. Defaults: 1515.
        running (bool): The actual status of the simulator. Initial state False.
        secret (str): The secret key used by the Authd server. Defaults: 'SuperSecretKey'.
        mode (Literal['ACCEPT', 'REJECT']): The mode of operation for the simulator. Valid values are 'ACCEPT'
                                            and 'REJECT'. Defaults: 'ACCEPT'.
        key_path (str): The path for the SSL key used by the server. Defaults: 'BASE_CONF_PATH/manager.key'.
        cert_path (str): The path for the SSL certificate used by the server. Defaults: 'BASE_CONF_PATH/manager.cert'.
        queue (Queue): The MitM Queue object used for storing received messages.
    """
    MODES = ['ACCEPT', 'REJECT']

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = 1515,
                 secret: str = 'SuperSecretKey',
                 mode: Literal['ACCEPT', 'REJECT'] = 'ACCEPT',
                 key_path: str = f'{BASE_CONF_PATH}/manager.key',
                 cert_path: str = f'{BASE_CONF_PATH}/manager.cert') -> None:
        """
        Initializes an AuthdSimulator object.

        Args:
            server_ip (str): The IP address of the Authd server.
            port (int): The port number of the Authd server
            secret (str): The secret key used by the Authd server.
            mode (Literal['ACCEPT', 'REJECT']): The mode of operation for the simulator.
            key_path (str): The file path for the SSL key used by the server.
            cert_path (str): The file path for the SSL certificate used by the server.
        """
        super().__init__(server_ip=server_ip, port=port, running=False)

        self.secret = secret
        self.mode = mode
        self.key_path = key_path
        self.cert_path = cert_path

        self.agent_id = 0
        self.cert_controller = CertificateController()

        self.__mitm = ManInTheMiddle(address=(self.server_ip, self.port),
                                     family='AF_INET', connection_protocol='SSL',
                                     func=self.__authd_response_simulation)

    # Properties

    @property
    def queue(self) -> Queue:
        """
        Get the queue used for storing received messages.

        Returns:
            Queue: MitM queue object that stores received messages.
        """
        return self.__mitm.queue

    # Methods

    def start(self) -> None:
        """
        Start the simulator and the MitM object.
        """
        if self.running:
            return
        self.__generate_certificates()
        self.__mitm.start()
        self.__mitm.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLS_SERVER,
                                                   certificate=self.cert_path, keyfile=self.key_path)
        self.running = True

    def shutdown(self) -> None:
        """
        Shutdown Man in the middle connection.
        """
        if not self.running:
            return
        self.__mitm.shutdown()
        self.running = False

    def clear(self) -> None:
        """
        Clear the queue and the event of the MitM object.

        This method removes all the messages from the queue and resets the event to False.
        """
        while not self.__mitm.queue.empty():
            self.__mitm.queue.get_nowait()
        self.__mitm.event.clear()

    def destroy(self) -> None:
        """
        Clear and shutdown the simulator.
        """
        self.clear()
        self.shutdown()

    # Internal methods.

    def __authd_response_simulation(self, _request: Any) -> bytes:
        """
        Simulate an Authd response to an agent based on the received message and the mode
        of operation.

        This method is passed as a callback function to the MitM object and is executed
        for every received message.

        Args:
            _request (Any): The received message from the agent.

        Raises:
            ValueError: If the received message is empty.

        Returns:
            bytes: The response message to send back to the agent.
        """
        if not _request:
            raise ValueError('Received message is empty.')

        if self.mode == 'REJECT':
            # Simulate a reject from authd.
            self.__mitm.event.set()
            return b'ERROR'

        self.agent_id += 1

        # Parse the received message and create the simulated response.
        msg_sections = _request.decode().split(' ')
        agent_info = self.__set_agent_info(msg_sections)
        response = f"OSSEC K:'{self.agent_id:03d} {agent_info['name']} {agent_info['ip']} {self.secret}'\n"

        # Notify the MitM event.
        self.__mitm.event.set()

        return response.encode()

    def __set_agent_info(self, msg_sections: List[str]) -> dict:
        """Extracts agent information from the message sections.

        Args:
            msg_sections (List[str]): The list of message sections to process.

        Returns:
            dict: A dictionary containing the agent information with the following keys:
                - 'id': The agent ID (same as self.agent_id).
                - 'name': The agent name extracted from the message sections.
                - 'ip': The agent IP address extracted from the message sections.
        """
        agent_info = {'id': self.agent_id, 'name': None, 'ip': None}

        for section in msg_sections:
            # Extract the name and ip from the message sections.
            if section.startswith('A:'):
                agent_info['name'] = section.split("'")[1]
            elif section.startswith('IP:'):
                agent_info['ip'] = section.split("'")[1]

        # If the IP has no value set it as any.
        agent_info['ip'] = agent_info.get('ip') or 'any'
        if agent_info['ip'] == 'src':
            # The IP is src so set the actual agent IP.
            agent_info['ip'] = self.__mitm.listener.last_address[0]

        return agent_info

    def __generate_certificates(self):
        """Generates and stores certificates for the root CA.

        It signs the root CA certificate with the root CA private key using
        the specified digest algorithm.
        The generated root CA certificate and private key are then stored
        at the provided paths.
        """
        self.cert_controller.root_ca_cert.sign(
            self.cert_controller.root_ca_key, self.cert_controller.digest)
        self.cert_controller.store_private_key(
            self.cert_controller.root_ca_key, self.key_path)
        self.cert_controller.store_ca_certificate(
            self.cert_controller.root_ca_cert, self.cert_path)
