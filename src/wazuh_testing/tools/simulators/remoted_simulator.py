# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from queue import Queue
from typing import Any, Literal, Union

from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.utils import secure_message
from wazuh_testing.utils.client_keys import get_client_keys

from .simulator_interface import SimulatorInterface


# Internal constants
_RESPONSE_ACK = b'#!-agent ack '
_RESPONSE_SHUTDOWN = b'#!-agent shutdown '
_RESPONSE_EMPTY = b''


class RemotedSimulator(SimulatorInterface):
    """
    A class that simulates a Remoted service.

    This class inherits from SimulatorInterface and implements methods to send and receive messages
    from a Wazuh server using a ManInTheMiddle object. It also allows to specify different modes of
    operation to simulate different scenarios.

    Attributes:
        MODES (list): A list of valid modes for the simulator.
        mode (str): The current mode of the simulator.
        protocol (str): The connection protocol used by the simulator ('udp' or 'tcp').
        keys_path (str): The path to the file containing the client keys.
        custom_message (bytes): A custom response message to send to the server instead of the default one.
        last_message_ctx (dict): A dictionary that stores the context of the last received message.
    """
    MODES = ['ACCEPT', 'WRONG_KEY', 'INVALID_MSG']

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = 1514,
                 mode='ACCEPT',
                 protocol: Literal['udp', 'tcp'] = 'tcp',
                 keys_path: str = WAZUH_CLIENT_KEYS_PATH) -> None:
        """
        Initialize a RemotedSimulator object.

        Args:
            server_ip (str, optional): The IP address of the Wazuh server. Defaults: '127.0.0.1'.
            port (int, optional): The port number of the Wazuh server. Defaults: 1514.
            mode (str, optional): The mode of the simulator. Must be one of MODES. Defaults: 'ACCEPT'.
            protocol (str, optional): The connection protocol used by the simulator ('udp' or 'tcp'). Defaults: 'tcp'.
            keys_path (str, optional): The path to the wazuh client keys file. Defaults: BASE_CONF_PATH/client.keys'.
        """
        super().__init__(server_ip, port, False)

        self.mode = mode
        self.protocol = protocol
        self.keys_path = keys_path
        self.__mitm = ManInTheMiddle(address=(self.server_ip, self.port),
                                     family='AF_INET', connection_protocol=self.protocol,
                                     func=self.__remoted_response_simulation)

        self.custom_message = None
        self.last_message_ctx = {}

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
        self.__mitm.start()
        self.running = True

    def shutdown(self) -> None:
        """
        Shutdown the simulator and the MitM object.
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

    def send_custom_message(self, message: Union[str, bytes]) -> None:
        """
        Send a custom message to the connected wazuh agent.

        Args:
            message (Union[str, bytes]): The message to send. Can be a string or bytes.

        Raises:
            TypeError: If message is not a string or bytes.
        """
        if not isinstance(message, (str, bytes)):
            raise TypeError('Message must be a string or bytes.')

        if not isinstance(message, bytes):
            message = message.encode()

        self.custom_message = message
        self.custom_message_sent = False

    # Internal methods.

    def __remoted_response_simulation(self, _request: Any) -> bytes:
        """
        Simulate a Remoted response to an agent based on the received message and the
        mode of operation.

        This method is passed as a callback function to the MitM object and is executed
        for every received message.

        Args:
            _request (Any): The received message from the agent.

        Returns:
            bytes: The response message to send back to the agent. If protocol is 'tcp',
                   then it also includes a header with the length of the response.
        """
        if not _request:
            self.__mitm.event.set()
            return _RESPONSE_EMPTY

        if b'#ping' in _request:
            return b'#pong'

        # Save message context.
        self.__set_encryption_values(_request)
        self.__save_message_context(_request)
        # Decrypt and decode the request message.
        _request = self.__decrypt_received_message(_request)

        # Set the correct response message.
        if self.mode == 'WRONG_KEY':
            self.encryption_key = secure_message.get_encryption_key('a', 'b', 'c')
            response = _RESPONSE_ACK
        elif self.mode == 'INVALID_MSG':
            response = b'INVALID'
        elif '#!-agent shutdown' in _request:
            self.__mitm.event.set()
            response = _RESPONSE_SHUTDOWN
        elif '#!-' in _request:
            response = _RESPONSE_ACK
        elif self.custom_message and not self.custom_message_sent:
            response = self.custom_message
            self.custom_message_sent = True
        else:
            return _RESPONSE_EMPTY

        # Encrypt the response.
        response = self.__encrypt_response_message(response)

        if self.protocol == "tcp":
            return secure_message.pack(len(response)) + response

        return response

    def __get_client_keys(self):
        """
        Get the client keys from the keys file.

        Returns:
            bytes: The encryption key derived from the client keys.
        """
        client_keys = get_client_keys(self.keys_path)[0]
        client_keys.pop('ip')

        return secure_message.get_encryption_key(**client_keys)

    def __decrypt_received_message(self, message: bytes) -> str:
        """
        Decrypt and decode a received message from the agent.

        Args:
            message (bytes): The received message from the agent.

        Returns:
            str: The decrypted and decoded message.
        """
        payload = secure_message.get_payload(message, self.algorithm)
        decrypted = secure_message.decrypt(payload, self.encryption_key, self.algorithm)

        return secure_message.decode(decrypted)

    def __encrypt_response_message(self, message: bytes) -> str:
        """
        Encrypt and encode a response message to the agent.

        Args:
            message (bytes): The response message to the agent.

        Returns:
            bytes: The encrypted and encoded message with an algorithm header.
        """
        encoded = secure_message.encode(message)
        payload = secure_message.encrypt(encoded, self.encryption_key, self.algorithm)

        return secure_message.set_algorithm_header(payload, self.algorithm)

    def __set_encryption_values(self, message: bytes) -> None:
        # Get the decryption/encryption algorithm and key.
        self.algorithm = secure_message.get_algorithm(message)
        self.encryption_key = self.__get_client_keys()

    def __save_message_context(self, message: bytes) -> None:
        """
        Save the context of a received message from the agent.

        The context includes the agent ID, counter and checksum of the message.

        Args:
            message (bytes): The received message from the agent.
        """
        if agent_id := secure_message.get_agent_id(message):
            self.last_message_ctx['id'] = agent_id
        else:
            self.last_message_ctx['ip'] = self.__mitm.listener.last_address[0]

        self.last_message_ctx['algorithm'] = self.algorithm
