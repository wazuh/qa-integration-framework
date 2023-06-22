from queue import Queue
from struct import pack
from typing import Any, Literal, List, Tuple, Union

from wazuh_testing.constants.paths.configurations import BASE_CONF_PATH
from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.tools.secure_message import SecureMessage
from wazuh_testing.utils import keys

from .simulator_interface import SimulatorInterface


class RemotedSimulator(SimulatorInterface):

    MODES = ['DUMMY', 'CONTROLLED', 'WRONG_KEY', 'INVALID_MSG']

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = 1514,
                 mode='CONTROLLED',
                 protocol: Literal['udp', 'tcp'] = 'tcp',
                 keys_path: str = f'{BASE_CONF_PATH}/client.keys') -> None:
        super().__init__(server_ip, port, False)

        self.mode = mode
        self.protocol = protocol
        self.keys_path = keys_path
        self.__mitm = ManInTheMiddle(address=(self.server_ip, self.port),
                                     family='AF_INET', connection_protocol=self.protocol,
                                     func=self.__remoted_response_simulation)

        self.special_response = None
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
        if self.running:
            return
        self.__mitm.start()
        self.running = True

    def shutdown(self) -> None:
        if not self.running:
            return
        self.__mitm.shutdown()
        self.running = False

    def send(self, message: Union[str, bytes]) -> None:
        if not isinstance(message, bytes):
            message.encode()
        self.special_response = message

    # Internal methods.

    def __remoted_response_simulation(self, received: Any) -> None:
        if not received:
            self.__mitm.event.set()
            return b''
        if b'#ping' in received:
            return b'#pong'

        # Get the decryption/encryption algorithm and key.
        algorithm = SecureMessage.get_algorithm(received)
        key = self.__get_client_keys()
        # Save message context.
        self.__save_message_context(received, algorithm)
        # Decrypt and decode the received message.
        received = self.__decrypt_received_message(received, key, algorithm)

        # Set the correct response message.
        if self.special_response and '#!-' not in received:
            response = self.special_response
        elif self.mode == 'CONTROLLED':
            if '#!-' not in received:
                response = b''
            elif 'agent shutdown' in received:
                self.__mitm.event.set()
                response = b'#!-agent shutdown '
            else:
                response = b'#!-agent ack '
        elif self.mode == 'DUMMY':
            response = b'#!-agent ack '
        elif self.mode == 'WRONG_KEY':
            key = keys.create_encryption_key('inv', 'inv', 'inv')
            response = b'#!-agent ack '
        elif self.mode == 'INVALID_MSG':
            response = b'INVALID'

        response = self.__encrypt_response_message(response, key, algorithm)

        if self.protocol == "tcp":
            return pack('<I', len(response)) + response

        return response

    def __get_client_keys(self):
        client_keys = keys.get_client_keys(self.keys_path)[0]
        client_keys.pop('ip')

        return keys.create_encryption_key(**client_keys)

    def __decrypt_received_message(self, message: bytes, key: bytes, algorithm: str) -> str:
        payload = SecureMessage.get_payload(message, algorithm)
        decrypted = SecureMessage.decrypt(payload, key, algorithm)

        return SecureMessage.decode(decrypted)

    def __encrypt_response_message(self, message: bytes, key: bytes, algorithm: str) -> str:
        encoded = SecureMessage.encode(message)
        payload = SecureMessage.encrypt(encoded, key, algorithm)

        return SecureMessage.set_algorithm_header(payload, algorithm)

    def __save_message_context(self, message: bytes, algorithm: str) -> None:
        if agent_id := SecureMessage.get_agent_id(message):
            self.last_message_ctx['id'] = agent_id
        else:
            self.last_message_ctx['ip'] = self.__mitm.listener.last_address[0]

        self.last_message_ctx['algorithm'] = algorithm
