from queue import Queue
import re
from typing import Any, Literal, List
from wazuh_testing.constants.paths.configurations import BASE_CONF_PATH

from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.tools.cipher import Cipher
from wazuh_testing.utils import keys

from .simulator_interface import SimulatorInterface


class RemotedSimulator(SimulatorInterface):

    MODES = ['REJECT', 'DUMMY_ACK',
             'CONTROLLED_ACK', 'WRONG_KEY', 'INVALID_MSG']

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = 1514,
                 mode='REJECT',
                 protocol: Literal['udp', 'tcp'] = 'tcp',
                 keys_path: str = f'{BASE_CONF_PATH}/client.keys') -> None:
        super().__init__(server_ip, port, False)

        self.mode = mode
        self.protocol = protocol
        self.keys_path = keys_path
        self.__mitm = ManInTheMiddle(address=(self.server_ip, self.port),
                                     family='AF_INET', connection_protocol=self.protocol,
                                     func=self.__remoted_response_simulation)

    # Properties

    @property
    def mode(self):
        return self.__mode

    @mode.setter
    def mode(self, mode) -> None:
        if mode.upper() not in self.MODES:
            raise ValueError('Invalid mode.')

        self.__mode = mode.upper()

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

    # Internal methods.

    def __remoted_response_simulation(self, received: Any) -> None:
        if not received:
            raise ValueError('Received message is empty.')

        # handle ping pong response
        if received == b'#ping':
            response = '#pong'

        identifier = self.__get_agent_identifier(received)
        print(f'AGENT IDENTIFIER: {identifier}')

        data = Cipher.get_encrypted_payload(received)
        print(f'FILTERED DATA: {data}')

        client_keys = keys.get_client_keys(self.keys_path)
        # Save the keys in case the file doesn't exists.
        keys.save_client_keys(client_keys, self.keys_path)
        
        encription = keys.create_encryption_key(**client_keys.pop('ip', None))

        if self.mode == 'REJECT':
            # Simulate a reject from authd.
            response = 'ERROR'

        self.__mitm.event.set()
        return response.encode()

    def __get_agent_identifier(self, message: bytes) -> dict:
        if (start_index := message.find(b'!') + 1) is not -1:
            # The message comes with the agent ID.
            end_index = message.find(b'!', start_index)
            agent_identifier = {'id': message[start_index: end_index].decode()}
        else:
            # Get the agent IP.
            agent_identifier = {'ip': self.__mitm.listener.last_address[0]}
        return agent_identifier
