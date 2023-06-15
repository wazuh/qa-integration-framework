from queue import Queue
from typing import Any, Literal, List

from wazuh_testing.constants.paths.configurations import BASE_CONF_PATH
from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.tools.secure_message import SecureMessage
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

        # Get and save the agent keys.
        client_keys = keys.get_client_keys(self.keys_path)[0]

        # Decrypt the received message.
        client_keys.pop('ip', None)
        encryption_key = keys.create_encryption_key(**client_keys)
        
        
        identifier = self.__get_agent_identifier(received)

        payload, algo = SecureMessage.extract_payload_and_algorithm(received)
        decrypted_message = SecureMessage.decrypt(payload, encryption_key, algo)
        msg_decoded = SecureMessage.decompress_and_decode(decrypted_message)
        

        print(f'DECRYPTED MESSAGE: {msg_decoded}')

        if '#!-' in msg_decoded:
            print('NECESITA RESPUESTA')

        if self.mode == 'REJECT':
            # Simulate a reject from authd.
            response = 'ERROR'

        self.__mitm.event.set()
        return response.encode()

    def __get_agent_identifier(self, message: bytes) -> dict:
        agent_id = SecureMessage.extract_agent_id(message)
        if not agent_id:
            return {'ip': self.__mitm.listener.last_address[0]}
        return {'id': agent_id}