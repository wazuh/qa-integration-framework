from queue import Queue
from struct import pack
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
        self.special_response = ''

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
            self.__mitm.event.set()
            return
            raise ValueError('Received message is empty.')

        # handle ping pong response
        if received == b'#ping':
            response = '#pong'

        # Get the client keys and prepare encryption key.
        client_keys = keys.get_client_keys(self.keys_path)[0]
        client_keys.pop('ip', None)
        encryption_key = keys.create_encryption_key(**client_keys)

        # Get agent identifier. ID or IP.
        identifier = self.__get_agent_identifier(received)

        # Decrypt and decode the received message.
        decrypted_message = SecureMessage.decrypt(received, encryption_key)
        msg_decoded = SecureMessage.decode(decrypted_message)

        print(f'DECRYPTED MESSAGE: {msg_decoded}')

        if '#!-' in msg_decoded:
            print('NECESITA RESPUESTA')

        if self.mode == 'REJECT':
            # Simulate a reject from authd.
            response = 'ERROR'
        response = SecureMessage.encode(b'#!-agent ack ')
        response = SecureMessage.encrypt(response, encryption_key, 'AES')

        if self.protocol == "tcp":
            length = pack('<I', len(response))
            return length + response
        #!-agent ack 
        # self.__mitm.event.set()
        
        #     def send(self, dst, data):
        # """Send method to write on the socket.

        # Args:
        #     dst (socket): Address to write specified data.
        #     data (socket): Data to be send.
        # """
        #     try:
        #         length = pack('<I', len(data))
        #         dst.send(length + data)
        #     except:
        #         pass
        # self.update_counters()
        # elif self.protocol == "udp":
        #     try:
        #         self.sock.sendto(data, dst)
        #     except:
        #         pass
        if self.special_response:
            return self.special_response
        return response

    def __get_agent_identifier(self, message: bytes) -> dict:
        agent_id = SecureMessage.extract_agent_id(message)
        if not agent_id:
            return {'ip': self.__mitm.listener.last_address[0]}
        return {'id': agent_id}
