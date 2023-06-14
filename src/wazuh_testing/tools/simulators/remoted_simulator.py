from queue import Queue
from typing import Any, Literal, List

from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.tools.cipher import Cipher

from .simulator_interface import SimulatorInterface


class RemotedSimulator(SimulatorInterface):

    MODES = ['REJECT', 'DUMMY_ACK',
             'CONTROLLED_ACK', 'WRONG_KEY', 'INVALID_MSG']

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = 1514,
                 mode='REJECT',
                 protocol: Literal['udp', 'tcp'] = 'tcp') -> None:
        super().__init__(server_ip, port, False)

        self.protocol = protocol
        self.mode = mode
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

        received, identifier = self.__get_message_and_identifier(received)
        
        print(received)
        print(identifier)

        if self.mode == 'REJECT':
            # Simulate a reject from authd.
            response = 'ERROR'

        self.__mitm.event.set()
        return response.encode()

    def __get_message_and_identifier(self, message: bytes) -> List[bytes | str]:
        index = message.find(b'!')
        if index == 0:
            index = message[1:].find(b'!')
            agent_identifier = {'id': message[1:index + 1].decode()}
            message = message[index + 2:]
        else:
            agent_identifier = {'ip': self.__mitm.listener.last_address[0]}
        return message, agent_identifier