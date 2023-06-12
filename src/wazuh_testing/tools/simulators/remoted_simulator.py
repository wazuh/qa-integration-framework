from typing import Any, Literal
import zlib

from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.tools.cipher import Cipher

from .simulator_interface import SimulatorInterface


class RemotedSimulator(SimulatorInterface):

    MODES = ['ACCEPT', 'REJECT', 'DUMMY_ACK',
             'CONTROLLED_ACK', 'WRONG_KEY', 'INVALID_MSG']

    def __init__(self,
                 server_ip: str = '',
                 port: int = 1,
                 protocol: Literal['udp', 'tcp'] = 'udp') -> None:
        super().__init__(server_ip, port, False)
        self.protocol = protocol
        self.__mitm = ManInTheMiddle(address=(self.server_ip, self.port),
                                     family='AF_INET', connection_protocol=self.protocol,
                                     )

    # Properties

    @property
    def mode(self) -> Literal['ACCEPT', 'REJECT']:
        """
        Get the mode of operation for the simulator.

        Returns:
            Literal['ACCEPT', 'REJECT']: The current mode of operation.
        """
        return self.__mode

    @mode.setter
    def mode(self, mode: Literal['ACCEPT', 'REJECT']) -> None:
        """
        Set the mode of operation for the simulator.

        Args:
            mode (Literal['ACCEPT', 'REJECT']): The mode of operation to set.

        Raises:
            ValueError: If the specified mode is not 'ACCEPT' or 'REJECT'.
        """
        if mode.upper() not in self.MODES:
            raise ValueError('Invalid mode.')

        self.__mode = mode.upper()

    # Methods
    
    def start():
        pass

    def shutdown():
        pass

    # Internal methods.

    def __remoted_response_simulation(self, received: Any) -> None:
        if not received:
            raise ValueError('Received message is empty.')
        
        if self.mode == 'REJECT':
            # Simulate a reject from authd.
            self.__mitm.event.set()
            return b'ERROR'