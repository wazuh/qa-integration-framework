from abc import ABC, abstractmethod


class SimulatorInterface(ABC):
    MODES: list

    def __init__(self, server_ip: str, port: int, running: bool) -> None:
        self.server_ip = server_ip
        self.port = port
        self.running = running

    @property
    def mode(self):
        """
        Get the mode of operation for the simulator.

        Returns:
            str: The current mode of operation.
        """
        return self.__mode

    @mode.setter
    def mode(self, mode: str) -> None:
        """
        Set the mode of operation for the simulator.
        It must be a valid mode from the list MODES.

        Args:
            mode str): The mode of operation to set.

        Raises:
            ValueError: If the specified mode is not valid.
        """
        if mode.upper() not in self.MODES:
            raise ValueError(f'Invalid mode. Modes: {self.MODES}')

        self.__mode = mode.upper()

    @abstractmethod
    def start():
        pass

    @abstractmethod
    def shutdown():
        pass
