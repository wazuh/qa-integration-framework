# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from abc import ABC, abstractmethod


class BaseSimulator(ABC):
    """
    An abstract base class that defines the interface for a simulator.

    A simulator is a class that can simulate the behavior of a Wazuh component
    by sending and receiving messages through a socket.

    Attributes:
        MODES (list): A list of valid modes for the simulator.
        server_ip (str): The IP address of the Wazuh server.
        port (int): The port number of the Wazuh server.
        running (bool): A flag that indicates if the simulator is running or not.
        mode (str): The current mode of the simulator. Must be one of MODES.
    """

    MODES: list

    def __init__(self, server_ip: str, port: int, running: bool) -> None:
        """
        Initialize a BaseSimulator object.

        Args:
            server_ip (str): The IP address of the Wazuh server.
            port (int): The port number of the Wazuh server.
            running (bool): A flag that indicates if the simulator is running or not.
        """
        self.server_ip = server_ip
        self.port = port
        self.running = running

    @property
    def mode(self):
        """
        Get the mode of the simulator.

        Returns:
            str: The current mode of the simulator.
        """
        return self.__mode

    @mode.setter
    def mode(self, mode: str) -> None:
        """
        Set the mode of the simulator.

        Raises:
            ValueError: If the mode is not one of MODES.
        """
        if mode.upper() not in self.MODES:
            raise ValueError(f'Invalid mode. Modes: {self.MODES}')

        self.__mode = mode.upper()

    @abstractmethod
    def start():
        """
        Start the simulator.

        This method should be implemented by subclasses to start the simulation process.
        """
        pass

    @abstractmethod
    def shutdown():
        """
        Shutdown the simulator.

        This method should be implemented by subclasses to stop the simulation process.
        """
        pass
