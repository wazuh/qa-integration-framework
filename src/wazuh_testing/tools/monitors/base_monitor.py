# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from abc import ABC, abstractmethod
from ast import Tuple
from typing import Any, Callable


class BaseMonitor(ABC):
    """
    A base class that defines the interface for a monitor.

    A monitor is a class that checks for a message to appear on the monitored object
    until the timeout is reached.

    Attributes:
        monitored_object (Any): The object to be monitored.
        callback_result (Tuple): The result of the callback function.
    """

    def __init__(self, monitored_object: Any) -> None:
        """
        Initialize a BaseMonitor object.

        Args:
            monitored_object (Any): The object to be monitored.
        """
        self.monitored_object: Any = monitored_object
        self.callback_result: Tuple = None
        self.matches = 0

    @abstractmethod
    def start():
        """
        Start the Monitor.

        This method should be implemented by subclasses to start the monitoring process.
        """
        pass

    def _clear_results(self) -> None:
        """
        Clear the monitor's callback_result.
        """
        self.callback_result = None
        self.matches = 0

    def _match(self, message: str, callback: Callable) -> bool:
        """Determine if a given message matches the current pattern using the callback function.

        Args:
            message (str): The message to search for a match.

        Returns:
            bool: 'True' if the message matches the pattern, 'False' otherwise.
        """
        result = callback(message)

        # Update match result only if it's not None (i.e., there was a match)
        if result:
            # Create a list in case accumulations is greater than 1
            if self.callback_result:
                if type(self.callback_result) != list or (type(result) == list and type(self.callback_result[0]) != list) :
                    self.callback_result = [self.callback_result, result]
                else:
                    self.callback_result.append(result)
            else:
                self.callback_result = result

        return bool(result)
