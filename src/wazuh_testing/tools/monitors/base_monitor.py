# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from abc import ABC, abstractmethod
from ast import Tuple
from typing import Any, Callable


class BaseMonitor(ABC):

    def __init__(self, monitored_object: Any) -> None:
        """
        Initialize a BaseMonitor object.

        Args:
        """
        self.monitored_object: Any = monitored_object
        self.callback_result: Tuple = None

    @abstractmethod
    def start():
        """
        Start the Monitor.

        This method should be implemented by subclasses to start the monitoring process.
        """
        pass

    def __clear_results(self) -> None:
        """
        Clear the callback_result the Monitor.

        This method should be implemented by subclasses to clear the saved results.
        """
        self.callback_result = None

    def __match(self, message: str, callback: Callable) -> bool:
        """Determine if a given message matches the current pattern using the callback function.

        Args:
            message (str): The message to search for a match.

        Returns:
            bool: 'True' if the message matches the pattern, 'False' otherwise.
        """
        result = callback(message)

        # Update match result only if it's not None (i.e., there was a match)
        self.callback_result = result if result else self.callback_result

        return bool(result)
