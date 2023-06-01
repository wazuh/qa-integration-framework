# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import queue
import time

from typing import Callable, Tuple


class QueueMonitor:
    """Class to monitor a queue and check if the content matches with the specified callback.

    Attributes:
        monitored_queue (Queue): Queue to monitor.
        callback_result (*): It will store the result returned by the callback call if it is not None.
        """

    def __init__(self, monitored_queue: queue.Queue) -> None:
        """
        Initialize the QueueMonitor class.

        Args:
            monitored_queue (queue.Queue): Queue to monitor.
        """
        self.monitored_queue: queue.Queue = monitored_queue
        self.callback_result: Tuple = None

    def start(self, callback: Callable, timeout: int = 10, accumulations: int = 1) -> None:
        """
        Start monitoring the target queue using the instance provided regex and accumulate matches.

        This method monitors the target queue using the regex provided during object instantiation.
        It accumulates the matches and stops monitoring when the number of matches reaches the number
        specified by the 'accumulations' attribute.

        If a match is found, the method invokes the callback function specified during object
        instantiation with the matching msg as an argument.

        Returns:
            None
        """
        matches = 0

        # Start count to set the timeout.
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                msg = self.monitored_queue.get(block=True, timeout=0.5)
                matches += self.__msg_matches(msg, callback)
                # If it has triggered the callback the expected times, break and leave the loop
                if matches >= accumulations:
                    break
            except queue.Empty:
                pass

    def __msg_matches(self, msg: str, callback: Callable) -> bool:
        """Determine if a given msg matches the current pattern using the callback function.

        Args:
            msg (str): The msg to search for a match.

        Returns:
            bool: 'True' if the msg matches the pattern, 'False' otherwise.
        """
        result = callback(msg)

        # Update match result only if it's not None (i.e., there was a match)
        self.callback_result = result if result else self.callback_result

        return bool(result)
