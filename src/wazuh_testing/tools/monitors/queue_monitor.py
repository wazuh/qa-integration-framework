"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import queue
import time
from typing import Callable

from .base_monitor import BaseMonitor


class QueueMonitor(BaseMonitor):
    """Class to monitor a queue and check if the content matches with the specified callback.

    Attributes:
        monitored_object (Queue): Queue to monitor.
        callback_result (*): It will store the result returned by the callback call if it is not None.
    """

    def __init__(self, monitored_object: queue.Queue) -> None:
        """
        Initialize the QueueMonitor class.

        Args:
            monitored_object (queue.Queue): Queue to monitor.
        """
        super().__init__(monitored_object=monitored_object)

    def start(self, callback: Callable, timeout: int = 10, accumulations: int = 1, encoding = 'latin-1') -> None:
        """Start monitoring the target queue using the instance provided regex and accumulate matches.

        This method monitors the target queue using the regex provided during object instantiation.
        It accumulates the matches and stops monitoring when the number of matches reaches the number
        specified by the 'accumulations' attribute.

        If a match is found, the method invokes the callback function specified during object
        instantiation with the matching msg as an argument.

        Returns:
            None
        """
        self._clear_results()

        # Start count to set the timeout.
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                item = self.monitored_object.get(block=True, timeout=0.5)

                def check_match(self, msg):
                    msg = msg.decode(encoding, 'ignore') if isinstance(msg, bytes) else msg
                    self.matches += self._match(msg, callback)

                if type(item) is tuple:
                    for msg in item:
                        check_match(self, msg)
                        # If it has triggered the callback the expected times, break and leave the loop
                        if self.matches >= accumulations:
                            break
                else:
                    check_match(self, item)

                # If it has triggered the callback the expected times, break and leave the loop
                if self.matches >= accumulations:
                    break
            except queue.Empty:
                pass
