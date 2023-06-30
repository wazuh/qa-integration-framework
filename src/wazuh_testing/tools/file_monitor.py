# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import time

from typing import Callable, Tuple

from wazuh_testing.utils import file


class FileMonitor:
    """Class to monitor a file and check if the content matches with the specified callback.

    Attributes:
        monitored_file (str): File path to monitor.
        callback_result (*): It will store the result returned by the callback call if it is not None.
        """

    def __init__(self, monitored_file: str) -> None:
        """
        Initialize the FileMonitor class.

        Args:
            monitored_file: File path to monitor.
        """
        self.monitored_file: str = monitored_file
        self.callback_result: Tuple = None

        self.__validate_parameters()

    def __validate_parameters(self) -> None:
        """Validate that the specified file is valid and can be monitored.

        This method checks that the monitored file exists, is a file, and that the program has permission
        to read its contents.

        Raises:
            ValueError: If the monitored file does not exist.
            TypeError: If the monitored file is not a file.
            PermissionError: If the monitored file is not readable.
        """
        # Check that the monitored file exists
        if not os.path.exists(self.monitored_file):
            raise ValueError(f"File {self.monitored_file} does not exist.")

        # Check that the monitored file is a file
        if not os.path.isfile(self.monitored_file):
            raise TypeError(f"{self.monitored_file} is not a file.")

        # Check that the program can read the content of the file
        if not os.access(self.monitored_file, os.R_OK):
            raise PermissionError(f"{self.monitored_file} is not readable.")

    def start(self, callback: Callable, timeout: int = 10, accumulations: int = 1, only_new_events: bool = False) -> None:
        """
        Start monitoring the target file using the instance provided regex and accumulate matches.

        This method monitors the target file using the regex provided during object instantiation.
        It accumulates the matches and stops monitoring when the number of matches reaches the number
        specified by the 'accumulations' attribute. If 'only_new_events' is False, it will also check
        the current content of the file for matches before monitoring the file for new events.

        If a match is found, the method invokes the callback function specified during object
        instantiation with the matching line as an argument.

        Returns:
            None
        """
        matches = 0
        encoding = file.get_file_encoding(self.monitored_file)

        # Check if current file content lines triggers the callback (only when new events has False value)
        if not only_new_events:
            with open(self.monitored_file, encoding=encoding) as _file:
                for line in _file:
                    matches += self.__line_matches(line, callback)
                    if matches >= accumulations:
                        return

        # Start count to set the timeout.
        start_time = time.time()

        # Start the file regex monitoring from the last line.
        with open(self.monitored_file, encoding=encoding) as _file:
            # Go to the end of the file.
            _file.seek(0, 2)
            while time.time() - start_time < timeout:
                current_position = _file.tell()
                line = _file.readline()
                # If we have not new changes wait for the next try.
                if not line:
                    _file.seek(current_position)
                    time.sleep(0.1)
                # If we have a new line, check if it matches with the callback.
                else:
                    matches += self.__line_matches(line, callback)
                    # If it has triggered the callback the expected times, break and leave the loop.
                    if matches >= accumulations:
                        return

    def __line_matches(self, line: str, callback: Callable) -> bool:
        """Determine if a given line matches the current pattern using the callback function.

        Args:
            line (str): The line to search for a match.

        Returns:
            bool: 'True' if the line matches the pattern, 'False' otherwise.
        """
        result = callback(line)

        # Update match result only if it's not None (i.e., there was a match)
        self.callback_result = result if result else self.callback_result

        return bool(result)
