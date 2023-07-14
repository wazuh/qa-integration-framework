"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import logging
from functools import wraps
from time import sleep
from typing import Union, Tuple, Any


def retry(exceptions: Union[Exception, Tuple], attempts: int = 5, delay: int = 1, delay_multiplier: int = 2) -> Any:
    """Decorator used to retry functions.

    This function will execute `func` multiple times until the max number of attempts is reached or
    the function is executed without errors.

    Args:
        exceptions (Exception or tuple): which exceptions to catch.
        attempts (int): number of times to retry the execution of func before abort.
        delay (int): number of seconds to wait between successive attempts.
        delay_multiplier (int): factor to multiply the wait time on each attempt.

    Example:
        @retry(requests.exceptions.Timeout, attempts=10, delay=5, backoff=0)
        def send_message(msg, dest):
    """
    def retry_function(func):
        wraps(func)

        def to_retry(*args, **kwargs):
            attempt, wait_time, wait_multiplier, excepts = attempts, delay, delay_multiplier, exceptions
            while attempt > 0:
                try:
                    return func(*args, **kwargs)
                except excepts as exception:
                    wait_time *= wait_multiplier
                    attempt -= 1
                    msg = f'Exception: "{exception}". {attempt}/{attempts} remaining attempts. ' \
                          f'Waiting {wait_time} seconds.'
                    logging.warning(msg)
                    sleep(wait_time)
            return func(*args, **kwargs)  # final attempt
        return to_retry  # actual decorator

    return retry_function
