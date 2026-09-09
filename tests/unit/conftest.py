"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Shared fixtures for the unit suite.

Mostly about ports. Several of these tests bind a real TLS listener, and the older ones hardcode
44890-44894; with more test modules that collides, and a collision surfaces as a confusing
"address already in use" in whichever test lost the race. Everything here hands out a port the
kernel just told us was free.

There is deliberately no pytest.ini or pyproject.toml alongside this: setting `pythonpath` would
let a bare `pytest` invocation succeed while silently importing an INSTALLED wazuh_testing rather
than this checkout, and on a machine with the released package present that is exactly the wrong
failure. Keep running these as the module docstrings say, with PYTHONPATH=src.
"""
import socket
import ssl
import time
from typing import Callable, Optional

import pytest

from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator


def free_port() -> int:
    """Return a port nothing is listening on.

    Racy in principle -- the port is released before the caller binds it -- but the window is
    microseconds and the alternative (a fixed port per module) collides deterministically.
    """
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def anchored_context(ca_pem: bytes) -> ssl.SSLContext:
    """A client context trusting exactly one CA, fully verifying, with no system anchors.

    This is the posture of the bootstrap's verified reconnect: `cadata` rather than a file so the
    fetched PEM is used exactly as it arrived, and no load_default_certs() call, so the only
    thing that can vouch for the listener is the certificate handed in.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca_pem.decode())
    return context


def unverified_context(minimum_version: Optional[ssl.TLSVersion] = None) -> ssl.SSLContext:
    """A client context that verifies nothing -- the posture of the unverified /cacerts fetch."""
    context = ssl._create_unverified_context()
    if minimum_version is not None:
        context.minimum_version = minimum_version
    return context


def wait_until(predicate: Callable[[], bool], timeout: float = 5.0,
               interval: float = 0.05) -> bool:
    """Poll `predicate` until it is true or `timeout` elapses. Returns what it last saw.

    Needed for anything observed on the server thread. A TLS alert in particular does not arrive
    while the client call that provoked it is still returning: a client rejecting the served
    certificate raises locally and the server only learns of it when the alert lands, which is
    after the exception has already propagated.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def simulator_factory():
    """Build RemotedSimulators on free ports and tear every one of them down.

    Yields a callable taking the same keyword arguments as RemotedSimulator; `port` is filled in
    when omitted. Instances are destroyed at teardown even if the test failed mid-flight, which
    matters because a leaked listener holds its port for the rest of the session.
    """
    built = []

    def build(**kwargs) -> RemotedSimulator:
        kwargs.setdefault('port', free_port())
        simulator = RemotedSimulator(**kwargs)
        built.append(simulator)
        return simulator

    yield build

    for simulator in built:
        try:
            simulator.destroy()
        except Exception:
            pass
