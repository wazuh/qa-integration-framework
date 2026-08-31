"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Unit tests for RemotedSimulator's reverse-proxy `prefix` support (wazuh#38624 /
qa-integration-framework#835): whether it routes bare, default-prefixed or custom-prefixed
requests, depending on the `prefix` constructor argument's three modes.
"""
import pytest
import requests
import urllib3

from wazuh_testing.tools.simulators.remoted_simulator import (
    DEFAULT_MANAGER_ENDPOINT_PREFIX, RemotedSimulator,
)

# The simulator's certificate is self-signed and not meant to be verified by tests.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------------------------------------------------------------------------------
# strip_prefix(): pure routing logic, no HTTP involved.
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize('path, expected', [
    ('/control', '/control'),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', '/control'),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}', ''),
    ('/other-proxy/control', '/other-proxy/control'),
])
def test_strip_prefix_lenient_default(path, expected):
    """prefix=None accepts bare-root and the real manager's default prefix alike."""
    simulator = RemotedSimulator()
    assert simulator.prefix is None
    assert simulator.strip_prefix(path) == expected


@pytest.mark.parametrize('path, expected', [
    ('/control', '/control'),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', None),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}', f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}'),
    ('/other-proxy/control', None),
])
def test_strip_prefix_strict_opt_out(path, expected):
    """prefix='' rejects any path with an extra leading segment, default prefix or not.

    A single-segment path never has an extra segment to strip -- including, degenerately,
    a bare ``/wazuh-manager`` with nothing after it, which passes through unchanged even
    though it isn't a real endpoint either; that case 404s downstream the same way any
    other unrecognized bare path would, prefix-aware or not.
    """
    simulator = RemotedSimulator(prefix='')
    assert simulator.strip_prefix(path) == expected


@pytest.mark.parametrize('path, expected', [
    ('/custom-proxy/control', '/control'),
    ('/custom-proxy', ''),
    ('/control', None),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', None),
    ('/other-proxy/control', None),
])
def test_strip_prefix_strict_custom(path, expected):
    """A non-empty prefix requires exactly that prefix; anything else is unroutable (None)."""
    simulator = RemotedSimulator(prefix='custom-proxy')
    assert simulator.strip_prefix(path) == expected


def test_get_requests_filters_by_bare_path_regardless_of_prefix():
    """get_requests(path) matches by logical endpoint, whatever prefix arrived on the wire."""
    simulator = RemotedSimulator()  # lenient default
    simulator.record_request('POST', '/control', {}, b'{}')
    simulator.record_request('POST', f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', {}, b'{}')
    simulator.record_request('POST', '/stateless', {}, b'{}')

    matches = simulator.get_requests('/control')

    assert len(matches) == 2
    assert {request['path'] for request in matches} == {
        '/control', f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control',
    }


# --------------------------------------------------------------------------------------
# End-to-end: drive the real TLS server to prove do_POST actually wires strip_prefix in,
# not just that the pure function is correct in isolation.
# --------------------------------------------------------------------------------------

@pytest.fixture()
def free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def _post(port: int, path: str) -> requests.Response:
    return requests.post(f'https://127.0.0.1:{port}{path}', json={'type': 'notify'},
                         verify=False, timeout=5)


@pytest.mark.parametrize('prefix, path, expected_status', [
    (None, '/control', 200),
    (None, f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', 200),
    (None, '/other-proxy/control', 404),
    ('', '/control', 200),
    ('', f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', 404),
    ('', '/other-proxy/control', 404),
    ('custom-proxy', '/custom-proxy/control', 200),
    ('custom-proxy', '/control', 404),
    ('custom-proxy', f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', 404),
])
def test_routing_over_real_https(free_port, prefix, path, expected_status):
    """The actual TLS server 404s or dispatches exactly as strip_prefix's mode dictates."""
    simulator = RemotedSimulator(port=free_port, prefix=prefix)
    simulator.start()
    try:
        response = _post(free_port, path)
        assert response.status_code == expected_status
    finally:
        simulator.destroy()


@pytest.mark.parametrize('mode', ['REJECT_AUTH', 'BAD_REQUEST', 'SERVICE_UNAVAILABLE'])
@pytest.mark.parametrize('path', [
    f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control',
    '/other-proxy/control',
])
def test_prefix_routing_miss_wins_over_fault_injection(free_port, mode, path):
    """A routing miss is decided before fault injection, for every fault mode.

    Regression test: prefix='' previously let a prefixed request (whether under the real
    default prefix or an arbitrary one) fall through to fault injection instead of 404ing
    immediately -- a REJECT_AUTH/BAD_REQUEST/SERVICE_UNAVAILABLE simulator would answer it
    with its fault status instead of the 404 a real unprefixed manager's reverse proxy
    (which has no prefix concept to route through at all) would give it.
    """
    simulator = RemotedSimulator(port=free_port, prefix='', mode=mode)
    simulator.start()
    try:
        response = _post(free_port, path)
        assert response.status_code == 404
    finally:
        simulator.destroy()
