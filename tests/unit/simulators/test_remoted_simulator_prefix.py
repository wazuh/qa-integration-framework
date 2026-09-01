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
# resolve_endpoint(): pure routing logic, no HTTP involved.
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize('path, expected', [
    ('/control', '/control'),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', '/control'),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}', None),
    ('/other-proxy/control', None),
])
def test_resolve_endpoint_lenient_default(path, expected):
    """prefix=None accepts bare-root and the real manager's default prefix alike."""
    simulator = RemotedSimulator()
    assert simulator.prefix is None
    assert simulator.resolve_endpoint(path) == expected


@pytest.mark.parametrize('path, expected', [
    ('/control', '/control'),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', None),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}', None),
    ('/other-proxy/control', None),
])
def test_resolve_endpoint_strict_opt_out(path, expected):
    """prefix='' rejects any path with an extra leading segment, default prefix or not."""
    simulator = RemotedSimulator(prefix='')
    assert simulator.resolve_endpoint(path) == expected


@pytest.mark.parametrize('path, expected', [
    ('/custom-proxy/control', '/control'),
    ('/custom-proxy', None),
    ('/control', None),
    (f'/{DEFAULT_MANAGER_ENDPOINT_PREFIX}/control', None),
    ('/other-proxy/control', None),
])
def test_resolve_endpoint_strict_custom(path, expected):
    """A non-empty prefix requires exactly that prefix; anything else is unroutable (None)."""
    simulator = RemotedSimulator(prefix='custom-proxy')
    assert simulator.resolve_endpoint(path) == expected


@pytest.mark.parametrize('path, expected', [
    ('/gateway/wazuh-manager/control', '/control'),
    ('/gateway/wazuh-manager/stateless', '/stateless'),
    # A one-segment prefix short of the configured two-segment one is a routing miss, not
    # a partial match -- confirms this is literal path equality, not a startswith check.
    ('/gateway/control', None),
    ('/wazuh-manager/control', None),
])
def test_resolve_endpoint_multi_segment_prefix(path, expected):
    """A multi-segment prefix (the agent supports host:port/gateway/wazuh-manager, see
    src/unit_tests/config/test_client-config_https.c:810) resolves correctly: literal
    path equality needs no special-casing for how many segments the prefix has.
    """
    simulator = RemotedSimulator(prefix='gateway/wazuh-manager')
    assert simulator.resolve_endpoint(path) == expected


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


def test_get_requests_finds_a_request_resolve_endpoint_would_reject():
    """A request get_requests(path) returns for a strict simulator can still have been a
    404 -- the point of recording it is to let a test assert exactly that ("the agent sent
    the wrong prefix and got 404"), which requires finding it by its bare endpoint name
    even though resolve_endpoint() rejects it.
    """
    simulator = RemotedSimulator(prefix='wazuh-manager')  # strict
    simulator.record_request('POST', '/control', {}, b'{}')  # bare: rejected by this mode
    simulator.record_request('POST', '/wazuh-manager/control', {}, b'{}')  # accepted

    assert simulator.resolve_endpoint('/control') is None  # confirms it would be a 404

    matches = simulator.get_requests('/control')
    assert len(matches) == 2
    assert {request['path'] for request in matches} == {'/control', '/wazuh-manager/control'}


def test_get_requests_ignores_a_query_string_on_the_filter_argument():
    """get_requests('/control?type=notify') finds the same request as get_requests('/control').

    record_request() stores the raw target, which does carry a query string; the filter
    argument needs the same normalization or a caller passing one back (a plausible mistake,
    since both parameters are named `path`) gets a silent [] instead of the match.
    """
    simulator = RemotedSimulator()
    simulator.record_request('POST', '/control?type=notify', {}, b'{}')

    assert simulator.get_requests('/control?type=notify') == simulator.get_requests('/control')
    assert len(simulator.get_requests('/control')) == 1


def test_get_requests_rejects_a_path_without_leading_slash():
    """A caller typo ('control' instead of '/control') is a loud error, not a silent
    false-positive match against an unrelated recorded path like '/foocontrol'.
    """
    simulator = RemotedSimulator()
    simulator.record_request('POST', '/foocontrol', {}, b'{}')

    with pytest.raises(ValueError):
        simulator.get_requests('control')


# --------------------------------------------------------------------------------------
# End-to-end: drive the real TLS server to prove do_POST actually wires resolve_endpoint
# in, not just that the pure function is correct in isolation.
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
    ('gateway/wazuh-manager', '/gateway/wazuh-manager/control', 200),
    ('gateway/wazuh-manager', '/gateway/control', 404),
])
def test_routing_over_real_https(free_port, prefix, path, expected_status):
    """The actual TLS server 404s or dispatches exactly as resolve_endpoint's mode dictates."""
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
