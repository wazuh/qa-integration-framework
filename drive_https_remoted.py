"""Throwaway driver: exercise the HTTPS RemotedSimulator while building it.

Not part of the package or git — a local dev aid.
Run with the project venv:
    /home/juan/qa-venv/bin/python drive_https_remoted.py
"""
import json
import os
import shutil
import sys
import tempfile
import time

import requests
import urllib3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from wazuh_testing.tools.simulators.remoted_simulator import ENDPOINTS, RemotedSimulator
from wazuh_testing.utils import request_auth

PORT = 27514
BASE = f'https://127.0.0.1:{PORT}'


def main() -> int:
    sim = RemotedSimulator(port=PORT)
    sim.start()
    print(f'[+] Simulator started on {BASE} (running={sim.running})')

    try:
        # 1) One request with every part spelled out, so the exact wire contents
        #    (including the auth headers a real agent sends) are obvious right here.
        method = 'POST'
        endpoint = '/control'
        headers = {
            'protocol-version': '1',
            'Authorization': 'Wazuh 001:1784238000:4b88d9235ea1a109d617f27f604918ea',
            'Content-Type': 'application/json',
        }
        body = json.dumps({'type': 'startup', 'version': '5.0.0'})

        resp = requests.request(method, f'{BASE}{endpoint}',
                                headers=headers, data=body, verify=False, timeout=5)
        print(f'[1] {method} {endpoint} (body={body})')
        print(f'    -> {resp.status_code} {json.dumps(resp.json())}')
        assert resp.status_code == 200
        assert 'limits' in resp.json() and 'settings_hash' not in resp.json()

        # Reuse the same spelled-out headers for the rest of the /control calls.
        def control(message: dict) -> requests.Response:
            return requests.post(f'{BASE}/control', headers=headers,
                                 data=json.dumps(message), verify=False, timeout=5)

        # 2) /control lifecycle: notify (no tasks) -> notify (with a task) -> shutdown.
        print('[2] /control lifecycle:')

        notify = control({'type': 'notify'}).json()
        print(f'    notify (no tasks) -> {json.dumps(notify)}')
        assert 'settings_hash' in notify and 'config_hash' in notify['agent'] and 'tasks' not in notify

        sim.add_task({'task_id': 'abc-123', 'task_type': 'agent_restart', 'payload': {}})
        notify = control({'type': 'notify'}).json()
        print(f'    notify (with task) -> {json.dumps(notify)}')
        assert notify['tasks'][0]['task_id'] == 'abc-123'

        notify = control({'type': 'notify'}).json()
        print(f'    notify (task drained) -> {json.dumps(notify)}')
        assert 'tasks' not in notify

        shutdown = control({'type': 'shutdown'})
        print(f'    shutdown -> {shutdown.status_code} {json.dumps(shutdown.json())}')
        assert shutdown.status_code == 200 and shutdown.json() == {}

        bad = control({'type': 'bogus'})
        print(f'    bogus type -> {bad.status_code} {json.dumps(bad.json())}')
        assert bad.status_code == 400 and bad.json()['code'] == 400

        # 3) /stateless: a valid H/E batch -> empty 200; a malformed one -> 400.
        print('[3] /stateless:')
        batch = b'H {"wazuh":{"agent":{"id":"001"}}}\nE 1:/var/log/syslog:hello\nE 2:/var/log/auth:world'
        ok = requests.post(f'{BASE}/stateless', headers=headers, data=batch, verify=False, timeout=5)
        print(f'    valid batch    -> {ok.status_code} {ok.text!r}')
        assert ok.status_code == 200 and ok.text == ''
        bad = requests.post(f'{BASE}/stateless', headers=headers, data=b'not a batch', verify=False, timeout=5)
        print(f'    malformed      -> {bad.status_code} {json.dumps(bad.json())}')
        assert bad.status_code == 400 and bad.json()['code'] == 400

        # 3b) /stateful: dedup by X-Session-Id; a retry with the same id is idempotent.
        print('[3b] /stateful:')
        sim.stateful_items_processed = 7
        s1 = requests.post(f'{BASE}/stateful', headers={**headers, 'X-Session-Id': 'sess-1'},
                           data=b'<flatbuffer-session-blob>', verify=False, timeout=5)
        print(f'    session sess-1  -> {s1.status_code} {json.dumps(s1.json())}')
        assert s1.json() == {'status': 'ok', 'sessionId': 'sess-1', 'itemsProcessed': 7}

        sim.stateful_items_processed = 999  # changed; the retry must still return the cached 7
        retry = requests.post(f'{BASE}/stateful', headers={**headers, 'X-Session-Id': 'sess-1'},
                              data=b'<flatbuffer-session-blob>', verify=False, timeout=5)
        print(f'    sess-1 retry    -> {retry.status_code} {json.dumps(retry.json())} (idempotent)')
        assert retry.json()['itemsProcessed'] == 7

        missing = requests.post(f'{BASE}/stateful', headers=headers, data=b'x', verify=False, timeout=5)
        print(f'    no X-Session-Id -> {missing.status_code} {json.dumps(missing.json())}')
        assert missing.status_code == 400 and 'sess-1' in sim.stateful_sessions

        # 4) The remaining endpoints route. The validating endpoints (/control, /stateless,
        #    /stateful, /download) are covered above and reject an empty/invalid body.
        print('[4] routing:')
        for route in [e for e in ENDPOINTS
                      if e not in ('/control', '/stateless', '/stateful', '/download')]:
            resp = requests.post(f'{BASE}{route}', json={}, verify=False, timeout=5)
            print(f'    POST {route:<11} -> {resp.status_code}')
            assert resp.status_code == 200, f'{route} expected 200, got {resp.status_code}'

        # 4b) /download streams the requested resource with chunked encoding.
        print('[4b] /download:')
        cfg = requests.post(f'{BASE}/download', headers=headers,
                            data=json.dumps({'resource_type': 'config', 'resource_id': 'default'}),
                            verify=False, timeout=5)
        print(f'    config -> {cfg.status_code}, chunked={cfg.headers.get("Transfer-Encoding")}, '
              f'bytes={len(cfg.content)}, matches_merged_mg={cfg.content == sim.merged_mg}')
        assert cfg.status_code == 200 and cfg.content == sim.merged_mg

        miss = requests.post(f'{BASE}/download', headers=headers,
                             data=json.dumps({'resource_type': 'wpk', 'resource_id': 'x.wpk'}),
                             verify=False, timeout=5)
        print(f'    wpk (unset) -> {miss.status_code} {json.dumps(miss.json())}')
        assert miss.status_code == 404

        sim.wpk = b'FAKE-WPK-BYTES' * 10000  # ~130 KB, spans multiple 64 KB chunks
        wpk = requests.post(f'{BASE}/download', headers=headers,
                            data=json.dumps({'resource_type': 'wpk', 'resource_id': 'x.wpk'}),
                            verify=False, timeout=5)
        print(f'    wpk (set)   -> {wpk.status_code}, bytes={len(wpk.content)}, matches={wpk.content == sim.wpk}')
        assert wpk.status_code == 200 and wpk.content == sim.wpk

        # 5) /config and /stats store what the agent pushed and ack empty.
        print('[5] /config + /stats:')
        cfg = requests.post(f'{BASE}/config', headers=headers,
                            data=json.dumps({'client': {'notify_time': '10'}}), verify=False, timeout=5)
        sts = requests.post(f'{BASE}/stats', headers=headers,
                            data=json.dumps({'events_received': 42}), verify=False, timeout=5)
        print(f'    config -> {cfg.status_code} {json.dumps(cfg.json())}, stored={json.dumps(sim.last_config)}')
        print(f'    stats  -> {sts.status_code} {json.dumps(sts.json())}, stored={json.dumps(sim.last_stats)}')
        assert cfg.json() == {} and sim.last_config['client']['notify_time'] == '10'
        assert sts.json() == {} and sim.last_stats['events_received'] == 42

        # 6) Unknown endpoint -> 404 with the ErrorResponse envelope.
        resp = requests.post(f'{BASE}/nope', data=b'x', verify=False, timeout=5)
        print(f'[6] POST /nope -> {resp.status_code} {json.dumps(resp.json())}')
        assert resp.status_code == 404 and resp.json()['code'] == 404

        # 7) Fault modes short-circuit every request (mode is read live per request).
        print('[7] fault modes:')
        expected = {'REJECT_AUTH': 401, 'BAD_REQUEST': 400,
                    'SERVICE_UNAVAILABLE': 503, 'PAYLOAD_TOO_LARGE': 413}
        for mode, code in expected.items():
            sim.mode = mode
            resp = control({'type': 'notify'})
            retry_after = resp.headers.get('Retry-After')
            print(f'    {mode:<20} -> {resp.status_code} {json.dumps(resp.json())}'
                  f'{" Retry-After=" + retry_after if retry_after else ""}')
            assert resp.status_code == code and resp.json()['code'] == code
            if mode == 'SERVICE_UNAVAILABLE':
                assert retry_after == '5'
        sim.mode = 'ACCEPT'

        # 8) Introspection helpers over the captured requests (non-destructive).
        print('[8] introspection helpers:')
        control_requests = sim.get_requests('/control')
        last_stateless = sim.last_request('/stateless')
        print(f'    /control requests captured : {len(control_requests)}')
        print(f'    last /stateless            : agent_id={last_stateless["agent_id"]} '
              f'body={last_stateless["body"]!r}')
        print(f'    total requests captured    : {len(sim.requests)}')
        assert len(control_requests) >= 1 and last_stateless is not None
        assert sim.last_request('/never-requested') is None
        print('[+] TLS handshake, /control lifecycle, routing and errors all OK.')
    finally:
        sim.destroy()
        print(f'[+] Simulator destroyed (running={sim.running})')

    auth_demo()
    return 0


def auth_demo() -> None:
    """Exercise verify_auth on a second simulator with a provisioned 32-hex key."""
    print('[9] verify_auth (signed requests):')
    keydir = tempfile.mkdtemp()
    keys_path = os.path.join(keydir, 'client.keys')
    agent_key_hex = '000102030405060708090a0b0c0d0e0f'
    with open(keys_path, 'w') as handle:
        handle.write(f'001 agent-001 any {agent_key_hex}\n')
    key = request_auth.derive_cmac_key(agent_key_hex)

    port = PORT + 1
    base = f'https://127.0.0.1:{port}'
    sim = RemotedSimulator(port=port, keys_path=keys_path, verify_auth=True)
    sim.start()
    try:
        body = json.dumps({'type': 'notify'}).encode()
        now = int(time.time())

        def signed(target, ts, sign_body, send_body):
            auth = request_auth.sign_authorization('POST', target, '001', ts, sign_body, key)
            return {'protocol-version': '1', 'Authorization': auth}, send_body

        headers, data = signed('/control', now, body, body)
        r = requests.post(f'{base}/control', headers=headers, data=data, verify=False, timeout=5)
        print(f'    valid signature         -> {r.status_code}')
        assert r.status_code == 200

        bad = dict(headers)
        bad['Authorization'] = headers['Authorization'][:-1] + ('0' if headers['Authorization'][-1] != '0' else '1')
        r = requests.post(f'{base}/control', headers=bad, data=data, verify=False, timeout=5)
        print(f'    tampered mac            -> {r.status_code} {json.dumps(r.json())}')
        assert r.status_code == 401

        r = requests.post(f'{base}/control', headers=headers, data=b'{"type":"shutdown"}', verify=False, timeout=5)
        print(f'    tampered body           -> {r.status_code}')
        assert r.status_code == 401

        headers, data = signed('/control', now - 1000, body, body)  # outside the 300s window
        r = requests.post(f'{base}/control', headers=headers, data=data, verify=False, timeout=5)
        print(f'    expired timestamp       -> {r.status_code}')
        assert r.status_code == 401

        # Identity binding: valid signature for 001, but the H metadata claims 002 -> 400.
        sbody = b'H {"wazuh":{"agent":{"id":"002"}}}\nE 1:loc:msg'
        headers, data = signed('/stateless', now, sbody, sbody)
        r = requests.post(f'{base}/stateless', headers=headers, data=data, verify=False, timeout=5)
        print(f'    id mismatch (stateless) -> {r.status_code} {json.dumps(r.json())}')
        assert r.status_code == 400
        print('[+] verify_auth: valid accepted, tamper/expiry/mismatch rejected.')
    finally:
        sim.destroy()
        shutil.rmtree(keydir, ignore_errors=True)


if __name__ == '__main__':
    raise SystemExit(main())
