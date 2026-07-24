"""Throwaway driver: exercise the HTTPS RemotedSimulator while building it.

Not part of the package or git — a local dev aid.
Run with the project venv:
    /home/juan/qa-venv/bin/python drive_https_remoted.py
"""
import json
import os
import sys

import requests
import urllib3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from wazuh_testing.tools.simulators.https_remoted_simulator import ENDPOINTS, RemotedSimulator

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

        # 3) The other endpoints route (still 200 stubs). /control is covered above and
        #    rightly rejects an empty body, so it is excluded here.
        print('[3] routing:')
        for route in [e for e in ENDPOINTS if e != '/control']:
            resp = requests.post(f'{BASE}{route}', json={}, verify=False, timeout=5)
            print(f'    POST {route:<11} -> {resp.status_code}')
            assert resp.status_code == 200, f'{route} expected 200, got {resp.status_code}'

        # 4) /config and /stats store what the agent pushed and ack empty.
        print('[4] /config + /stats:')
        cfg = requests.post(f'{BASE}/config', headers=headers,
                            data=json.dumps({'client': {'notify_time': '10'}}), verify=False, timeout=5)
        sts = requests.post(f'{BASE}/stats', headers=headers,
                            data=json.dumps({'events_received': 42}), verify=False, timeout=5)
        print(f'    config -> {cfg.status_code} {json.dumps(cfg.json())}, stored={json.dumps(sim.last_config)}')
        print(f'    stats  -> {sts.status_code} {json.dumps(sts.json())}, stored={json.dumps(sim.last_stats)}')
        assert cfg.json() == {} and sim.last_config['client']['notify_time'] == '10'
        assert sts.json() == {} and sim.last_stats['events_received'] == 42

        # 5) Unknown endpoint -> 404 with the ErrorResponse envelope.
        resp = requests.post(f'{BASE}/nope', data=b'x', verify=False, timeout=5)
        print(f'[5] POST /nope -> {resp.status_code} {json.dumps(resp.json())}')
        assert resp.status_code == 404 and resp.json()['code'] == 404

        print('[+] TLS handshake, /control lifecycle, routing and errors all OK.')
        return 0
    finally:
        sim.destroy()
        print(f'[+] Simulator destroyed (running={sim.running})')


if __name__ == '__main__':
    raise SystemExit(main())
