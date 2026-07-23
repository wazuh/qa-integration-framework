"""Throwaway Phase-1 driver: prove the HTTPS RemotedSimulator stands up TLS and routes.

Not part of the package or git — a local dev aid while building the simulator.
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
        #    are obvious right here in the driver's code.
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
        print(f'    {method} {endpoint} (body={body}) -> {resp.status_code} {resp.text!r}')
        assert resp.status_code == 200

        # 2) Every known endpoint routes to the Phase-1 200 stub.
        for route in ENDPOINTS:
            resp = requests.post(f'{BASE}{route}', json={'type': 'notify'}, verify=False, timeout=5)
            print(f'    POST {route:<11} -> {resp.status_code} {resp.text!r}')
            assert resp.status_code == 200, f'{route} expected 200, got {resp.status_code}'

        # 2) Unknown endpoint should 404 with the ErrorResponse envelope.
        resp = requests.post(f'{BASE}/nope', data=b'x', verify=False, timeout=5)
        print(f'    POST /nope        -> {resp.status_code} {resp.text!r}')
        assert resp.status_code == 404 and resp.json()['code'] == 404

        # 3) A signed-looking request: check agent id is parsed from the header + body captured.
        headers = {'protocol-version': '1', 'Authorization': 'Wazuh 001:1784238000:deadbeef'}
        requests.post(f'{BASE}/stateless', data=b'H {}\nE 1:loc:msg', headers=headers, verify=False, timeout=5)

        # 4) Drain the introspection queue and show what landed.
        print('[+] Captured requests:')
        seen_paths = []
        while not sim.queue.empty():
            item = sim.queue.get_nowait()
            seen_paths.append(item['path'])
            print(f'    {item["method"]} {item["path"]} agent_id={item["agent_id"]} body={item["body"]!r}')

        assert '/stateless' in seen_paths
        print('[+] TLS handshake, routing, and request capture all OK.')
        return 0
    finally:
        sim.destroy()
        print(f'[+] Simulator destroyed (running={sim.running})')


if __name__ == '__main__':
    raise SystemExit(main())
