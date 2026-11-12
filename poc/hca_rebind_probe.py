#!/usr/bin/env python3
"""Retire this owned request, then test whether its HCA identity can acquire another."""

import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request


def environment_and_pid():
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            values = open(entry.path + "/environ", "rb").read().split(b"\0")
            environment = dict(item.split(b"=", 1) for item in values if b"=" in item)
        except OSError:
            continue
        if b"scheduler_api_url" in environment and b"jwt_token" in environment:
            return environment, int(entry.name)
    raise RuntimeError("HCA environment not found")


def call(base, token, method, suffix):
    request = urllib.request.Request(
        base.rstrip("/") + suffix,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "owned-rebind-check-3900000",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, response.read(1 << 20)
    except urllib.error.HTTPError as error:
        return error.code, error.read(1 << 20)
    except OSError as error:
        return type(error).__name__, b""


environment, hca_pid = environment_and_pid()
base = environment[b"scheduler_api_url"].decode()
token = environment[b"jwt_token"].decode()
os.kill(hca_pid, signal.SIGSTOP)
print(f"HCA_REBIND stopped_hca=true pid={hca_pid}", flush=True)
status, data = call(base, token, "DELETE", "/request?outcome=0&runner_exit_code=0")
print(f"HCA_REBIND finish_status={status} bytes={len(data)}", flush=True)

seen = {}
deadline = time.monotonic() + (int(sys.argv[1]) if len(sys.argv) > 1 else 90)
while time.monotonic() < deadline:
    status, data = call(base, token, "GET", "/request")
    seen[status] = seen.get(status, 0) + 1
    if status == 200:
        try:
            parsed = json.loads(data)
            fields = ",".join(sorted(parsed)) if isinstance(parsed, dict) else type(parsed).__name__
        except Exception:
            fields = "-"
        print(
            "HCA_REBIND acquired=true "
            f"bytes={len(data)} json_fields={fields} "
            f"private_b_marker={str(b'OWNED-CROSS-REPOSITORY-MARKER-3900000-B' in data).lower()}",
            flush=True,
        )
        break
    time.sleep(0.25)
else:
    print("HCA_REBIND acquired=false", flush=True)
print("HCA_REBIND statuses=" + json.dumps(seen, sort_keys=True), flush=True)
