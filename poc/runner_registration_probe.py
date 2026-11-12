#!/usr/bin/env python3
"""Test the hosted runner's readable registration credential without printing it."""

import glob
import hashlib
import json
import os
import base64
import urllib.error
import urllib.parse
import urllib.request


root = glob.glob("/home/runner/actions-runner/cached/*/.runner")[0].rsplit("/", 1)[0]
settings = json.load(open(root + "/.runner"))
credentials = json.load(open(root + "/.credentials"))
data = credentials.get("data", credentials.get("Data", {}))
token = data.get("token") or data.get("Token")
print(
    "RUNNER_REGISTRATION "
    f"scheme={credentials.get('scheme', credentials.get('Scheme'))} "
    f"ephemeral={str(settings.get('ephemeral', settings.get('Ephemeral'))).lower()} "
    f"disable_update={str(settings.get('disableUpdate', settings.get('DisableUpdate'))).lower()} "
    f"use_v2={str(settings.get('useV2Flow', settings.get('UseV2Flow'))).lower()} "
    f"credential_fields={','.join(sorted(data))}",
    flush=True,
)

try:
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    print(
        "RUNNER_REGISTRATION_JWT "
        f"claims={','.join(sorted(claims))} iss={claims.get('iss', '-')} "
        f"aud_type={type(claims.get('aud')).__name__} exp={claims.get('exp', '-')}",
        flush=True,
    )
except Exception:
    pass
if not token:
    raise SystemExit("RUNNER_REGISTRATION direct_access_token=false")
print(
    f"RUNNER_REGISTRATION direct_access_token=true length={len(token)} "
    f"sha256={hashlib.sha256(token.encode()).hexdigest()}",
    flush=True,
)

pool = settings.get("poolId", settings.get("PoolId"))
agent = settings.get("agentId", settings.get("AgentId"))
for field in ("serverUrlV2", "ServerUrlV2", "serverUrl", "ServerUrl"):
    if not settings.get(field):
        continue
    base = settings[field].rstrip("/")
    target = (
        f"{base}/_apis/distributedtask/pools/{pool}/agents/{agent}"
        "?includeCapabilities=true&includeAssignedRequest=true&api-version=7.1-preview.1"
    )
    for valid in (False, True):
        request = urllib.request.Request(
            target,
            headers={
                "Authorization": "Bearer " + (token if valid else "invalid"),
                "Accept": "application/json",
                "User-Agent": "owned-runner-registration-check-3900000",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                status, body = response.status, response.read(1 << 20)
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read(1 << 20)
        except OSError as error:
            print(
                f"RUNNER_REGISTRATION_API field={field} valid={str(valid).lower()} "
                f"network={type(error).__name__}",
                flush=True,
            )
            continue
        try:
            parsed = json.loads(body)
            response_fields = ",".join(sorted(parsed)) if isinstance(parsed, dict) else "-"
        except Exception:
            response_fields = "-"
        print(
            f"RUNNER_REGISTRATION_API field={field} host={urllib.parse.urlsplit(base).hostname} "
            f"valid={str(valid).lower()} status={status} bytes={len(body)} "
            f"response_fields={response_fields}",
            flush=True,
        )

broker = settings.get("ServerUrlV2", settings.get("serverUrlV2", "")).rstrip("/")
session = json.dumps({
    "ownerName": "owned-session-conflict-control-3900000",
    "agent": {
        "id": agent,
        "name": settings.get("AgentName", settings.get("agentName")),
        "version": "2.338.2",
        "osDescription": "Linux",
    },
    "brokerSession": True,
}).encode()
for valid in (False, True):
    for method, suffix, body in (
        ("POST", "/session", session),
        (
            "GET",
            "/message?status=Online&runnerVersion=2.338.2&os=Linux&architecture=X64&disableUpdate=true",
            None,
        ),
    ):
        probe = urllib.request.Request(
            broker + suffix,
            data=body,
            method=method,
            headers={
                "Authorization": "Bearer " + (token if valid else "invalid"),
                "Content-Type": "application/json",
                "User-Agent": "owned-broker-check-3900000",
            },
        )
        try:
            with urllib.request.urlopen(probe, timeout=5) as response:
                status, response_body = response.status, response.read(1 << 20)
        except urllib.error.HTTPError as error:
            status, response_body = error.code, error.read(1 << 20)
        except OSError as error:
            print(
                f"RUNNER_BROKER method={method} valid={str(valid).lower()} "
                f"network={type(error).__name__}",
                flush=True,
            )
            continue
        print(
            f"RUNNER_BROKER method={method} valid={str(valid).lower()} "
            f"status={status} bytes={len(response_body)}",
            flush=True,
        )
