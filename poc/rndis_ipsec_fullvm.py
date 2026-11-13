#!/usr/bin/env python3
"""Exercise handler-valid IPsec direct OIDs through Linux netvsc."""

import ctypes
import glob
import os
import socket
import struct
import subprocess
import sys


NETVSP_CLASS = "f8615163-df3e-46c5-913f-f2d2f965ed0e"


class KCore:
    def __init__(self):
        self.fd = os.open("/proc/kcore", os.O_RDONLY)
        header = os.pread(self.fd, 64, 0)
        fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
        phoff, phentsize, phnum = fields[5], fields[9], fields[10]
        self.loads = []
        for index in range(phnum):
            raw = os.pread(self.fd, phentsize, phoff + index * phentsize)
            ptype, _, offset, vaddr, _, filesz, _, _ = struct.unpack(
                "<IIQQQQQQ", raw[:56]
            )
            if ptype == 1 and filesz:
                self.loads.append((vaddr, vaddr + filesz, offset))

    def read(self, address, length):
        for start, end, offset in self.loads:
            if start <= address and address + length <= end:
                return os.pread(self.fd, length, offset + address - start)
        raise ValueError("address is not represented in kcore")


def symbol(name, prefix=False):
    exact = []
    prefixed = []
    with open("/proc/kallsyms") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) < 3 or fields[1].lower() != "t":
                continue
            if fields[2] == name:
                exact.append((fields[2], int(fields[0], 16)))
            elif prefix and fields[2].startswith(name):
                prefixed.append((fields[2], int(fields[0], 16)))
    hits = exact or prefixed
    if len(hits) != 1:
        raise RuntimeError("symbol %s hits=%r" % (name, hits))
    return hits[0][1]


def channel_for_relid(kcore, relid):
    address = symbol("relid2channel")
    code = kcore.read(address, 160)
    candidates = []
    for index in range(len(code) - 7):
        if not (code[index] in (0x48, 0x4C) and code[index + 1] == 0x8B
                and code[index + 2] & 0xC7 == 0x05):
            continue
        displacement = struct.unpack("<i", code[index + 3:index + 7])[0]
        global_address = address + index + 7 + displacement
        try:
            array_address = struct.unpack("<Q", kcore.read(global_address, 8))[0]
            channel_address = struct.unpack(
                "<Q", kcore.read(array_address + relid * 8, 8)
            )[0]
        except (ValueError, OSError):
            continue
        if (array_address >> 48) == 0xFFFF and (channel_address >> 48) == 0xFFFF:
            candidates.append(channel_address)
    if len(set(candidates)) != 1:
        raise RuntimeError("channel pointer candidates=%r" % candidates)
    return candidates[0]


def resolve_rndis():
    devices = []
    for path in glob.glob("/sys/bus/vmbus/devices/*"):
        with open(path + "/class_id") as stream:
            if stream.read().strip("\n{}").lower() == NETVSP_CLASS:
                devices.append(path)
    if len(devices) != 1:
        raise RuntimeError("netvsc devices=%r" % devices)
    guid = devices[0].rsplit("/", 1)[1]
    with open(devices[0] + "/channel_vp_mapping") as stream:
        relid = int(stream.read().split(":", 1)[0])
    kcore = KCore()
    channel = channel_for_relid(kcore, relid)
    callback = symbol("netvsc_channel_cb")
    channel_data = kcore.read(channel, 4096)
    hits = [offset for offset in range(0, len(channel_data) - 16, 8)
            if struct.unpack_from("<Q", channel_data, offset)[0] == callback]
    if len(hits) != 1:
        raise RuntimeError("callback offsets=%r" % hits)
    context = struct.unpack_from("<Q", channel_data, hits[0] + 8)[0]
    context_channel, nvdev = struct.unpack("<QQ", kcore.read(context, 16))
    if context_channel != channel:
        raise RuntimeError("channel context mismatch")
    candidates = []
    nvdev_data = kcore.read(nvdev, 0x400)
    for offset in range(0, len(nvdev_data) - 8, 8):
        rndis = struct.unpack_from("<Q", nvdev_data, offset)[0]
        if rndis >> 48 != 0xffff:
            continue
        try:
            ndev, state, request_id = struct.unpack("<QII", kcore.read(rndis, 16))
            prev, nxt = struct.unpack("<QQ", kcore.read(rndis + 24, 16))
        except (OSError, ValueError):
            continue
        if (ndev >> 48 == 0xffff and state == 3 and request_id < 0x100000
                and prev == rndis + 24 and nxt == rndis + 24):
            candidates.append((offset, rndis, request_id))
    if len(candidates) != 1:
        raise RuntimeError("RNDIS candidates=%r" % candidates)
    offset, rndis, request_id = candidates[0]
    print("IPSEC_RNDIS_OFFSET offset=%#x" % offset, flush=True)
    return guid, relid, rndis, request_id


def case(label, request_type, oid, data):
    params = "/sys/module/rndis_oid_set/parameters/"
    for key, value in (("request_type", request_type), ("oid", hex(oid)),
                       ("data_hex", data.hex()), ("input_length", len(data))):
        with open(params + key, "w") as stream:
            stream.write(str(value))
    with open(params + "arm", "w") as stream:
        stream.write("1")
    lines = subprocess.check_output(["dmesg", "--notime"], text=True).splitlines()
    needle = "rndis_oid_set iteration=0 oid=%#x " % oid
    completion = next((line for line in reversed(lines) if needle in line), "missing")
    query = next((line for line in reversed(lines)
                  if "rndis_oid_query oid=%#x " % oid in line), "")
    print("IPSEC_CASE label=%s type=%u oid=%#x bytes=%u completion=%s query=%s" %
          (label, request_type, oid, len(data), completion, query), flush=True)


def add_sa(operation, auth_id, auth_len, enc_id, enc_len, flags=0):
    key_len = auth_len + enc_len
    blob = bytearray(0xb0 + key_len)
    struct.pack_into("<BBHII", blob, 0, 0x80, 1, 0xaa, 1, flags)
    blob[0x0c:0x10] = socket.inet_aton("10.0.0.1")
    blob[0x10:0x14] = socket.inet_aton("10.0.0.2")
    struct.pack_into("<II", blob, 0x3c, 0, operation)
    struct.pack_into("<I", blob, 0x44, 0x11223344)
    struct.pack_into("<IIII", blob, 0x48, auth_id, auth_len, 0, 0)
    struct.pack_into("<IIII", blob, 0x58, enc_id, enc_len, auth_len, 0)
    struct.pack_into("<II", blob, 0x9c, key_len, 0xb0)
    blob[0xb0:] = bytes((index * 29 + 7) & 0xff for index in range(key_len))
    return blob


def main():
    module = sys.argv[1]
    guid, relid, rndis, request_id = resolve_rndis()
    params = ("get_address=0x%x send_address=0x%x put_address=0x%x "
              "rndis_device=0x%x request_type=4 oid=0xfc01020d "
              "input_length=0 arm=1" %
              (symbol("get_rndis_request", True),
               symbol("rndis_filter_send_request", True),
               symbol("put_rndis_request", True), rndis)).encode()
    print("IPSEC_PRE guid=%s relid=%u rndis=%x request_id=%u" %
          (guid, relid, rndis, request_id), flush=True)
    fd = os.open(module, os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(313, fd, params, 3)
    print("IPSEC_FINIT result=%d errno=%d" % (result, ctypes.get_errno()), flush=True)
    if result == -1:
        raise SystemExit(1)

    case("hardware-before", 4, 0xfc01020d, b"")
    case("current-before", 4, 0xfc01020b, b"")
    config = bytearray(22)
    struct.pack_into("<BBH", config, 0, 0x80, 2, 22)
    config[20] = config[21] = 4
    case("enable-ah-esp", 5, 0xfc01020c, config)
    case("current-after", 4, 0xfc01020b, b"")
    delete = struct.pack("<BBHIQQ", 0x80, 1, 24, 0, 0, 0x1122334455667788)
    case("delete-absent", 5, 0xfc030203, delete)
    case("add-ah-sha1", 5, 0xfc030205, add_sa(0, 2, 20, 0, 0))
    case("add-esp-auth-sha1", 5, 0xfc030205, add_sa(1, 2, 20, 1, 0))
    case("add-esp-aes-cbc128", 5, 0xfc030205, add_sa(1, 0, 0, 0x40, 16))
    case("add-esp-gcm128", 5, 0xfc030205, add_sa(1, 0, 0, 8, 20))


if __name__ == "__main__":
    main()
