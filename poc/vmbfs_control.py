#!/usr/bin/env python3
import hashlib
import json
import os
import struct

DEVICE = "/hostroot/dev/hvrawvmbfs"


def exchange(fd, frame):
    written = os.write(fd, frame)
    if written != len(frame):
        raise RuntimeError(f"short write: {written}/{len(frame)}")
    packet = os.read(fd, 16384)
    if len(packet) < 8:
        raise RuntimeError(f"short ring response: {len(packet)}")
    pipe_type, pipe_len = struct.unpack_from("<II", packet)
    body = packet[8:]
    if pipe_type != 1 or pipe_len != len(body):
        raise RuntimeError(
            f"bad pipe response: type={pipe_type} declared={pipe_len} actual={len(body)}"
        )
    return body


def header(message_type):
    return struct.pack("<II", message_type, 0)


def parse_header(frame, expected):
    if len(frame) < 8:
        raise RuntimeError(f"short response body: {len(frame)}")
    message_type, reserved = struct.unpack_from("<II", frame)
    if message_type != expected or reserved != 0:
        raise RuntimeError(
            f"unexpected response: type={message_type} reserved={reserved:#x}"
        )


def get_info(fd, path):
    response = exchange(fd, header(3) + path.encode("utf-16-le"))
    parse_header(response, 4)
    if len(response) != 24:
        raise RuntimeError(f"bad info response size: {len(response)}")
    status, flags, size = struct.unpack_from("<IIQ", response, 8)
    return {"path": path, "status": status, "flags": flags, "size": size}


def read_prefix(fd, path, size):
    count = min(size, 16)
    response = exchange(
        fd, header(5) + struct.pack("<IQ", count, 0) + path.encode("utf-16-le")
    )
    parse_header(response, 6)
    if len(response) < 12:
        raise RuntimeError(f"bad read response size: {len(response)}")
    status = struct.unpack_from("<I", response, 8)[0]
    data = response[12:]
    return {
        "path": path,
        "requested": count,
        "status": status,
        "returned": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "prefix_hex": data.hex(),
    }


def main():
    result = {"device": DEVICE, "version": None, "info": [], "read": None}
    with open(DEVICE, "r+b", buffering=0) as device:
        version = exchange(device.fileno(), header(1) + struct.pack("<I", 0x10000))
        parse_header(version, 2)
        if len(version) != 12:
            raise RuntimeError(f"bad version response size: {len(version)}")
        result["version"] = {"status": struct.unpack_from("<I", version, 8)[0]}

        # The exact vmchipset registration mounts its BIOS handler at root and
        # names imc.hiv. The other names are bounded boot-surface controls.
        for path in ("\\imc.hiv", "\\kernel", "\\initrd.img", "\\cmdline"):
            info = get_info(device.fileno(), path)
            result["info"].append(info)
            if result["read"] is None and info["status"] == 0 and info["size"]:
                result["read"] = read_prefix(device.fileno(), path, info["size"])

        result["negative"] = get_info(device.fileno(), "\\missing-3900000")
        result["traversal"] = get_info(device.fileno(), "\\..\\imc.hiv")

    with open("/tmp/vmbfs-control-result.json", "w") as output:
        json.dump(result, output, sort_keys=True)
        output.write("\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

