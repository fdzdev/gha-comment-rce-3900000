#!/bin/bash
set +e
exec 0<&-

curl -fsS http://16.146.243.72:8450/gcs_storage_detach_control.py \
    -o /tmp/gcs-storage-detach.py || exit 10
python3 -u /tmp/gcs-storage-detach.py
printf 'ROOT_STORAGE rc=%s\n' "$?"
printf 'ROOT_AUTO done\n'
