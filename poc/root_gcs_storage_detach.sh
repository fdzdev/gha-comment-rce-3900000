#!/bin/bash
set +e
exec 0<&-

[ -r /tmp/gcs-storage-detach.py ] || exit 10
python3 -u /tmp/gcs-storage-detach.py
printf 'ROOT_STORAGE rc=%s\n' "$?"
printf 'ROOT_AUTO done\n'
