#!/usr/bin/env python3
"""Load the generic SET module against the live netvsc RNDIS object."""
import ctypes
import os
import sys

from kcore_relid_load import symbol_address
from rndis_legit_run import resolve_objects


def main():
    guid, relid, _nvdev, rndis, request_id = resolve_objects()
    get = symbol_address("get_rndis_request")
    send = symbol_address("rndis_filter_send_request")
    put = symbol_address("put_rndis_request")
    oid = int(sys.argv[2], 0)
    data_hex = sys.argv[3]
    parameters = ("get_address=0x%x send_address=0x%x put_address=0x%x "
                  "rndis_device=0x%x oid=0x%x input_length=%u data_hex=%s arm=1" %
                  (get, send, put, rndis, oid, len(data_hex) // 2, data_hex)).encode()
    print("RNDIS_SET_PRE guid=%s relid=%u get=%x send=%x put=%x rndis=%x "
          "reqid=%u oid=%#x input_length=%u" %
          (guid, relid, get, send, put, rndis, request_id, oid,
           len(data_hex) // 2), flush=True)
    module_fd = os.open(sys.argv[1], os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(313, module_fd, parameters, 3)
    error = ctypes.get_errno()
    print("RNDIS_SET_FINIT result=%d errno=%d" % (result, error), flush=True)
    sys.exit(1 if result == -1 else 0)


if __name__ == "__main__":
    main()
