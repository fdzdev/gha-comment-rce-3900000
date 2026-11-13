#!/bin/bash
set +e

rm -f /tmp/broker-prehold.log
env BROKER_STAGE_ONLY=1 PROC_ROOT=/hostproc \
    BROKER_CANDIDATES_FILE=/tmp/broker-session-candidates.json \
    python3 -u /tmp/broker_prehold_receiver.py \
    >/tmp/broker-prehold.log 2>&1
receiver_rc=$?
printf 'ROOT_AUTO broker_stage_rc=%s state=%s\n' "$receiver_rc" \
    "$([ -s /tmp/broker-session-candidates.json ] && printf ready || printf failed)"
sed -n '1,8p' /tmp/broker-prehold.log 2>/dev/null
printf 'ROOT_AUTO done\n'
