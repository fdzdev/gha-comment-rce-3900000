#!/bin/bash
set +e

rm -f /tmp/broker-prehold.log
setsid python3 -u - <<'PY' <&- >/tmp/broker-prehold.log 2>&1 &
import json
import os

config = json.load(open("/tmp/broker-prehold-config.json"))
for key in ("RECEIVER_BILLING_OWNER_ID", "RECEIVER_REPOSITORY",
            "RECEIVER_RUN_ID", "RECEIVER_NONCE", "BROKER_HOLD_SECONDS"):
    os.environ[key] = str(config[key])
os.environ["TARGET_AGENT_ID"] = "next"
os.environ["BROKER_RESULT_RELAY"] = "http://16.146.243.72:8450/BROKER_PREHOLD"
os.execv("/usr/bin/python3", ["python3", "/tmp/broker_prehold_receiver.py"])
PY
receiver_pid=$!

for attempt in $(seq 1 400); do
    grep -q '^BROKER_RECEIVER state=ready$' /tmp/broker-prehold.log 2>/dev/null && break
    kill -0 "$receiver_pid" 2>/dev/null || break
    sleep 0.05
done
printf 'ROOT_AUTO broker_prehold_pid=%s state=%s\n' "$receiver_pid" \
    "$([ "$attempt" -lt 400 ] && printf started || printf pending)"
sed -n '1,8p' /tmp/broker-prehold.log 2>/dev/null
printf 'ROOT_AUTO done\n'
