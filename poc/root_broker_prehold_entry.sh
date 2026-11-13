#!/bin/bash
set +e

rm -f /tmp/broker-prehold.log
setsid env TARGET_AGENT_ID=next \
    BROKER_CONFIG_PATH=/tmp/broker-prehold-config.json \
    BROKER_RESULT_RELAY=http://16.146.243.72:8450/BROKER_PREHOLD \
    python3 -u /tmp/broker_prehold_receiver.py \
    <&- >/tmp/broker-prehold.log 2>&1 &
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
