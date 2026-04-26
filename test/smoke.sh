#!/usr/bin/env bash
# Round-trip the M1 commands against a freshly-launched daemon.
set -euo pipefail

BIN=${BIN:-./wificapc}
SOCK=$(mktemp -u /tmp/wificapc.smoke.XXXXXX.sock)

cleanup() {
	[[ -n ${PID:-} ]] && kill -TERM "$PID" 2>/dev/null || true
	wait "${PID:-0}" 2>/dev/null || true
	rm -f "$SOCK"
}
trap cleanup EXIT

"$BIN" --socket "$SOCK" --foreground &
PID=$!

# wait for the socket to appear
for _ in {1..50}; do
	[[ -S $SOCK ]] && break
	sleep 0.05
done
[[ -S $SOCK ]] || { echo "socket never appeared at $SOCK"; exit 1; }

run() {
	# send one line, read one line back
	printf '%s\n' "$1" | timeout 2 nc -N -U "$SOCK"
}

assert_match() {
	local got=$1 want=$2 label=$3
	if [[ $got != *"$want"* ]]; then
		printf 'FAIL %s\n  got : %s\n  want: %s\n' "$label" "$got" "$want" >&2
		exit 1
	fi
	printf 'ok   %s\n' "$label"
}

resp=$(run '{"id":1,"cmd":"ping"}')
assert_match "$resp" '"ok":true'      "ping returns ok"
assert_match "$resp" '"pong":"yes"'   "ping data has pong"
assert_match "$resp" '"id":1'         "ping echoes id"

resp=$(run '{"id":2,"cmd":"version"}')
assert_match "$resp" '"name":"wificapc"' "version returns name"

resp=$(run '{"id":3,"cmd":"uptime"}')
assert_match "$resp" '"uptime":'         "uptime returns int"

resp=$(run '{"id":4,"cmd":"nope"}')
assert_match "$resp" '"ok":false'        "unknown cmd → not ok"
assert_match "$resp" 'unknown command'   "unknown cmd → error msg"

resp=$(run 'not even json')
assert_match "$resp" '"ok":false'        "garbage line → not ok"

echo "all good"
