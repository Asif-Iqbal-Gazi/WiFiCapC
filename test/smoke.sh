#!/usr/bin/env bash
# Round-trip the M1 commands against a freshly-launched daemon.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
BIN=${BIN:-$REPO_DIR/wificapc}
SOCK=$(mktemp -u /tmp/wificapc.smoke.XXXXXX.sock)

if [[ ! -x $BIN ]]; then
	echo "binary not found at $BIN — run 'make' in $REPO_DIR first" >&2
	exit 2
fi

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

# M2 — no-root: command surface validation (these all return errors without
# an iface, but the dispatcher must recognise them and not say "unknown").
resp=$(run '{"id":10,"cmd":"iface_info"}')
assert_match "$resp" 'no iface set'      "iface_info pre-set → error"

resp=$(run '{"id":11,"cmd":"monitor_on"}')
assert_match "$resp" 'no iface set'      "monitor_on pre-set → error"

resp=$(run '{"id":12,"cmd":"set_channel","args":{"channel":6}}')
assert_match "$resp" 'no iface set'      "set_channel pre-set → error"

resp=$(run '{"id":13,"cmd":"hop_start","args":{"channels":[1,6,11],"interval_ms":250}}')
assert_match "$resp" 'no iface set'      "hop_start pre-set → error"

resp=$(run '{"id":14,"cmd":"hop_stop"}')
assert_match "$resp" '"ok":true'         "hop_stop on no hopper → ok"

resp=$(run '{"id":15,"cmd":"iface_set","args":{}}')
assert_match "$resp" "missing or oversize" "iface_set without name → error"

# nonexistent iface (short enough name that we get past the length check)
resp=$(run '{"id":16,"cmd":"iface_set","args":{"name":"nothere0"}}')
assert_match "$resp" 'iface_open failed' "iface_set on bogus iface → error"

# obviously-oversize name
resp=$(run '{"id":17,"cmd":"iface_set","args":{"name":"this_name_is_way_too_long_for_an_iface"}}')
assert_match "$resp" 'too long'          "iface_set with oversize name → error"

# M3 — recon command surface (no root required; iface guard kicks in first)
resp=$(run '{"id":20,"cmd":"recon_start"}')
assert_match "$resp" 'no iface set'      "recon_start pre-set → error"

resp=$(run '{"id":21,"cmd":"recon_stop"}')
assert_match "$resp" '"ok":true'         "recon_stop on inactive → ok"

resp=$(run '{"id":22,"cmd":"list_aps"}')
assert_match "$resp" 'no table'          "list_aps before recon → error"

resp=$(run '{"id":23,"cmd":"list_stas"}')
assert_match "$resp" 'no table'          "list_stas before recon → error"

resp=$(run '{"id":24,"cmd":"clear"}')
assert_match "$resp" '"ok":true'         "clear on empty → ok"

resp=$(run '{"id":25,"cmd":"stats"}')
assert_match "$resp" '"n_aps":0'         "stats reports n_aps"
assert_match "$resp" '"n_stas":0'        "stats reports n_stas"
assert_match "$resp" '"capturing":false' "stats reports capturing=false"

echo "all good"
