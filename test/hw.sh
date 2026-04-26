#!/usr/bin/env bash
# Hardware test against a real wifi card. Requires root (CAP_NET_ADMIN).
#
# Usage:  sudo IFACE=wlx00c0cab79cb7 bash test/hw.sh
#
# Verifies: iface_set → monitor_on → hop_start → events arrive → monitor_off.
set -euo pipefail

IFACE=${IFACE:-wlx00c0cab79cb7}
BIN=${BIN:-./wificapc}
SOCK=$(mktemp -u /tmp/wificapc.hw.XXXXXX.sock)

if [[ $EUID -ne 0 ]]; then
	echo "must run as root (sudo $0)" >&2
	exit 2
fi
if ! ip link show "$IFACE" >/dev/null 2>&1; then
	echo "iface $IFACE not present" >&2
	exit 2
fi

cleanup() {
	[[ -n ${PID:-} ]] && kill -TERM "$PID" 2>/dev/null || true
	[[ -n ${LISTEN:-} ]] && kill -TERM "$LISTEN" 2>/dev/null || true
	wait 2>/dev/null || true
	# best-effort restore
	ip link set "$IFACE" down 2>/dev/null || true
	iw dev "$IFACE" set type managed 2>/dev/null || true
	ip link set "$IFACE" up 2>/dev/null || true
	rm -f "$SOCK" /tmp/wificapc.hw.events
}
trap cleanup EXIT

"$BIN" --socket "$SOCK" --foreground --debug &
PID=$!

for _ in {1..50}; do
	[[ -S $SOCK ]] && break
	sleep 0.05
done
[[ -S $SOCK ]] || { echo "socket never appeared"; exit 1; }

# Persistent reader: collect events for 5 seconds in the background
(timeout 5 nc -U "$SOCK" >/tmp/wificapc.hw.events) &
LISTEN=$!
sleep 0.2

run() { printf '%s\n' "$1" | nc -N -U "$SOCK"; }

assert() {
	local got=$1 want=$2 label=$3
	if [[ $got != *"$want"* ]]; then
		printf 'FAIL %s\n  got : %s\n  want: %s\n' "$label" "$got" "$want" >&2
		exit 1
	fi
	printf 'ok   %s\n' "$label"
}

resp=$(run "{\"id\":1,\"cmd\":\"iface_set\",\"args\":{\"name\":\"$IFACE\"}}")
assert "$resp" '"ok":true'   "iface_set on $IFACE"

resp=$(run '{"id":2,"cmd":"iface_info"}')
assert "$resp" "\"iface\":\"$IFACE\"" "iface_info names iface"

resp=$(run '{"id":3,"cmd":"monitor_on"}')
assert "$resp" '"ok":true'   "monitor_on"

# Verify the kernel really sees monitor mode
mode=$(iw dev "$IFACE" info | awk '/type/ {print $2; exit}')
[[ $mode = monitor ]] && echo "ok   kernel reports type=monitor" || {
	echo "FAIL kernel reports type=$mode (wanted monitor)"; exit 1; }

resp=$(run '{"id":4,"cmd":"hop_start","args":{"channels":[1,6,11],"interval_ms":150}}')
assert "$resp" '"ok":true'   "hop_start on 1,6,11"

# Let the timer tick a few times
sleep 1
wait "$LISTEN" 2>/dev/null || true
LISTEN=

if grep -q '"event":"iface.channel"' /tmp/wificapc.hw.events; then
	echo "ok   iface.channel events emitted"
else
	echo "FAIL no iface.channel events seen"
	echo "--- captured stream ---"
	cat /tmp/wificapc.hw.events
	exit 1
fi
ticks=$(grep -c '"event":"iface.channel"' /tmp/wificapc.hw.events || true)
echo "info ${ticks} channel ticks captured in 1.0s"

resp=$(run '{"id":5,"cmd":"hop_stop"}')
assert "$resp" '"ok":true'   "hop_stop"

resp=$(run '{"id":6,"cmd":"monitor_off"}')
assert "$resp" '"ok":true'   "monitor_off"

mode=$(iw dev "$IFACE" info | awk '/type/ {print $2; exit}')
[[ $mode = managed ]] && echo "ok   kernel back to managed" || {
	echo "FAIL kernel reports type=$mode after monitor_off"; exit 1; }

echo "all good"
