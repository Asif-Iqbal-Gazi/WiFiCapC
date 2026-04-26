#!/usr/bin/env bash
# Recon end-to-end on real hardware. Requires root.
#
# Usage: sudo IFACE=wlx00c0cab79cb7 RECON_SECS=10 bash test/recon.sh
#
# Brings up monitor mode, hops 1/6/11, captures for RECON_SECS seconds,
# then prints how many APs and STAs were observed and confirms ap.new
# events arrived on the socket.
set -euo pipefail

IFACE=${IFACE:-wlx00c0cab79cb7}
RECON_SECS=${RECON_SECS:-10}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
BIN=${BIN:-$REPO_DIR/wificapc}
SOCK=$(mktemp -u /tmp/wificapc.recon.XXXXXX.sock)
EVT=$(mktemp /tmp/wificapc.recon.events.XXXXXX)

if [[ $EUID -ne 0 ]]; then echo "must run as root" >&2; exit 2; fi
if [[ ! -x $BIN ]]; then echo "binary not built ($BIN)" >&2; exit 2; fi
if ! ip link show "$IFACE" >/dev/null 2>&1; then
	echo "iface $IFACE not present" >&2; exit 2; fi

cleanup() {
	[[ -n ${LISTEN:-} ]] && kill -TERM "$LISTEN" 2>/dev/null || true
	[[ -n ${PID:-}   ]] && kill -TERM "$PID"    2>/dev/null || true
	wait 2>/dev/null || true
	ip link set "$IFACE" down 2>/dev/null || true
	iw dev "$IFACE" set type managed 2>/dev/null || true
	ip link set "$IFACE" up 2>/dev/null || true
	rm -f "$SOCK" "$EVT"
}
trap cleanup EXIT

"$BIN" --socket "$SOCK" --foreground &
PID=$!
for _ in {1..50}; do [[ -S $SOCK ]] && break; sleep 0.05; done
[[ -S $SOCK ]] || { echo "socket never appeared"; exit 1; }

# Long-lived listener that captures events for RECON_SECS+2 seconds
(timeout $((RECON_SECS + 2)) nc -U "$SOCK" >"$EVT") &
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
assert "$resp" '"ok":true' "iface_set"

resp=$(run '{"id":2,"cmd":"monitor_on"}')
assert "$resp" '"ok":true' "monitor_on"

resp=$(run '{"id":3,"cmd":"hop_start","args":{"channels":[1,6,11],"interval_ms":250}}')
assert "$resp" '"ok":true' "hop_start"

resp=$(run '{"id":4,"cmd":"recon_start"}')
assert "$resp" '"ok":true' "recon_start"

echo "info capturing for ${RECON_SECS}s..."
sleep "$RECON_SECS"

resp=$(run '{"id":5,"cmd":"stats"}')
echo "info $resp"

resp=$(run '{"id":6,"cmd":"list_aps"}')
n_aps=$(printf '%s' "$resp" | sed -n 's/.*"count":\([0-9]\+\).*/\1/p' | head -1)
echo "info list_aps count=$n_aps"
[[ -n $n_aps && $n_aps -gt 0 ]] && echo "ok   recon discovered $n_aps APs" || {
	echo "FAIL recon found 0 APs (try a busier RF environment, or larger RECON_SECS)"
	exit 1; }

resp=$(run '{"id":7,"cmd":"list_stas"}')
n_stas=$(printf '%s' "$resp" | sed -n 's/.*"count":\([0-9]\+\).*/\1/p' | head -1)
echo "info list_stas count=$n_stas"

resp=$(run '{"id":8,"cmd":"recon_stop"}')
assert "$resp" '"ok":true' "recon_stop"

resp=$(run '{"id":9,"cmd":"hop_stop"}')
assert "$resp" '"ok":true' "hop_stop"

resp=$(run '{"id":10,"cmd":"monitor_off"}')
assert "$resp" '"ok":true' "monitor_off"

# Wait for the listener to flush
wait "$LISTEN" 2>/dev/null || true
LISTEN=

n_evt_ap=$(grep -c '"event":"ap.new"' "$EVT" || true)
echo "info ap.new events received: $n_evt_ap"
[[ $n_evt_ap -gt 0 ]] && echo "ok   ap.new events streamed" || {
	echo "FAIL no ap.new events on socket"
	echo "--- events stream ---"; cat "$EVT"; exit 1; }

# Sanity: every ap.new event should at minimum carry bssid + channel + rssi
if grep '"event":"ap.new"' "$EVT" | head -1 | grep -q '"bssid":"' \
   && grep '"event":"ap.new"' "$EVT" | head -1 | grep -q '"channel":' \
   && grep '"event":"ap.new"' "$EVT" | head -1 | grep -q '"rssi":'; then
	echo "ok   ap.new event shape contains bssid/channel/rssi"
else
	echo "FAIL ap.new event shape malformed"
	grep '"event":"ap.new"' "$EVT" | head -3; exit 1
fi

echo "all good"
