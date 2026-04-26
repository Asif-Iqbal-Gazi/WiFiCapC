#!/usr/bin/env bash
# Live handshake-capture test. Requires root.
#
# Usage:
#   sudo IFACE=wlx00c0cab79cb7 CHANNEL=6 WAIT_SECS=90 bash test/handshake.sh
#
# What it does:
#   1. Brings up monitor mode on IFACE
#   2. Pins to CHANNEL (so we don't miss frames during a 4-way exchange)
#   3. Starts recon (which opens the per-pair pcap when EAPOL appears)
#   4. Prompts you to toggle Wi-Fi on a phone connected to a network on
#      that channel — the rejoin generates the 4-way handshake
#   5. Waits up to WAIT_SECS for handshake.captured + handshake.hash22000
#      events to arrive on the socket
#   6. Verifies the .pcap and .22000 files exist and the hash file is non-empty
set -euo pipefail

IFACE=${IFACE:-wlx00c0cab79cb7}
CHANNEL=${CHANNEL:-6}
WAIT_SECS=${WAIT_SECS:-90}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
BIN=${BIN:-$REPO_DIR/wificapc}
SOCK=$(mktemp -u /tmp/wificapc.hs.XXXXXX.sock)
EVT=$(mktemp /tmp/wificapc.hs.events.XXXXXX)
HSDIR=$(mktemp -d /tmp/wificapc.hs.dir.XXXXXX)

if [[ $EUID -ne 0 ]]; then echo "must run as root" >&2; exit 2; fi
if [[ ! -x $BIN ]]; then echo "binary not built ($BIN)" >&2; exit 2; fi
if ! command -v hcxpcapngtool >/dev/null; then
	echo "hcxpcapngtool not on PATH — install hcxtools first" >&2; exit 2
fi
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
	echo "captures preserved in: $HSDIR"
}
trap cleanup EXIT

"$BIN" --socket "$SOCK" --foreground --debug &
PID=$!
for _ in {1..50}; do [[ -S $SOCK ]] && break; sleep 0.05; done
[[ -S $SOCK ]] || { echo "socket never appeared"; exit 1; }

(timeout $((WAIT_SECS + 5)) nc -U "$SOCK" >"$EVT") &
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

# Pin to a single channel so we don't miss any of the 4-way.
resp=$(run "{\"id\":3,\"cmd\":\"set_channel\",\"args\":{\"channel\":$CHANNEL}}")
assert "$resp" '"ok":true' "set_channel $CHANNEL"

resp=$(run "{\"id\":4,\"cmd\":\"set_handshake_dir\",\"args\":{\"path\":\"$HSDIR\"}}")
assert "$resp" '"ok":true' "set_handshake_dir"

resp=$(run '{"id":5,"cmd":"recon_start"}')
assert "$resp" '"ok":true' "recon_start"

cat <<EOF

  ┌────────────────────────────────────────────────────────────┐
  │ Listening on channel $CHANNEL of $IFACE for up to ${WAIT_SECS}s.
  │ NOW: toggle Wi-Fi off and back on on a device that
  │      reconnects to an AP on channel $CHANNEL.
  │ The reconnect's 4-way handshake should be captured.
  └────────────────────────────────────────────────────────────┘

EOF

deadline=$(( SECONDS + WAIT_SECS ))
got_handshake=""
got_hash=""
while [[ $SECONDS -lt $deadline ]]; do
	if grep -q '"event":"handshake.captured"' "$EVT"; then got_handshake=1; fi
	if grep -q '"event":"handshake.hash22000"' "$EVT"; then got_hash=1; break; fi
	sleep 1
done

run '{"id":10,"cmd":"recon_stop"}'  >/dev/null
run '{"id":11,"cmd":"monitor_off"}' >/dev/null
wait "$LISTEN" 2>/dev/null || true; LISTEN=

if [[ -z $got_handshake ]]; then
	echo "FAIL no handshake.captured event in ${WAIT_SECS}s"
	echo "--- events stream tail ---"; tail -30 "$EVT"
	exit 1
fi
echo "ok   handshake.captured event seen"

pcaps=( "$HSDIR"/*.pcap )
if [[ ! -e ${pcaps[0]} ]]; then
	echo "FAIL no .pcap files in $HSDIR"; exit 1; fi
echo "ok   pcap exists: ${pcaps[0]}"

if [[ -z $got_hash ]]; then
	echo "WARN handshake.hash22000 event not seen yet — running hcxpcapngtool inline"
	hcxpcapngtool -o "${pcaps[0]}.22000" "${pcaps[0]}" >/dev/null 2>&1 || true
fi

hash_files=( "$HSDIR"/*.22000 )
if [[ ! -e ${hash_files[0]} ]]; then
	echo "FAIL no .22000 files produced"; exit 1; fi
echo "ok   .22000 file exists: ${hash_files[0]}"

if [[ ! -s ${hash_files[0]} ]]; then
	echo "FAIL .22000 file is empty (capture incomplete?)"; exit 1; fi
echo "ok   .22000 file is non-empty ($(wc -c <"${hash_files[0]}") bytes)"

echo "all good"
