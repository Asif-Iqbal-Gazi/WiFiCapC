# WiFiCapC

A small, native C daemon for 802.11 monitor-mode capture, channel hopping,
and WPA2 4-way / PMKID handshake acquisition. Drop-in replacement for the
bettercap surface that pwnagotchi historically used — single static binary,
single Unix-domain socket, no Python in the hot path.

Single-radio, single-process, designed to run unattended for days on a Pi
Zero 2 W under the pwnagotchi service. Every reported issue from the field
since v0.6.0 has been a fix in this tree, not pwnagotchi-side.

## Status

Stable on Raspberry Pi OS 64-bit (kernel 6.12, brcmfmac with Nexmon
firmware). Releases on every `v*` tag with cross-compiled aarch64 binary +
SHA256 attached.

Running pairs:

| Daemon  | Compatible pwnagotchi |
|---------|------------------------|
| `v0.6.6` | `v3.0.7+`             |
| `v0.6.5` | `v3.0.4+`             |
| `v0.6.4` | `v3.0.3+`             |

## Features

- **AF_PACKET monitor capture** — 802.11 frames in, radiotap parsed, FCS
  honoured. RSSI filter optional (recon table only; handshake routing is
  always unfiltered).
- **nl80211 iface management** — mode set (monitor/managed), channel set,
  link up/down. RFKILL soft-unblock and Wi-Fi power-save off are issued
  automatically before bringing the link up, so a freshly reloaded
  brcmfmac driver doesn't trip on `EBUSY`.
- **timerfd channel hopper** — fixed list of channels, configurable
  dwell time. Survives transient `iface_set_channel` failures by logging
  and retrying on the next tick.
- **AP / STA in-memory recon table** — TTL-based eviction, snapshot and
  emit on new/lost transitions.
- **EAPOL-Key extractor** — M1/M2/M3/M4 classification, PMKID KDE
  detection, ANonce + MIC + key-data preservation for `.22000`
  assembly.
- **Per-pair handshake artifacts** — for every pair that produces
  usable material (PMKID **or** ANonce+M2):
  - a `<ap>_<sta>.22000` hashcat hash file (offline cracking)
  - a `<ap>_<sta>.pcap` (cached beacon prefix + EAPOL frames, what
    wpa-sec.org / hcxpcapngtool consume).
  Pairs that retire without enough frames don't write either file —
  no junk uploads.
- **Active attacks** — spoofed deauth (count + reason configurable);
  open auth + WPA2-PSK association request to elicit M1/PMKID.
- **Self-healing on driver glitches** — capture exits on
  `ENODEV`/`ENETDOWN`, systemd respawns, `wificapc-prep.service`
  cycles `brcmfmac` and clears `rfkill`. Days-long uptime on flaky
  USB Wi-Fi adapters is a tested workload.
- **Line-delimited JSON IPC** over a Unix socket. Multi-client,
  request/reply with id, server-pushed events.

## Quickstart

```sh
# Build
make

# Standalone (autostart capture + 2.4 GHz hop + autonomous attacks)
sudo ./wificapc \
    --iface wlan0 \
    --hs-dir /etc/pwnagotchi/handshakes \
    --attack \
    --foreground

# Talk to it
echo '{"id":1,"cmd":"ping"}' | nc -U /run/wificapc.sock
echo '{"id":2,"cmd":"stats"}' | nc -U /run/wificapc.sock
```

## Run modes

### Standalone (daemon owns the policy)

The systemd unit shipped in `systemd/wificapc.service` boots the daemon
with `--iface`, `--hs-dir`, `--attack`. Capture, hopping, and the
autonomous attack timer all start at boot. Useful for "headless capture
node" deployments. Pair with `wificapc-prep.service` for brcmfmac
auto-recovery.

```sh
make
sudo make install              # binary only since v0.6.5
sudo make install-systemd      # opt-in: ships the .service files
sudo systemctl enable --now wificapc-prep.service wificapc.service
```

### Pwnagotchi (agent owns the policy)

The pwnagotchi image overrides this with its own `wificapc.service`
that starts the daemon in **command-only** mode (no autostart). The
agent connects over the IPC socket and drives everything: `iface_set`,
`monitor_on`, `set_handshake_dir`, `set_ttls`, `recon_start`,
`hop_start`, `assoc`, `deauth`, `set_channel`. Daemon stays passive.
Standard pwnagotchi build pulls v0.6.6 via the chroot script:

```
stage3/01-wificapc/01-run-chroot.sh:
  WIFICAPC_TAG=v0.6.6
  git clone --depth 1 --branch "${WIFICAPC_TAG}" ...
```

## IPC protocol

Line-delimited JSON over a `SOCK_STREAM` Unix socket (default
`/run/wificapc.sock`, mode `0660`). Multiple clients allowed.

**Request:**
```json
{"id": 1, "cmd": "stats"}
```

**Reply:**
```json
{"id": 1, "ok": true, "data": {"n_aps": 7, "n_stas": 23, "frames_total": 481213, "frames_dropped": 12, "capturing": true}}
```

**Event** (server-initiated, no `id`):
```json
{"event": "handshake.done", "data": {"ap_bssid": "aa:bb:cc:dd:ee:ff", "sta_mac": "11:22:33:44:55:66", "channel": 6, "rssi": -57, "msg_seen": 14, "pmkid": false, "file": "/etc/pwnagotchi/handshakes/aabbccddeeff_112233445566.pcap", "hash22000": "/etc/pwnagotchi/handshakes/aabbccddeeff_112233445566.22000"}}
```

### Commands

| cmd                  | args                                                  | reply data                              |
|----------------------|-------------------------------------------------------|-----------------------------------------|
| `ping`               | —                                                     | `{"pong":"yes"}`                        |
| `version`            | —                                                     | `{"name":"wificapc","version":"..."}`   |
| `uptime`             | —                                                     | `{"uptime":secs}`                       |
| `iface_set`          | `name`                                                | —                                       |
| `iface_info`         | —                                                     | iface struct as JSON                    |
| `monitor_on`         | —                                                     | —                                       |
| `monitor_off`        | —                                                     | —                                       |
| `set_channel`        | `channel`                                             | —                                       |
| `hop_start`          | `channels[]`, `interval_ms?`                          | —                                       |
| `hop_stop`           | —                                                     | —                                       |
| `recon_start`        | —                                                     | —                                       |
| `recon_stop`         | —                                                     | —                                       |
| `list_aps`           | —                                                     | `{count, items:[...], truncated?}`      |
| `list_stas`          | —                                                     | `{count, items:[...], truncated?}`      |
| `stats`              | —                                                     | counters + flags                        |
| `clear`              | —                                                     | —                                       |
| `set_handshake_dir`  | `path`                                                | —                                       |
| `set_ttls`           | `ap_ttl?`, `sta_ttl?`, `min_rssi?`                    | —                                       |
| `set_mac_rand`       | `enabled` (bool/int)                                  | —                                       |
| `deauth`             | `bssid`, `sta?`, `count?`, `reason?`                  | `{sent:N}`                              |
| `assoc`              | `bssid`                                               | —                                       |

### Events emitted

| event                  | when                                                       |
|------------------------|------------------------------------------------------------|
| `iface.mode`           | mode change (managed ↔ monitor)                            |
| `iface.channel`        | every successful channel set (hopper or pin)               |
| `ap.new` / `ap.lost`   | recon table transitions                                    |
| `sta.new` / `sta.lost` | recon table transitions                                    |
| `handshake.captured`   | first M2/M3/M4 seen for a pair (incremental)               |
| `pmkid.captured`       | PMKID KDE seen in M1                                       |
| `handshake.done`       | pair retired; usable `.22000` + `.pcap` ready (or no file) |

## Architecture

```
            ┌──────────────────────────────────────┐
   802.11 →─│ wificapc (single process)            │
   monitor  │   AF_PACKET RX → radiotap → 802.11   │
            │     ↓                                │
            │   AP/STA recon table                 │
            │     ↓                                │
            │   EAPOL collector → per-pair pcap    │──→ /etc/pwnagotchi/handshakes/
            │     ↓                                │      <ap>_<sta>.pcap
            │   .22000 writer                      │      <ap>_<sta>.22000
            │                                      │
            │   nl80211 ◄─── chanhop timer         │
            │   nl80211 ◄─── iface_set_mode        │
            │   AF_PACKET TX (deauth/assoc)        │
            └────────────┬─────────────────────────┘
                         │ Unix socket, line-delimited JSON
                         ▼
               pwnagotchi (or any client)
```

One `epoll` loop, one thread of control. The capture socket, the channel
hopper's timerfd, the eviction timerfd, and N client sockets are all
multiplexed in `ipc_run()`.

## Project layout

```
include/        public headers (one per module)
src/            implementation (.c per header)
test/           parser unit tests + smoke test driver
systemd/        wificapc.service + wificapc-prep.service
.github/        release workflow (cross-compiles aarch64 on tag)
```

## Build

Native:
```sh
make
make test           # parser unit tests + smoke test
make asan           # rebuild with ASan + UBSan for development
```

Cross-compile for aarch64 (Pi Zero 2 W / Pi 4):
```sh
make CC=aarch64-linux-gnu-gcc \
     NL_CFLAGS="-I/opt/libnl-aarch64/include/libnl3" \
     NL_LIBS="/opt/libnl-aarch64/lib/libnl-genl-3.a /opt/libnl-aarch64/lib/libnl-3.a"
```

The release workflow does this automatically on every `v*` tag and
attaches `wificapc-X.Y.Z-aarch64.zip` (binary + SHA256) to the GitHub
release.

## Contributing / improvements

See [TODO.md](TODO.md) for the prioritized improvement list. Pick an
item, open a PR, signed commits preferred.

## License

GPL-3.0-or-later. See `LICENSE`.
