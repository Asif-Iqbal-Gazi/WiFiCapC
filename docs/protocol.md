<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# WiFiCapC IPC protocol

Canonical reference for the Unix-socket control protocol. The daemon is
**passive**: it captures, hops, and (optionally) injects, but policy lives
in the client (e.g. the pwnagotc agent). This document is kept in lockstep
with `src/main.c` — if they disagree, the code wins; please fix the doc.

## Transport

- A `SOCK_STREAM` Unix socket, default `/run/wificapc.sock` (`--socket`),
  mode `0660` (`--mode`).
- **Line-delimited JSON**: one JSON object per line, `\n`-terminated, in
  both directions. No embedded newlines inside an object.
- Multiple clients may connect (up to 16). Replies go only to the
  requesting client; events are broadcast (subject to per-client
  subscriptions — see `subscribe`).

### Request

```json
{"id": 1, "cmd": "<command>", "args": { ... }}
```

- `id` — any client-chosen integer; echoed back in the reply. Optional but
  recommended so replies can be correlated.
- `cmd` — command name (below).
- `args` — object of parameters; omitted when a command takes none.

### Reply

Success:

```json
{"id": 1, "ok": true, "data": { ... }}
```

Error:

```json
{"id": 1, "ok": false, "error": "human-readable reason"}
```

`data` is present only for commands that return values; otherwise an
empty-data `ok` is sent.

### Event (unsolicited)

```json
{"event": "ap.new", "bssid": "...", ...}
```

Events have no `id` and arrive at any time, interleaved with replies.

---

## Commands

### Liveness / info

| Command | Args | Reply `data` |
|---|---|---|
| `ping` | — | `{}` (ok) |
| `version` | — | `{version: "x.y.z"}` |
| `uptime` | — | `{uptime: <seconds>}` |
| `stats` | — | see **stats** below |
| `iface_info` | — | `{iface, mode, channel}` |

**stats** `data` fields: `n_aps`, `n_stas`, `n_handshake_pairs`,
`frames_total`, `frames_dropped`, `capturing` (bool), `hopping` (bool),
`current_channel`, `attack_active` (bool), `pmkid_only` (bool),
`iface_mode` (`"managed"`/`"monitor"`/…), `uptime`.

### Interface / capture lifecycle

Typical bring-up order: `iface_set` → `monitor_on` → `recon_start` →
`hop_start`.

| Command | Args | Notes |
|---|---|---|
| `iface_set` | `{name}` | Select the wireless iface (e.g. `wlan0`). |
| `monitor_on` | — | Put the iface into monitor mode. |
| `monitor_off` | — | Return the iface to managed mode. |
| `recon_start` | — | Begin AP/STA table building from captured frames. Requires an iface set. Reloads persisted recon state (R1) if present. |
| `recon_stop` | — | Stop table building. |
| `hop_start` | — | Start channel hopping over the configured list. |
| `hop_stop` | — | Stop hopping (stay on the current channel). |
| `set_channel` | `{channel}` | Park on a single channel (implies hop off). |
| `clear` | — | Wipe the AP/STA tables (no events emitted). |

### Recon queries

| Command | Args | Reply `data` |
|---|---|---|
| `list_aps` | — | `{aps: [{bssid, ssid?, vendor?, channel, rssi, ...}]}` |
| `list_stas` | — | `{stas: [{mac, ap_bssid?, vendor?, channel, rssi, ...}]}` |

### Tuning

| Command | Args | Notes |
|---|---|---|
| `set_ttls` | `{ap_ttl, sta_ttl, min_rssi}` | Eviction TTLs (s) and RSSI floor. |
| `set_handshake_dir` | `{path}` | Where per-pair `.pcap`/`.22000` are written. |
| `set_mac_rand` | `{enabled: 0\|1}` | Fresh random MAC per assoc (S1). |
| `set_pmkid_only` | `{enabled: 0\|1}` | Autonomous attack sends assoc only, no deauth (S2). |

### Handshakes

| Command | Args | Notes |
|---|---|---|
| `delete_handshake` | `{ap_bssid, sta_mac}` | Unlink the `.pcap` + `.22000` for a pair. Reply `data`: `{removed: <0..2>}`. |

### Injection (requires `recon_start` first)

| Command | Args | Notes |
|---|---|---|
| `assoc` | `{bssid}` | Send auth+assoc once (PMKID elicitation); returns immediately, never waits on the 4-way. SSID is looked up from the recon table. |
| `deauth` | `{bssid, sta, count, reason?}` | Send `count` (1..256) deauth frames spoofed from `bssid` to `sta`. |

### Event subscriptions (X4)

A client starts subscribed to **all** events. Narrow with:

| Command | Args | Notes |
|---|---|---|
| `subscribe` | `{events: "a,b,c"}` | Add event categories. |
| `unsubscribe` | `{events: "a,b,c"}` | Remove event categories. |

`events` is a comma/space-separated list of event names or category
shortcuts. Recognized tokens: `ap.new`, `ap.lost`, `sta.new`, `sta.lost`,
`iface.channel`, `iface.mode` (or `iface` for both), `handshake` /
`handshake.*` / `pmkid.captured` (the handshake category), and `all` / `*`.
Unknown tokens are ignored unless *every* token is unknown (then an error).

Example — the agent dropping the 4/sec channel chatter it ignores:

```json
{"id": 9, "cmd": "unsubscribe", "args": {"events": "iface.channel,iface.mode"}}
```

---

## Events

| Event | Category | Key fields |
|---|---|---|
| `ap.new` | AP | `bssid`, `ssid?`, `vendor?`, `channel`, `rssi` |
| `ap.lost` | AP | `bssid`, `ssid?`, `vendor?`, `channel`, `rssi` |
| `sta.new` | STA | `mac`, `ap_bssid?`, `vendor?`, `channel`, `rssi` |
| `sta.lost` | STA | `mac`, `ap_bssid?`, `vendor?`, `channel`, `rssi` |
| `iface.channel` | IFACE | `channel`, `freq` — emitted on every hop (~4/s) |
| `iface.mode` | IFACE | `mode` (`"managed"`/`"monitor"`) |
| `pmkid.captured` | HANDSHAKE | `ap_bssid`, `sta_mac`, `channel`, `rssi`, `msg_seen`, `pmkid` |
| `handshake.captured` | HANDSHAKE | one or more 4-way frames seen (same fields) |
| `handshake.done` | HANDSHAKE | pair retired; adds `pcap_path`, `hash22000_path?` |

Fields marked `?` are omitted when unknown (hidden SSID, unresolved/
randomized OUI vendor, unassociated STA, PMKID-only pairs with no `.22000`).

### Notes on handshake events

- `pmkid.captured` fires when an M1 carries a PMKID KDE; `handshake.captured`
  when M2/M3/M4 proves a real exchange. Both may fire for one pair.
- `handshake.done` fires once when the pair is finalized — eagerly on a
  complete 4-way (`anonce`+`m2`), otherwise at stale-close. `hash22000_path`
  is present only when a `.22000` was written.
