# WiFiCapC — Improvement TODO

Items that survived triage and are worth a future session. Roughly in
descending impact-for-effort. Most have an integration angle on the
pwnagotchi side; cross-references are tagged `(pwnagotchi: …)`.

## Design ideas (not yet TODOs)

Bigger than a single PR — captured separately so they can spawn
multiple TODO items when ready.

- [docs/IDEAS/iface-and-driver-health.md](docs/IDEAS/iface-and-driver-health.md)
  — why `iface_set_mode(MONITOR)` is broken on brcmfmac, why the
  `wlan0mon` sibling-iface dance is the contract, and a phased plan
  for daemon-side wedge detection + an external recovery actor
  (`wificapc-watchdog`). Cross-cuts pwnagotchi.

## Reliability / stability

### TODO-R1 — Persist recon table across daemon restarts
- [ ] Dump `aps[]` / `stas[]` to a small file on shutdown (and maybe on
      `clear`) and reload at startup, with a configurable max-age so we
      don't resurface ancient state.
- Why: today every systemd respawn (e.g. after a brcmfmac firmware
  crash recovery cycle, or a routine reboot) loses the daemon's
  knowledge of the local airspace. Pwnagotchi has to rebuild. With
  persistence the daemon comes back up already aware of the APs/STAs
  it had seen.
- Files: `src/table.c`, new `src/state.c` (or extend `table_*` with
  `_dump` / `_load`).
- pwnagotchi: nothing required — events still fire on reload.

### TODO-R2 — Backoff for channel-set failures
- [ ] Per-channel "consecutive-failure" counter. If a channel fails N
      times in a row (driver-side glitch), skip it for a tick budget
      and emit `iface.channel_blacklisted`.
- Why: `chanhop_on_timer` currently logs a warning and tries the same
  channel on the next tick. Drivers that wedge on one channel keep
  taking the slot.
- Files: `src/chanhop.c`.

### TODO-R3 — Dynamic capacity for handshake pair table
- [ ] Replace the fixed `HS_MAX_PAIRS = 64` array with either a
      slab/free-list or a small dynamic resize (cap at maybe 256).
- Why: drops new pairs in dense environments (conferences,
  apartment buildings). Visible as `pair table full, dropping` log
  lines.
- Files: `include/handshake.h`, `src/handshake.c`.

### TODO-R4 — WPA3 SAE handshake support
- [ ] Recognize SAE Commit / Confirm frames. Decide on a hash format
      (hashcat 22000 has a SAE mode).
- Why: more APs are WPA3-only, today's classifier ignores them.
  Future-proof.
- Files: `src/eapol.c` (or new `src/sae.c`), `src/handshake.c`.

## User-visible quality

### TODO-Q1 — OUI vendor lookup
- [ ] Embed a compact OUI → vendor map (IEEE registry, ~40 KB
      compressed). Populate `ap_record.vendor` and `sta_record.vendor`
      so `ap.new` / `sta.new` events carry vendor strings.
- Why: pwnagotchi displays vendor next to MACs; today they're empty.
  Cosmetic but the user feedback always asks for this.
- Files: `src/table.c`, new `src/oui.c` + `oui.txt` data.
- pwnagotchi: nothing required (`agent.py` already passes
  `data.get("vendor", "")` through).

### TODO-Q2 — Pcapng output instead of pcap
- [ ] Re-implement `pcap.c` writer as pcapng (Section Header Block +
      Interface Description Block + Enhanced Packet Block per frame).
- Why: hcxpcapngtool emits "limited dump file format detected!" on
  legacy pcap and recommends pcapng. wpa-sec accepts both, but pcapng
  carries per-frame channel/freq metadata cleanly and is the format
  modern tools expect.
- Files: `src/pcap.c` (rename → `src/pcapng.c`), `include/pcap.h`.
- pwnagotchi: minor — extension changes from `.pcap` to `.pcapng`.
  Plugin path resolution already handles either.

### TODO-Q3 — Default channel set should include 5 GHz
- [ ] Replace `DEFAULT_CHANNELS = {1..13}` with a list that also
      covers UNII-1 (36, 40, 44, 48), UNII-2 (52..64), UNII-3
      (149, 153, 157, 161). Detect 5 GHz capability via nl80211
      `WIPHY_BANDS` so we don't try to hop to a channel the radio
      can't reach.
- Why: most home APs are 5 GHz now. With 2.4-only defaults we miss
  the majority of targets.
- Files: `src/iface.c`, `src/main.c`.

### TODO-Q4 — Expand `stats` reply ✅ v0.6.7 (68709f0)
- [x] Add: `n_handshake_pairs`, `current_channel`, `hopping`,
      `attack_active`, `iface_mode`, `uptime`. (`min_rssi_filter`
      deferred — daemon doesn't expose its current min_rssi setter
      back yet; not blocking.)
- Why: a single `stats` round-trip should be all an operator needs to
  diagnose state. Today they have to run `iface_info` + `stats` +
  inspect logs.
- Files: `src/main.c::handle_stats`.
- pwnagotchi: optional UI surfacing (e.g. show current channel in the
  status line).

### TODO-Q5 — Per-pair handshake-file cleanup IPC ✅ v0.6.7 (68709f0)
- [x] New `delete_handshake` command taking `ap_bssid`/`sta_mac`
      that unlinks the pcap + .22000.
- Why: handshake dir grows unbounded. Pwnagotchi knows which
  uploads succeeded; it should be able to ask the daemon to remove
  them. Today the daemon owns those files and has no API.
- Files: `src/main.c`, `include/handshake.h`.
- pwnagotchi: wpa-sec.py to call after a successful upload+ack.

## Performance / efficiency

### TODO-P1 — Persistent nl80211 session
- [ ] Hold one `nl_sock` open in `struct iface` (or globally) instead
      of alloc/free per call.
- Why: today every channel set opens a fresh netlink socket. With a
  250 ms hop that's 4 socket allocs/sec, ~350 K/day on a Pi Zero.
- Files: `src/iface.c`.

### TODO-P2 — Smarter autonomous attack scheduling
- [ ] In `on_attack_timer`: skip APs whose `(ap, sta)` already has a
      `.22000` on disk (or a bit set in the handshake table). Add a
      per-target backoff after N failed attempts. Prefer higher-RSSI
      targets in each tick.
- Why: today we blast auth+assoc to *every* visible AP every 5 s
  regardless of whether we already cracked the handshake. Wastes RF
  airtime, increases detectability, slows the radio.
- Files: `src/main.c::on_attack_timer`, `src/handshake.c`.

## Security / stealth

### TODO-S1 — MAC randomization for `inject_assoc` ✅ v0.6.9
- [x] `--mac-rand` daemon flag generates a fresh locally-
      administered, unicast MAC per `inject_assoc` call (one MAC
      shared between the auth and assoc frames so the AP sees a
      coherent dialog). `inject_set_mac_rand()` exposed in
      `include/inject.h` for runtime toggle. Per-call IPC override
      not implemented — flip via daemon flag at startup. Random
      bytes via `getrandom(2)`, `rand()` fallback for sandboxed
      hosts where it's unavailable. inject_deauth unchanged — it
      spoofs the AP's BSSID by design.
- Files: `src/inject.c`, `include/inject.h`, `src/main.c`.

### TODO-S2 — PMKID-only attack mode
- [ ] New IPC `pmkid_only` flag (or new `assoc_pmkid` cmd) that sends
      the auth+assoc once per target and returns immediately, never
      waiting for the 4-way exchange. Daemon already collects the
      PMKID from M1 if the AP leaks it.
- Why: faster cycles when targeting a list. PMKID-vulnerable APs
  give us cracking material in one round-trip.
- Files: `src/main.c`, `src/inject.c`.

## Polish

### TODO-X1 — `wificapc(8)` man page
- [ ] Generate from CLI flags + IPC reference. Install via `make install`.

### TODO-X2 — `docs/protocol.md`
- [ ] One canonical reference for every command and event with field
      schemas + version-introduced markers. Today the README's table
      is the closest thing.

### TODO-X3 — Configuration file
- [ ] `--config /etc/wificapc.toml` parser (or simple INI). Lets ops
      avoid 12-flag systemd `ExecStart` lines.
- Files: new `src/config.c`, `src/main.c`.

### TODO-X4 — Subscribe / unsubscribe IPC
- [ ] Per-client event filter: `subscribe { events: ["handshake.done"] }`
      / `unsubscribe`. Default unchanged (everything broadcast).
- Why: a UI client doesn't need every `iface.channel` tick at 250 ms.
  wpa-sec only cares about `handshake.done`. Reduces wakeups +
  outbox pressure.
- Files: `src/ipc.c`, `src/main.c`.

### TODO-X5 — Structured logging mode
- [ ] `--log-format json` to emit one JSON object per line instead of
      free-form. journald + downstream log aggregators love this.
- Files: `src/log.c`.

---

## How to use this file

- New session picks an item, opens a branch, ships a PR.
- When an item lands, move its checkbox to `[x]` and link the PR.
  When a whole section's items all land, drop the section.
- Don't add aspirational items here — only things with a clear
  enough scope that someone could start tomorrow.
