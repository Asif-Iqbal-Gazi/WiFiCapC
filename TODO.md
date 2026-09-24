# WiFiCapC — Improvement TODO

Reworked after a full codebase audit (2026-09), targeting the **Raspberry
Pi Zero 2 W**: quad A53 @ 1 GHz, 512 MB RAM shared with GPU, SD-card
storage (wear-sensitive), brcmfmac on-SoC Wi-Fi that is **2.4 GHz only
(no 5 GHz, no 6 GHz)**, days of unattended uptime. Ordered by
impact-for-effort. `[x]` + `✅ vX.Y.Z` when shipped.

Knock these top-to-bottom. Tier 1 first (bugs + dead-code + cheap wins),
then Tier 2 (perf), then Tier 3 (features).

## Design ideas (not yet TODOs)

- [docs/IDEAS/iface-and-driver-health.md](docs/IDEAS/iface-and-driver-health.md)
  — brcmfmac wedge detection + external recovery actor. R2 (shipped)
  is one input to its Phase 1.

---

# Tier 1 — bugs, dead code, cheap wins

### B1 — radiotap: bound-check the present-word extension walk ✅ v0.6.12
- [x] `radiotap_parse` reads `le16(pres + 2)` for the next present word's
      continuation bit **before** confirming that word is within `it_len`
      / `len` (the `&&` short-circuits deref-first). A malformed/truncated
      radiotap header (it_len == len, continuation bit set, no room) reads
      up to 2 bytes past the buffer.
- Severity: low — radiotap is prepended by the *local* kernel, not the
  remote attacker, so it's well-formed in practice. But it's a real OOB
  read in a hot parse path; hardening is a few lines.
- Fix: require room for the next word (`4 + (nwords+1)*4 <= it_len`)
  before dereferencing, or check the bound before the `le16`.
- Files: `src/radiotap.c`.

### B2 — recon: downlink (FromDS) data frames mis-record the STA ✅ v0.6.12
- [x] For a FromDS data frame (AP→STA), dot11.c sets `d->sa` = the
      *original source* (often a host on the wired LAN behind the AP) and
      `d->da` = the actual wireless client. `capture.c` →
      `table_observe_sta` keys the STA off `d->sa`, so the STA table fills
      with wired/upstream MACs attributed to the BSSID. Inflates STA
      counts and makes the autonomous attacker deauth non-existent
      clients.
- Fix: the wireless STA is `d->sa` **except** when `from_ds && !to_ds`,
      where it's `d->da`. Skip group-addressed (multicast/broadcast)
      derived MACs entirely. (handshake.c already derives the pair
      correctly and is unaffected.)
- Files: `src/capture.c` and/or `src/table.c` (`table_observe_sta`).

### C3 — restrict channel/freq helpers to 2.4 GHz (drop 5/6 GHz) ✅ v0.6.12
- [x] The Zero 2 W radio is 2.4 GHz only, so the 5 GHz and 6 GHz arms of
      `iface_chan_to_freq` / `iface_freq_to_chan` are dead weight — and
      the 6 GHz arm carries a latent channel-number ambiguity bug
      (channels 1..13 resolve as 2.4 GHz first). Cut both helpers down to
      channels 1..14 (2407 + ch*5, with 14 = 2484). This deletes the
      ambiguity and matches the hardware. (The old "add 5 GHz default
      channels" item is dropped for the same reason — nothing to add.)
- Note: if a USB 5 GHz adapter is ever a target, reintroduce behind a
      band-aware API rather than overloading the bare channel number.
- Files: `src/iface.c`.

### C1 — remove the dead `proc` module ✅ v0.6.12
- [x] `proc.c` + `proc.h` (async child-process runner for
      hcxpcapngtool/wlancap2wpasec) is **never used**: `proc_create` is
      called nowhere, `app.proc` is only ever `NULL` then "destroyed".
      The daemon assembles `.22000` itself. ~240 lines of dead code +
      a misleading "kept for future use" field.
- Fix: delete `src/proc.c`, `include/proc.h`, the `#include`, the
      `struct proc *proc` field, and the `if (a.proc) proc_destroy` line.
- Files: `src/proc.c`, `include/proc.h`, `src/main.c`.

### C2 — remove the `set_wpasec` no-op stub ✅ v0.6.12
- [x] `handle_set_wpasec` parses `enabled` and does nothing but reply ok.
      The pwnagotc agent never sends it (verified). It's a vestigial
      bettercap-compat lie. Remove the handler + dispatch line (and drop
      it from `test/smoke.sh` if referenced).
- Files: `src/main.c`, `test/smoke.sh`.

### Q6 — demote autonomous-attack per-target logging to DEBUG ✅ v0.6.12
- [x] `inject_deauth` / `inject_assoc` log one INFO line **per target**.
      With `--attack` and ~50 visible APs every 5 s that's ~600 INFO
      lines/min into journald — needless SD/journal churn on a device
      meant to run for days (related to the zram-log-full incident on the
      pi). Keep a single per-tick summary at INFO; move per-target lines
      to DEBUG.
- Files: `src/inject.c`, `src/main.c::on_attack_timer`.

---

# Tier 2 — performance / footprint (Zero 2)

### P1 — persistent nl80211 session
- [ ] Every `iface_set_channel` does `nl_socket_alloc` + `genl_connect` +
      `genl_ctrl_resolve` (a full netlink round-trip just to re-resolve
      the nl80211 family id) + the actual command — i.e. **two round
      trips per hop**, 4 hops/s = 8 netlink transactions/s, forever, on a
      1 GHz core. Hold one `nl_sock` + cached `family_id` open in
      `struct iface`; reuse for channel/mode/power-save. Also switch
      channel-set to `NL80211_CMD_SET_CHANNEL` (per-ifindex) — the header
      already documents that; the code uses the legacy `SET_WIPHY`.
- Files: `src/iface.c`, `include/iface.h`.

### P3 — stop snapshotting full ap_records onto the stack
- [ ] `sizeof(struct ap_record)` is **632 bytes** (it carries a 512-byte
      cached beacon). `on_attack_timer` copies `aps[256]` (158 KB) **and**
      `stas[1024]` (90 KB) onto the stack every 5 s, and `handle_list_stas`
      puts ~152 KB on the stack — all just to read a few fields. Wasteful
      memcpy + big transient stack frames.
- Fix: a lightweight snapshot struct (bssid/ssid/channel/rssi) or an
      in-place `table_for_each_*` iterator with a callback. Keeps the hot
      attack path and list handlers off 150–250 KB stack spikes.
- Files: `src/table.c`, `include/table.h`, `src/main.c`.

### R5 — write the handshake artifacts as soon as a pair is complete
- [ ] Today `.22000` / `.pcap` are only written in `close_pair`, i.e. on
      the 30 s stale timeout. A device that keeps re-handshaking (busy
      STA) refreshes `last_seen` and never triggers the write, so a
      captured handshake sits unwritten for minutes. Emit + write the
      moment `have_pmkid || (have_anonce && have_m2)` first becomes true
      (guard with an `emitted_done`/`written` flag so close doesn't
      double-write). Faster handoff to wpa-sec, closes the "never
      finalized" gap.
- Files: `src/handshake.c`.

### P2 — smarter autonomous attack scheduling
- [ ] `on_attack_timer` blasts auth+assoc at **every** visible AP and
      deauth at every STA each interval, regardless of whether we already
      have the handshake. Skip pairs already on disk / flagged; per-target
      backoff after N attempts; prefer high-RSSI targets. Cuts RF airtime,
      detectability, CPU, and log volume. (Pairs well with Q6.)
- Files: `src/main.c::on_attack_timer`, `src/handshake.c`.

---

# Tier 3 — features / larger

### R3 — dynamic capacity for the handshake pair table
- [ ] `HS_MAX_PAIRS = 64` fixed array drops pairs in dense environments
      (`pair table full, dropping`). Grow dynamically (cap ~256) or use a
      slab/free-list. On 512 MB, a few hundred × ~1.4 KB pairs is fine.
- Files: `include/handshake.h`, `src/handshake.c`.

### R1 — persist recon table across daemon restarts
- [ ] Dump `aps[]`/`stas[]` on shutdown, reload with a configurable
      max-age. Survives the brcmfmac respawn cycle so the daemon comes
      back aware of the airspace. (pwnagotc D5 handles the reconnect wave.)
- Files: `src/table.c`, new `src/state.c`.

### Q1 — OUI vendor lookup
- [ ] Embed a compact OUI→vendor table (~40 KB compressed); populate
      `vendor` on ap/sta records so `ap.new`/`sta.new` carry it. pwnagotc
      D1 surfaces it in the UI (field already flows through as "").
- Files: `src/table.c`, new `src/oui.c` + data.

### W1 — every capture must have a wpa-sec-uploadable artifact
- [ ] wpa-sec accepts pcap/pcapng only (never `.22000`; it runs
      hcxpcapngtool on the upload). We keep `.22000` for offline hashcat
      and already save a per-pair `.pcap` for **4-way** captures (v0.6.8)
      — that path is covered. The gap is **PMKID-only** captures: their
      pcap (beacon + brcmfmac M1) is rejected because hcxpcapngtool flags
      the M1 as `KDV:0 AKM defined - not supported`, so v0.6.8 drops it —
      leaving PMKID-only handshakes with no wpa-sec route.
- Fix options (research needed): (a) synthesize a normalized,
      hcxpcapngtool-parseable EAPOL-M1 (or association frame) carrying the
      PMKID KDE, written into the pcap; (b) use wpa-sec's dedicated PMKID
      submission path from the agent using the `.22000` WPA*01 line;
      (c) accept that brcmfmac PMKIDs are offline-only. Decide, then make
      it explicit rather than silently dropping.
- Files: `src/handshake.c` (daemon side), pwnagotc `wpa-sec.py` (if (b)).

### Q2 — pcapng output instead of pcap
- [ ] Re-implement the writer as pcapng (SHB + IDB + EPB). Directly serves
      the wpa-sec goal: drops hcxpcapngtool's "limited dump file format
      detected" warning and is the format modern tooling expects; carries
      per-frame channel metadata cleanly. wpa-sec accepts both, so this is
      quality, not a fix. pwnagotc D2 handles the `.pcap`→`.pcapng`
      extension migration.
- Files: `src/pcap.c` → `src/pcapng.c`, `include/pcap.h`.

### S2 — PMKID-only attack mode
- [ ] IPC flag / `assoc_pmkid` cmd: send auth+assoc once and return,
      never wait on the 4-way. Faster target cycling.
- Files: `src/main.c`, `src/inject.c`.

### R4 — WPA3 SAE handshake support
- [ ] Recognize SAE Commit/Confirm; pick a hashcat 22000 SAE mode. The
      current fixed 95-byte key-descriptor offsets in `eapol.c` assume
      classic WPA2 — SAE needs its own path.
- Files: `src/eapol.c` (or new `src/sae.c`), `src/handshake.c`.

### X1–X5 — polish
- [ ] X1 `wificapc(8)` man page · X2 `docs/protocol.md` (canonical
      command/event reference) · X3 `--config` file parser · X4
      subscribe/unsubscribe IPC (pwnagotc D6) · X5 `--log-format json`.

---

## Shipped (changelog)

- **v0.6.1** stability hardening (NULL deref, nl busy-loop, fd leak,
  iface_set teardown, exit-on-recv-error, volatile stop)
- **v0.6.2–0.6.4** brcmfmac recovery: `wificapc-prep`, daemon rfkill
  unblock + power_save off
- **v0.6.5–0.6.8** per-pair pcap+.22000 pipeline, gated to skip
  PMKID-only/partial pcaps wpa-sec rejects
- **v0.6.7** expanded `stats` (Q4), `delete_handshake` IPC (Q5)
- **v0.6.9/0.6.10** MAC randomization (S1) + `set_mac_rand` IPC
- **v0.6.11** chanhop per-channel backoff (R2)

## How to use this file

- Pick the top unchecked item, branch, ship a PR, bump the version, tag.
- Mark `[x]` + `✅ vX.Y.Z` when it lands; move it to the changelog when a
  whole tier clears.
- Bump `pwnagotc/stage3/01-wificapc/01-run-chroot.sh` `WIFICAPC_TAG` on
  the next pwnagotc image so the change reaches the Pi.
