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
- [docs/IDEAS/auto-mode.md](docs/IDEAS/auto-mode.md) — `--auto`: a
  self-sufficient autonomous capture mode (channel auto-detect, intelligent
  hop+attack to maximise handshakes à la hcxdumptool, self-written
  artifacts), with pwnagotc inverted to a thin consumer. Spawns the AU*
  items below.

---

# Autonomous mode (`--auto`) — see docs/IDEAS/auto-mode.md

### AU1 — channel auto-detection (Phase 0) ✅ v0.7.2
- [x] `iface_supported_channels()` parses `NL80211_CMD_GET_WIPHY` bands/freqs
      (regdomain + DISABLED/NO-IR aware), generic across 2.4/5/6 GHz. Replaces
      the hardcoded 1-13 default when channels=auto.
- Files: `src/iface.c`, `include/iface.h`.

### AU2 — self-managed monitor vif (Phase 0) ✅ v0.8.0
- [x] Daemon brings monitor up itself (create vif / set type), brcmfmac-safe
      (managed netdev down first; never flip it live -> `-25`). Lets `--auto`
      run with no launcher; retires the pwnagotc launcher's vif creation
      (old A3). Needs on-pi validation.
- Files: `src/iface.c`, `include/iface.h`.

### AU3 — auto orchestrator + IPC (Phase 1) ✅ v0.8.0 (flag; runtime IPC toggle deferred)
- [x] `--auto` flag + `auto_start`/`auto_stop` IPC + `stats.auto`. New
      `src/auto.c` sequences detect->monitor->recon->hop->attack.
- Files: `src/auto.c`, `src/main.c`.

### AU4 — channel-coupled capture-maximising engine (Phase 1) ✅ v0.8.0
- [x] Per-dwell attack rounds (inject only on the tuned channel); PMKID-first
      via directed assoc, targeted deauth only when a client exists + a
      reconnect listen window; stop at first usable handshake (PMKID or
      Q7-validated 4-way); adaptive dwell. Builds on P2 + chanhop.
- Files: `src/auto.c`, `src/main.c`, `src/chanhop.c`, `src/inject.c`.

### AU5 — standalone UX (Phase 2) ✅ v0.8.1 (status + `auto` config key; deauth/dwell dials deferred)
- [x] Periodic status summary (human + JSON via X5); auto-mode config knobs
      via `--config` (channels=auto|list, attack mode, deauth dial, dwell,
      output dir, filters).
- Files: `src/auto.c`, `src/main.c`.

### AU6 — pwnagotc thin consumer (Phase 3, agent repo) ✅ (v3.0.19–v3.0.24)
- [x] Agent consumes stats.auto + ap/sta/handshake + attack.assoc/deauth
      events, displays + uploads; set_attack toggles the attack; AU7 next.

### AU7 — runtime self-driving toggle (auto_start / auto_stop) ✅ v0.8.5
- [x] IPC to start/stop the `--auto` self-hop+attack at runtime without
      dropping monitor/capture, so a client can hand channel control to the
      agent (pwnagotc "Agent" mode) and take it back ("Engine" mode). Add
      `auto_driving` to `stats`. Completes AU3's deferred runtime toggle;
      consumed by pwnagotc's tri-mode (Manual/Agent/Engine).
- Files: `src/main.c`.

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

### E1 — 5 GHz support + host-agnostic engine defaults ✅ v0.8.7
Surfaced by bringing up a dual-band RTL8812AU (Alfa AWUS036ACH) on an x86-64
host as a testbed.
- [x] **5 GHz re-added** (reverses C3 for dual-band adapters): `iface_chan_to_freq`
      / `iface_freq_to_chan` map channels 36..177 (`5000 + ch*5`). 5 GHz numbers
      don't overlap 2.4 (1..14) so a bare channel int stays unambiguous; 6 GHz
      stays out (its 1..233 *do* overlap). On the Alfa: 14→39 channels, ~157→~229
      APs. DFS channels enumerate (RX/passive OK) and tune fine. ✅ v0.8.7
- [x] **Enumerate in every mode**: dropped the `&& auto_mode` guard and the
      pre-autostart 13-channel pre-fill in `main()`, so a plain (non-`--auto`)
      capture run covers the radio's real band plan, not a hardcoded 2.4 list.
- [x] **Neutral handshake dir**: `DEFAULT_HS_DIR` was `/etc/pwnagotchi/handshakes`
      (engine assuming pwnagotchi + mkdir-spamming on hosts without it). Now
      `handshakes` (CWD-relative); `ensure_dir` is `mkdir -p` and caches the
      result (`dir_ready`) so a bad dir no longer spams per write. pwnagotchi
      passes `-H /etc/pwnagotchi/handshakes` explicitly.
- Note: rtw88 (in-kernel) does monitor **RX** well but does **not radiate**
      injected frames — confirmed: our TX writes succeed, no AP responds, and
      hcxdumptool can't operate either. Injection needs the out-of-tree
      morrownr `8812au` driver. Attacks remain validated on the Pi (brcmfmac).
- Files: `src/iface.c`, `src/main.c`, `src/handshake.c`.

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

### P1 — persistent nl80211 session ✅ v0.6.13
- [x] Cache one `nl_sock` + resolved family id on `struct iface`
      (`iface_nl()` opens lazily, `iface_close()` frees; `iface_open`
      closes any stale session before re-targeting, shutdown closes it).
      GET_INTERFACE / SET_INTERFACE / SET_POWER_SAVE / SET_WIPHY all reuse
      it, so a channel hop no longer re-runs `genl_ctrl_resolve` (a full
      round-trip) + socket alloc/free each tick.
- Kept channel-set as `SET_WIPHY` (not `SET_CHANNEL`) deliberately: it's
      the form brcmfmac reliably honours in monitor mode, and swapping it
      is an independent risk the perf win doesn't need.
- Files: `src/iface.c`, `include/iface.h`, `src/main.c`.

### P3 — stop snapshotting full ap_records onto the stack ✅ v0.6.14
- [x] Moved the 512-byte cached beacon out of `ap_record` into a parallel
      `beacons[]` array in `struct table` (reset on slot (re)alloc /
      eviction / clear; fetched via new `table_ap_beacon()`). `ap_record`
      632 → **112 bytes**: `list_aps` snapshot 158 → 28 KB, attack-timer
      snapshot 248 → 116 KB. No JSON/IPC change (beacon was never emitted).
      Total table heap unchanged — the blob just moved off the per-record
      struct so snapshots don't drag it. (The residual STA-array copy is
      inherently small per-record; an iterator is overkill now.)
- Files: `src/table.c`, `include/table.h`, `src/handshake.c`.

### R5 — write the handshake artifacts as soon as a pair is complete ✅ v0.6.15
- [x] `finalize_pair()` writes the `.22000` + fires `handshake.done` the
      moment a complete 4-way (`have_anonce && have_m2`) is held, called
      from `handshake_observe`; `done_emitted` guards `close_pair` from
      rewriting/re-emitting. Deliberately finalizes on the 4-way only,
      not on PMKID (PMKID rides in M1 — finalizing there would pre-empt
      the M2/M3/M4 landing microseconds later); PMKID-only pairs still
      finalize at stale-close, which is fine since a lone M1 doesn't keep
      the pair alive. The pcap is left open after eager finalize so late
      frames keep appending (closing would let ensure_pcap reopen+truncate).
- Files: `src/handshake.c`.

### P2 — smarter autonomous attack scheduling ✅ v0.6.16
- [x] `on_attack_timer` used to blast auth+assoc at **every** visible AP
      and deauth at every STA each interval, regardless of whether we
      already had the handshake. Now: APs flagged `captured` (via
      `table_mark_ap_captured` on `handshake.done`) are skipped, so are
      their STAs; per-target cooldown (`ATTACK_COOLDOWN_SEC=30`) and an
      attempt cap (`ATTACK_MAX_ATTEMPTS=10`) throttle the rest; each tick
      launches at most `ATTACK_PER_TICK=8` assoc + 8 deauth. Cuts RF
      airtime, detectability, CPU, and log volume. (Pairs with Q6.)
      Attack bookkeeping (`captured`/`last_attack`/`attack_count`) lives
      in ap_record/sta_record, cleared on eviction.
- Files: `src/main.c::on_attack_timer`, `src/table.c`, `include/table.h`.

### P6 — hcxdumptool-parity attack improvements
From a source-level study of hcxdumptool 7.1.2's default attack model.
- [x] **B — MFP-aware deauth.** Parse RSN capabilities (MFP bits) from beacons
      (`dot11.c::parse_rsn` → `dot11_info.mfp_required`, stored in ap_record);
      skip deauth on 802.11w-required APs (they ignore it) — still PMKID them
      via assoc. `table_ap_mfp_required`. ✅ v0.8.6
- [x] **D — attempt-budget replenish.** A gave-up target (`attack_count` cap)
      re-arms after `TABLE_ATTACK_REPLENISH_SEC`=1h idle (hcxdumptool parity),
      in `table_note_{ap,sta}_attacked` + the give-up check. ✅ v0.8.6
- [x] **C-lite — attack-on-new-target.** Fire one assoc/deauth the instant a
      new AP/STA appears (`on_table_event` → `attack_new_{ap,sta}`), silent, for
      fast first-contact; the periodic path's cooldown prevents double-hits. ✅ v0.8.6
- [ ] **A — ap-less / rogue-AP M2 client attack** (the big one). Respond to
      client probe requests impersonating the probed ESSID → assoc/auth
      responses → inject our own EAPOL M1 → capture the client's M2 → feed the
      .22000 pipeline. Harvests handshakes from probing clients with no AP in
      range. Needs a rogue-AP state machine + a config/IPC gate (like
      `pmkid_only`). Design doc first, then its own release. See
      `docs/IDEAS/ap-less-m2-attack.md`.

---

# Tier 3 — features / larger

### R7 — capture-health rx-silence watchdog ✅ v0.6.18
- [x] **Field-observed 2026-09-27 on a fresh flash:** the radio can come up
      wedged — `SET_WIPHY … failed: -7` on every channel, chanhop blacklists
      them all, AF_PACKET delivers 0 frames, and it never recovers on its own
      (needs the launcher's modprobe cycle). Only a `systemctl restart
      wificapc` (which re-runs `wificapc-launcher`) fixed it. Added a health
      timer (`HEALTH_CHECK_SEC=5`): while hopping+capturing, if `frames_total`
      shows **0 new frames for `RX_SILENCE_SEC=45`s**, log and `exit(3)` so
      systemd (`Restart=always`) re-runs the launcher and re-inits the radio.
      A healthy radio sees beacons within ~1 s in any populated 2.4 GHz area,
      so this silence is a wedge, not a quiet channel. Detect-and-delegate:
      the daemon never touches the driver itself. Implements the "rx_silent"
      detector from `docs/IDEAS/iface-and-driver-health.md` Phase 1.
- Files: `src/main.c` (`on_health_timer`/`start_health_timer`).

### R6 — escalate self-heal beyond the modprobe cycle (SDIO backplane wedge) — SCRAPPED
- [ ] **Field-observed 2026-09-24 on the Zero 2 W (v0.6.16):** the BCM43430
      wedged at the SDIO bus level — `brcmf_sdio_dpc: sdio ctrlframe tx
      failed err=-84` → `failed backplane access over SDIO, halting
      operation` → `brcmf_attach failed`. `wlan0` disappeared entirely and
      the daemon logged `iface_open: <iface>: No such device` for ~5 hours.
      The existing self-heal (rfkill unblock + power_save off + `wificapc-prep`
      modprobe cycle, v0.6.2–0.6.4) **cannot** recover this: a `modprobe -r/`
      `modprobe brcmfmac` re-loads the module but the chip re-fails `attach`
      every time. Manually confirmed insufficient: module reload ✗; an SDIO
      host unbind/rebind power-cycle (`.../mmc-bcm2835/{unbind,bind}` on the
      `3f300000.mmcnr` host) re-enumerated the card but brcmfmac would not
      re-attach live ✗. **Only a reboot cleared it.**
- Fix: add an escalation ladder to the wedge detector (see
      [iface-and-driver-health.md](docs/IDEAS/iface-and-driver-health.md)).
      Detect the wedge signature — N consecutive `iface_open`/`SET_WIPHY`
      failures, or repeated `brcmf_attach failed` / `err=-84` in the kernel
      ring — and escalate in stages with cooldowns and a persisted attempt
      counter (survive across daemon restarts; never boot-loop):
      (1) modprobe cycle → (2) SDIO host unbind/rebind power-cycle →
      (3) `systemctl reboot` as last resort, rate-limited (e.g. ≤1/hour,
      backoff, give up after M reboots). The reboot rung is the agent's or a
      dedicated recovery unit's job, not the passive daemon — decide owner.
- Also seen: `wificapc-prep.service` was **not-found** on the running image
      (self-heal prep never installed there) — verify the stage3 install and
      that the unit is enabled. And the brcmfmac monitor invariant: `wlan0`
      (managed) must be **down** or the monitor vif can't tune the radio
      (`SET_WIPHY … -25/Object busy`, 0 RX) — document/enforce it.
- Files: `src/iface.c`, `src/chanhop.c`, `systemd/`, pwnagotc recovery unit,
      `docs/IDEAS/iface-and-driver-health.md`.

### R3 — dynamic capacity for the handshake pair table ✅ v0.7.0
- [x] `HS_MAX_PAIRS = 64` fixed array drops pairs in dense environments
      (`pair table full, dropping`). Grow dynamically (cap ~256) or use a
      slab/free-list. On 512 MB, a few hundred × ~1.4 KB pairs is fine.
- Files: `include/handshake.h`, `src/handshake.c`.

### R1 — persist recon table across daemon restarts ✅ v0.7.0
- [x] Dump `aps[]`/`stas[]` on shutdown, reload with a configurable
      max-age. Survives the brcmfmac respawn cycle so the daemon comes
      back aware of the airspace. (pwnagotc D5 handles the reconnect wave.)
- Files: `src/table.c`, new `src/state.c`.

### Q1 — OUI vendor lookup ✅ v0.6.17
- [x] Embedded the full IEEE MA-L registry (40,250 OUIs → 19,866 unique
      vendors, deduped string pool) as `src/oui_table.h`, generated by
      `tools/gen_oui.py` from IEEE `oui.csv`. `oui_lookup()` binary-searches
      it and returns NULL for locally-administered (randomized) / multicast
      MACs so we never show a bogus vendor for a private client address.
      `table_observe_ap/sta` fill `vendor`; `ap.new`/`sta.new` now carry a
      `vendor` field. Adds ~1.27 MB rodata to the binary (fine on the Zero 2;
      demand-paged) — bigger than the original ~40 KB estimate because it's
      full coverage, not a curated subset. Consumed by pwnagotc D1.
- Files: `src/oui.c`, `src/oui_table.h`, `include/oui.h`, `tools/gen_oui.py`,
      `src/table.c`, `src/main.c` (event emit), `test/test_oui.c`.

### Q7 — correct .22000 MESSAGEPAIR + replay-counter validation ✅ v0.7.1
- [x] Borrowed from hcxtools' hcxpcapngtool. Extract the EAPOL replay
      counter (`eapol_info.replay_counter`), track M1/M2/M3 counters per
      pair, and compute the WPA*02 messagepair byte properly: pair bits
      (M1+M2 / authorized M2+M3) plus **bit 7** ("replaycount not checked")
      when we can't confirm `m1_rc==m2_rc` / `m3_rc==m2_rc+1`, so hashcat
      nonce-error-corrects instead of trusting a stale (AP,STA)-window
      pairing. Drop zeroed-ANONCE hashes; surface `messagepair` in the
      pmkid/handshake events + protocol.md. Replay-counter unit test added.
- Files: `include/eapol.h`, `src/eapol.c`, `include/handshake.h`,
      `src/handshake.c`, `src/main.c`, `docs/protocol.md`, `test/test_eapol.c`.

### Q8 — scheduled OUI vendor-table refresh ✅ v0.7.1
- [x] Monthly (+ on-demand) GitHub Action re-downloads the IEEE MA-L
      registry, regenerates `src/oui_table.h` via `tools/gen_oui.py`,
      builds+tests, and opens a PR when it changed — keeps Q1's embedded
      vendor data fresh without hand-updates.
- Files: `.github/workflows/oui-refresh.yml`.

### W1 — every capture must have a wpa-sec-uploadable artifact — SCRAPPED
- Parked by decision: the PMKID-only route needs on-hardware validation
  (brcmfmac PMKIDs are `KDV:0 AKM not supported`). hcxtools' PMKID
  acceptance criteria are the reference if revived.
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

### Q2 — pcapng output instead of pcap — SCRAPPED
- [ ] Re-implement the writer as pcapng (SHB + IDB + EPB). Directly serves
      the wpa-sec goal: drops hcxpcapngtool's "limited dump file format
      detected" warning and is the format modern tooling expects; carries
      per-frame channel metadata cleanly. wpa-sec accepts both, so this is
      quality, not a fix. pwnagotc D2 handles the `.pcap`→`.pcapng`
      extension migration.
- Files: `src/pcap.c` → `src/pcapng.c`, `include/pcap.h`.

### S2 — PMKID-only attack mode ✅ v0.7.0
- [x] IPC flag / `assoc_pmkid` cmd: send auth+assoc once and return,
      never wait on the 4-way. Faster target cycling.
- Files: `src/main.c`, `src/inject.c`.

### R4 — WPA3 SAE handshake support — SCRAPPED
- [ ] Recognize SAE Commit/Confirm; pick a hashcat 22000 SAE mode. The
      current fixed 95-byte key-descriptor offsets in `eapol.c` assume
      classic WPA2 — SAE needs its own path.
- Files: `src/eapol.c` (or new `src/sae.c`), `src/handshake.c`.

### X1–X5 — polish
- [x] X1 `wificapc(8)` man page ✅ v0.7.0 · X2 `docs/protocol.md` (canonical
      command/event reference) ✅ v0.7.0 · X3 `--config` file parser ✅ v0.7.0
      · X4 subscribe/unsubscribe IPC (pwnagotc D6) ✅ v0.7.0 · X5
      `--log-format json` ✅ v0.7.0.

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
- **v0.6.12–v0.6.18** radiotap/recon/channel hardening (B1,B2,C1–C3,Q6),
  nl80211 session + snapshot perf (P1,P3), eager finalize (R5), smarter
  attack scheduling (P2), OUI vendor lookup (Q1), rx-silence watchdog (R7)
- **v0.8.5** `auto_start`/`auto_stop` IPC — runtime self-driving toggle
  (AU7; enables pwnagotc Agent mode to take channel control)
- **v0.8.4** `attack.assoc`/`attack.deauth` events — surface the --auto
  attack activity (one representative per channel round) for a UI client
- **v0.8.3** `set_attack` IPC — gate the `--auto` attack at runtime
  (capture/hop unaffected), so a client can run capture-only
- **v0.8.2** `--auto` reuses an existing monitor vif untouched (clean
  integration with an environment that preps it, e.g. the pi launcher)
- **v0.8.1** `--auto` standalone UX: periodic status line + `auto` config key (AU5)
- **v0.8.0** autonomous `--auto` mode: self-managed monitor vif (AU2),
  orchestrator (AU3), channel-coupled PMKID-first/deauth engine (AU4) —
  validated self-driving on hardware (hw-agnostic; brcmfmac reload stays the
  environment's job)
- **v0.7.2** autonomous-mode Phase 0 start: regdomain-aware channel
  auto-detection + `iface_channels` IPC (AU1); auto-mode design doc
- **v0.7.1** hcxtools-borrowed quality: correct `.22000` MESSAGEPAIR +
  replay-counter validation (Q7), scheduled OUI-table refresh CI (Q8)
- **v0.7.0** dynamic handshake-pair table (R3), recon-table persistence
  (R1), PMKID-only attack mode (S2), and the X-series polish: man page
  (X1), protocol.md (X2), `--config` file (X3), subscribe/unsubscribe IPC
  (X4), `--log-format json` (X5)

## How to use this file

- Pick the top unchecked item, branch, ship a PR, bump the version, tag.
- Mark `[x]` + `✅ vX.Y.Z` when it lands; move it to the changelog when a
  whole tier clears.
- Bump `pwnagotc/stage3/01-wificapc/01-run-chroot.sh` `WIFICAPC_TAG` on
  the next pwnagotc image so the change reaches the Pi.
