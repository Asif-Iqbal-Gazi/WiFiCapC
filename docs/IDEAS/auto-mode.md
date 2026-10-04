<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# WiFiCapC autonomous mode (`--auto`)

Goal: a **self-sufficient** capture mode built into the daemon. `wificapc
--auto` (plus an interface, or auto-picked) brings the radio up, figures out
which channels it may use, hops intelligently while sniffing and attacking to
**maximise handshakes/PMKIDs**, and writes the artifacts — with no external
driver. It must be good enough to stand alone as a best-in-class autonomous
WPA capture tool, while still integrating cleanly with the pwnagotc agent.

Technique is informed by hcxdumptool/hcxtools: clientless PMKID elicitation,
targeted deauth only when it helps, stop once a usable handshake is held, and
inject only on the tuned channel.

## Principle: control inversion

| Mode | Who drives | Client role |
|---|---|---|
| `wificapc` (default) | the client (pwnagotc) sends `iface_set`→`monitor_on`→`recon_start`→`hop_start`→`assoc`/`deauth` | driver (today's behaviour, unchanged) |
| `wificapc --auto` | the daemon drives itself | **observer** — subscribes, displays, uploads |

`stats.auto` tells a client which mode is active. `auto_start` / `auto_stop`
IPC toggle it at runtime. The daemon **never needs** a client; a client only
enriches (UI + internet upload). Side-effect: because the daemon self-drives,
capture no longer depends on the agent's auto-vs-manual mode.

## Responsibility split

- **wificapc (engine):** all RF — channel detection, monitor-vif setup,
  hopping, recon, attack, capture, `.pcap`/`.22000` writing + Q7 quality,
  persistence (R1), self-heal (R7). Emits events + status. Fully autonomous.
- **pwnagotc (face):** UI/mood, internet detection + wpa-sec upload,
  pwnagotchi personality, image build. A thin consumer in auto mode.

The Unix socket is the only seam.

## Confirmed decisions

1. **"Done" per AP = first usable handshake** (PMKID *or* a Q7-validated
   4-way). Config override to keep chasing a 4-way after a PMKID.
2. **Balanced deauth default**, with a stealth↔max-capture dial in config.
3. **`--auto` fully owns the monitor vif** (retires the pwnagotc launcher's
   vif creation — old TODO-A3), respecting the brcmfmac invariant: the
   managed netdev must be **down**; never flip it to monitor live (`-25`).
4. **Channel detection is generic** (2.4/5/6 GHz from the regdomain), so the
   tool shines on radios better than the Zero 2's 2.4-only brcmfmac.
5. **Same binary**, `--auto` flag (plus `auto_start`/`auto_stop` IPC).

## The capture-maximising engine

The core change vs today's P2 attack timer: **couple attack to channel
dwell** — you can only inject reliably on the channel you're tuned to. Each
dwell is a round:

1. **Tune** to channel N (from the auto-detected set).
2. **Recon** passively (beacons, data → AP/STA table, as today).
3. **Attack ch-N APs** that aren't "done":
   - **PMKID first:** directed association → AP's M1 PMKID. Clientless,
     stealthy, fast — the primary move.
   - **EAPOL as needed:** only if PMKID hasn't landed *and* the AP has an
     associated client, send a measured (targeted) deauth, then **listen**
     for the reconnect 4-way. No continuous hammering.
   - Skip "done" APs (P2 `captured`), honour per-target cooldown + attempt
     caps (P2), cap frames per round.
4. **Adaptive dwell:** linger where there are targets/activity; skim empty
   channels. (Builds on chanhop's existing per-channel backoff.)
5. **Hop.**

"Maximise" = clientless PMKID on everything + opportunistic 4-way where a
client exists + never wasting airtime on captured APs or off-channel injects.

## Phases / TODO

- **Phase 0 — foundation**
  - `iface_supported_channels()` via `NL80211_CMD_GET_WIPHY` (regdomain +
    DISABLED/NO-IR aware), on the P1 session.
  - Self-managed monitor vif (create/bring-up in the daemon, brcmfmac-safe).
- **Phase 1 — engine**
  - `--auto` flag + `auto_start`/`auto_stop` IPC + `stats.auto`.
  - Orchestrator (`src/auto.c`) sequencing detect→monitor→recon→hop→attack.
  - Channel-coupled per-dwell attack rounds; PMKID-first/deauth-as-needed;
    first-usable stop; adaptive dwell.
- **Phase 2 — standalone UX**
  - Periodic status summary (human + JSON via X5).
  - Auto-mode config knobs via `--config` (X3): channels=auto|list, attack
    mode, deauth dial, dwell, output dir, whitelist/filters.
- **Phase 3 — pwnagotc as consumer**
  - `auto.status` event; agent detects `stats.auto`, stops orchestrating,
    subscribes → displays (channel, counts, mood) → uploads when online.

## Hardware note — brcmfmac/nexmon vif creation (measured)

wificapc does **not** reload any driver — it is hardware-agnostic and only
speaks nl80211. On a normal monitor-capable adapter, `NEW_INTERFACE type
monitor` succeeds directly and `--auto` is fully standalone.

The Pi's BCM43430/nexmon firmware is the exception. Its monitor vif is
created (per the DKMS driver's `brcmf_mon_add_vif`) by asking the *firmware*
to add an interface (`brcmf_cfg80211_request_ap_if` → wait for
`BRCMF_E_IF_ADD`). Measured: that firmware op returns `-EOPNOTSUPP`/`-EBUSY`
until the module is freshly reloaded — bare `iw ... interface add ... type
monitor` fails the same way without a reload (settle time doesn't help, a
clean `iw del` doesn't help). That is why the image's launcher runs
`reload_brcm` on every start.

Decision: the reload stays the **environment's** job (the image launcher /
prep service / R7 self-heal → systemd restart → launcher reload), never the
daemon's. `--auto` therefore **reuses a monitor vif if one already exists**
(the prepped case) and only creates one otherwise. On the Pi, deploy `--auto`
behind the same prep the launcher already does; on a laptop it just works.

## Why it's robust for unattended standalone runs

R7 rx-silence watchdog (recover a wedged radio) + R1 recon persistence
(come back aware after a respawn) already make days-long unattended
operation viable — a direct selling point for the standalone tool.
