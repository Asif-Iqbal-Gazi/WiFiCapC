# Idea: Iface management & brcmfmac driver-health architecture

Status: **discussion**, not implemented. Spawn TODOs from sections of
this document into `TODO.md` when a concrete piece becomes actionable.
Cross-cuts WiFiCapC and pwnagotchi.

## TL;DR

- `nl80211_cmd_set_interface(IFTYPE_MONITOR)` on `wlan0` does not work
  reliably on brcmfmac. Channel sets after the switch silently fail,
  TX queues misbehave, Nexmon's monitor patches assume a fresh
  monitor-type iface. The empirically known-good path is `iw phy phyN
  interface add wlan0mon type monitor` — i.e. **add a sibling**, do not
  switch in place.
- Today the bring-up sequence lives in `wificapc-launcher` + `pwnlib`
  on the pwnagotchi image. The daemon's own `iface_set_mode(MONITOR)`
  short-circuits because by the time the daemon sees the iface, it's
  already in monitor mode.
- brcmfmac additionally wedges mid-session — Set Channel starts
  returning errors, or worse, succeeds at the netlink layer but the
  radio never actually retunes (silent stall).
- We want clean separation: **the daemon detects, an external actor
  recovers**. Driver loading should never live inside the capture
  daemon.

## Problem 1 — in-place mode switch is broken on brcmfmac

What looks like the right thing in nl80211:

```
ip link set wlan0 down
iw dev wlan0 set type monitor    # NL80211_CMD_SET_INTERFACE iftype=MONITOR
ip link set wlan0 up
iw dev wlan0 set channel 6
```

What actually happens on Pi Zero 2 W with brcmfmac + Nexmon firmware:

- The mode change succeeds at the netlink layer. `iw dev wlan0 info`
  reports `type monitor`.
- Channel sets after the switch may succeed but the radio doesn't
  retune (frames keep arriving with the previous channel's freq).
- TX (frame injection) often fails silently — `send()` returns the
  expected byte count, no frame goes out the air.
- The Nexmon firmware patches that enable monitor + injection are
  designed against a fresh monitor-type iface created by
  `cfg80211_cfg80211_add_iface`, not against an iface that
  transitioned from `IFTYPE_STATION`. State machinery upstream of
  the firmware is in an indeterminate place.

The known-good sequence on brcmfmac (currently in `pwnlib`):

```
modprobe -r brcmfmac && modprobe brcmfmac      # clean driver state
sleep 2                                        # udev re-creates wlan0
ip link set wlan0 up
iw phy "$(iw phy | head -1 | cut -d" " -f2)" \
    interface add wlan0mon type monitor        # SIBLING iface
ip link set wlan0 down                         # stop kernel from
                                               # touching the original
ip link set wlan0mon up
rfkill unblock all
iw dev wlan0mon set power_save off
```

This is the contract the rest of the system has to live with **for
brcmfmac**. On other chipsets (ath9k_htc, rtl8812au with the
realtek-rtl88xxau-dkms stack, mt76 USB) the in-place switch works
fine; the daemon's `iface_set_mode` is correct for them.

## Problem 2 — brcmfmac wedges during a session

Modes of failure observed in journalctl:

1. **iface_set_channel returns an error.** nl80211 reply has rc < 0,
   often `-EINVAL` or `-EOPNOTSUPP`. Currently `chanhop_on_timer` logs
   a warning and tries the same channel on the next tick.
2. **iface_set_channel silently does nothing.** Reply rc == 0,
   `i->channel` updates, but radiotap headers on subsequent frames
   show the previous freq. The radio is stuck.
3. **brcmf_cfg80211_add_iface: iface validation failed: err=-95**
   (kernel ring buffer). `fix_services.py`'s pattern1 already
   matches this.
4. **Allmulti / multicast list errors** (pattern7). Cosmetic in
   isolation but often co-occurs with deeper firmware unhappiness.
5. **AF_PACKET recv stalls** while no obvious nl80211 error fires. The
   socket never reports readable, frames just stop. The capture
   loop's `ipc_stop()` on hard recv error covers ENODEV/ENETDOWN but
   not silent stalls.

## Current state

```
   pwnagotchi image                wificapc daemon
   ────────────────                ───────────────
   wificapc-launcher.sh            iface_open()       ← finds iface
     reload_brcm                                        already monitor
     start_monitor_interface       iface_set_mode()   ← short-circuits
       iw phy ... interface add                         (mode == current)
       ifconfig wlan0 down                            iface_set_channel()
       ifconfig wlan0mon up                             ← may fail or
       rfkill unblock all                                 silently stall
       iw set power_save off
     exec wificapc                 capture_start()
                                     AF_PACKET RX

   fix_services.py (pwnagotchi plugin)
     on_epoch:
       grep journalctl for known wedge patterns
       if matched: monstart / restart wificapc
```

Pain points with this layout:

- The bring-up logic lives only in shell, only in the pwnagotchi
  image. A standalone WiFiCapC user is on their own. If the launcher
  is updated, the daemon-side fallback in `iface_set_mode` is stale.
- `fix_services.py` polls journalctl every epoch (~60 s). Slow. Also
  conflates agent state with driver state.
- The daemon has no way to ask "am I healthy?" — it just keeps
  running. A silent-stall wedge is invisible until someone notices
  the AP/STA table going stale.
- The chain from "channel set silently failed" to "brcmfmac
  reloaded" goes through 3 components (daemon → log message →
  fix_services match → systemctl restart), each of which can break
  independently.

## Proposed architecture

Cleanly separate **detect** from **act**. The daemon detects,
something else acts.

```
   ┌─────────────────────────────────────────────────────┐
   │ wificapc daemon                                     │
   │                                                     │
   │   chanhop ──┐                                       │
   │             │ tracks per-channel set rc + frame     │
   │             │ rate; emits iface.unhealthy when      │
   │             │ a channel hits N consecutive failures │
   │             │ or stays silent for M ticks while     │
   │             │ other channels show traffic           │
   │             ▼                                       │
   │   iface.unhealthy ──┐                               │
   │   (IPC event)       │                               │
   └─────────────────────┼───────────────────────────────┘
                         │
                         ▼
   ┌─────────────────────────────────────────────────────┐
   │ wificapc-watchdog (new, small, single purpose)      │
   │                                                     │
   │   subscribes to iface.unhealthy via Unix socket     │
   │   on event:                                         │
   │     systemctl restart wificapc.service              │
   │   wificapc-prep then cycles brcmfmac;               │
   │   launcher rebuilds wlan0mon;                       │
   │   the daemon comes back up clean.                   │
   └─────────────────────────────────────────────────────┘
```

Why a separate watchdog rather than wiring directly into pwnagotchi:

- Pwnagotchi might not be running (testing, headless capture node).
- Pwnagotchi is Python in a venv with no special privs; calling
  `systemctl restart` from there works but adds a layer.
- A 50-line bash daemon (or systemd `Type=oneshot` triggered by an
  IPC event listener) is cheaper to reason about.

### Detection signals

Concrete metrics the daemon can emit:

1. **`channel_set_failures{channel}`** — counter, reset on success.
   Once it hits N (e.g. 5) consecutive, that channel is suspect.
2. **`channel_silent_ticks{channel}`** — number of consecutive
   chanhop ticks where we sat on a channel and got 0 frames, *while*
   at least one other channel in the same rotation was non-silent.
3. **`mismatch_radiotap_freq`** — frames arriving with `freq != current_channel`'s freq for more than a second. This is the **silent stall** detector — radio stuck on the previous channel.
4. **`recv_silence_seconds`** — how long since the AF_PACKET socket
   delivered any frame. If hopping is supposedly running and this
   exceeds a threshold (e.g. 30 s), driver is wedged.

The daemon emits `iface.unhealthy {reason: "...", evidence: {...}}`
when any of these crosses threshold. It does not act on its own —
it just reports.

### Recovery actor (`wificapc-watchdog`)

Minimal first cut:

```bash
#!/usr/bin/env bash
# /usr/bin/wificapc-watchdog
exec nc -U /run/wificapc.sock <<<'{"id":1,"cmd":"ping"}' >/dev/null
exec socat - UNIX-CONNECT:/run/wificapc.sock |
  jq --unbuffered -r 'select(.event=="iface.unhealthy") | .data.reason' |
  while read -r reason; do
    logger -t wificapc-watchdog "iface unhealthy: $reason"
    systemctl restart wificapc.service
    sleep 30   # backoff so we don't loop
  done
```

Plus a systemd unit `wificapc-watchdog.service` with `Wants=` /
`After=` `wificapc.service` and `Restart=always`.

Future: rate-limit (don't restart more than once per 5 minutes), keep
a count of restarts in a status file, escalate to `reboot` after K
restarts in M minutes (catastrophic firmware corruption).

### Launcher contract

Keep `wificapc-launcher` + `pwnlib::start_monitor_interface` as the
canonical brcmfmac bring-up path on the pwnagotchi image. Document
this explicitly:

- WiFiCapC's `iface_set_mode` is the right primitive for **non-brcmfmac**
  drivers and is what a standalone deployment (USB Wi-Fi adapter)
  uses.
- For brcmfmac, the launcher must run before the daemon. The
  `defaults.toml` `iface = "wlan0mon"` is correct and intentional.

Things to retire from the launcher (now redundant with daemon-side
work since v0.6.4) but harmless to keep as belt-and-braces:

- `rfkill unblock all` (daemon does soft-unblock per link_up)
- `iw dev wlan0mon set power_save off` (daemon does
  `NL80211_CMD_SET_POWER_SAVE PS_DISABLED` after monitor mode)

Things that **must** stay in the launcher (no daemon equivalent):

- `iw phy phy0 interface add wlan0mon type monitor`
- The whole modprobe -r/+ cycle (CAP_SYS_MODULE; not the daemon's
  business)

## Phased implementation plan

Each phase ships independently, no flag-day:

### Phase 1 — daemon-side detection

1. WiFiCapC: per-channel failure counter in chanhop. Emit
   `iface.unhealthy {reason: "channel_set_failures", channel: N}`
   after 5 consecutive failures on the same channel.
2. WiFiCapC: AF_PACKET silence watchdog. If hop is running and we've
   had 0 frames for `silence_threshold_sec` (configurable, default
   30 s), emit `iface.unhealthy {reason: "rx_silent"}`.
3. WiFiCapC: radiotap freq vs current channel sanity check. Emit
   `iface.unhealthy {reason: "channel_stuck"}` when mismatched
   frames pile up.

These are small, isolated changes in `chanhop.c` + `capture.c`. No
new dependencies. Pwnagotchi already ignores unknown events so
shipping these without an actor is safe.

### Phase 2 — recovery actor

4. WiFiCapC: ship a minimal `wificapc-watchdog` script + systemd
   unit. Subscribes to the IPC, restarts `wificapc.service` on
   `iface.unhealthy`. Same install pattern as `wificapc-prep`
   (opt-in via `make install-systemd`).
5. WiFiCapC: rate-limit, restart counter, escalation to reboot after
   K within M.

### Phase 3 — pwnagotchi integration cleanup

6. Pwnagotchi: `fix_services.py` simplifies. Drop the journalctl
   regex polling for the patterns Phase 1 covers; subscribe to the
   IPC event instead (or trust the watchdog and remove the plugin
   entirely). Keep the "wlan0mon up but down" sanity check as a
   secondary safety net.
7. Pwnagotchi: optional UI surface for "iface unhealthy" (banner /
   face change) so the operator sees that recovery is happening.

### Phase 4 (long-term, optional) — drop wlan0mon

8. When brcmfmac stabilizes (or we move to a different chipset by
   default), revisit the in-place type switch. If it works:
     - drop `start_monitor_interface` from the launcher
     - flip `defaults.toml` `iface = "wlan0"`
     - daemon does the right thing on its own, launcher only runs
       `modprobe` + `rfkill unblock`
9. Until then, defaults stay as they are.

## Open questions

- **Should `iface.unhealthy` be a single event with a `reason` field,
  or multiple events (`iface.channel_stuck`, `iface.rx_silent`,
  `iface.channel_failures`)?** Single with `reason` keeps the
  protocol surface small; multiple makes per-cause subscribe filters
  trivial. Lean toward single for now.
- **Watchdog: bash + socat, or extend the daemon to fork a child on
  unhealthy?** Bash + socat is simpler and follows the
  separation-of-concerns argument. Extending the daemon means
  daemon needs CAP_SYS_MODULE which we explicitly want to avoid.
  Bash wins.
- **What's the right silence threshold?** Even on a quiet channel
  with no APs, a healthy radio shouldn't be silent for 30s — beacons
  are on the air. But on rural channels (12, 13 in regions where
  they're disused) we might see real silence. Maybe scale by recent
  per-channel frame rate.
- **How does the watchdog know recovery worked?** After
  `systemctl restart wificapc.service`, it should re-probe (open the
  socket, send `ping`) and only mark recovery done on a successful
  reply.
- **Handling truly unrecoverable hardware?** After K restarts in M
  minutes the watchdog should escalate. Reboot? Power-cycle the USB
  bus? Persist a flag and refuse to bring wificapc up until the
  operator clears it? Probably reboot, since on Pi Zero 2 W the
  brcmfmac is on-SoC and you can't power-cycle it independently.

## Why we're not doing this today

- Phase 1 is medium-effort and would benefit from a real wedge to
  debug the detection thresholds. Without the failure case in front
  of us, the silence-threshold tuning is guesswork.
- Phase 2 builds on Phase 1 — premature without it.
- Phase 3 simplifies pwnagotchi-side, low priority until Phase 1+2
  ship.
- The current launcher dance, plus the systemd `Restart=always`,
  plus `fix_services.py`, plus the `wificapc-prep` brcmfmac cycle,
  recovers from the failure modes we've actually observed in the
  field. It's a Rube Goldberg machine but it works.

When we hit a wedge that the current chain doesn't recover from,
Phase 1 jumps to the top of the list. Until then this idea sits.
