# Idea: Ap-less / rogue-AP M2 client attack ("A")

Status: **design, not implemented.** Spawns TODO item P6-A. Daemon-side
(WiFiCapC); the agent needs no changes (captures flow as `handshake.done`).
Derived from a source-level study of hcxdumptool 7.1.2 (`process80211proberequest`,
`send_80211_probereresponse_directed`, `send_80211_eapol_m1_wpa2`,
`process80211eapol_m2`).

## TL;DR

Today we only attack from the **AP side** — directed assoc to elicit a PMKID,
and deauth of connected clients to force a 4-way. We never attack **clients
directly**. hcxdumptool's biggest edge is the *ap-less* attack: it impersonates
whatever network a client is **probing** for, completes a fake association, and
sends its own EAPOL **M1** so the client replies with **M2** — crackable
material from a device whose real AP isn't even in range (a phone probing for
"HomeWiFi" on the train). This doc specs that for WiFiCapC.

## What we capture and why it's crackable

In a normal 4-way, M2 carries the client's SNONCE + a MIC computed with the PTK:

```
PTK  = PRF(PMK, ANONCE ‖ SNONCE ‖ AP_MAC ‖ CLIENT_MAC)
MIC  = HMAC(KCK, EAPOL-M2-body)        PMK = PBKDF2(passphrase, ESSID, …)
```

If **we** are the AP, we *chose* the ANONCE (we sent it in M1), we know both
MACs and the ESSID (the client told us in its probe), and the client hands us
SNONCE + MIC in M2. That's a complete hashcat `WPA*02` line — **message-pair
type `00` (M1+M2 "challenge")**, same as any M1M2 capture we already emit. No
real AP, no deauth, no connected client required.

## The flow (what the daemon must do)

Per client, on the **current channel** (we respond with the NIC already tuned):

1. **Probe request RX** → the client lists an ESSID it wants. We currently parse
   probe requests only for STA discovery; now we also **respond**.
2. **Directed probe response TX** — impersonate that exact ESSID from a
   fabricated rogue-AP BSSID, advertising WPA2-PSK (reuse `RSN_IE_WPA2_PSK`
   from `inject.c`). (Broadcast/wildcard probes → optionally answer from an
   ESSID pool; **phase 2**, skip at first.)
3. Client **authentication request** → we send **authentication response**
   (open system, success).
4. Client **association request** → we send **association response** (success),
   then immediately inject **EAPOL M1** with a known ANONCE.
5. Client replies **EAPOL M2** → we capture it, pair it with our M1's ANONCE,
   write the `.22000` + per-pair pcap, emit `handshake.done`.

hcxdumptool fabricates rogue BSSIDs by incrementing a NIC counter under a fixed
OUI (`nicaprg++`); we do the same so each impersonated ESSID gets a stable MAC
within a session.

## Where it lands in our codebase

| Piece | New work |
|---|---|
| RX dispatch | handle `PROBE_REQ`, `AUTH`, `ASSOC_REQ`, `REASSOC_REQ` subtypes we currently ignore for TX purposes (`dot11.c` already classifies; wire responders in `main.c`/a new `apless.c`) |
| TX frames | `inject_probe_response(essid, rogue_bssid)`, `inject_auth_response`, `inject_assoc_response`, `inject_eapol_m1(rogue_bssid, client, anonce)` — all alongside the existing `inject.c` builders |
| Rogue-AP state | a small table keyed by (rogue_bssid, client): ESSID, our ANONCE, state (PROBED→AUTHED→ASSOCED→M2), timestamps, attempt cap/cooldown — mirror the `attack_count`/`last_attack` discipline we already use |
| **Capture/assembly** | the hard part — the handshake tracker (`handshake.c`/`eapol.c`) assembles from *sniffed* M1(AP)+M2(client). Here **M1 is our injected frame**, so we must register our ANONCE for the pair at inject time so the client's M2 completes it. New entry point like `handshake_note_injected_m1(rogue_bssid, client, anonce, essid)` |
| Beacon for the pcap | hcxpcapngtool wants the SSID+RSN; we already prepend a cached beacon per pair (Q-series). For rogue pairs we synthesize one from our probe-response params |
| Gate | a config flag + IPC `set_apless {enabled}` (like `set_pmkid_only`), **default OFF** (see Risks) |

## Design decisions / open questions

1. **Default on or off?** hcxdumptool defaults it on. We should default **OFF**
   and gate behind `set_apless` — it's materially louder/more detectable than
   our current AP-side attacks (we actively impersonate networks and solicit
   clients). Engine mode can opt in; the agent exposes it as a toggle later.
2. **Phase 1 scope:** directed probe requests only (answer a named ESSID). Skip
   broadcast-probe ESSID-pool answering and active beaconing (phase 2) — they're
   the loudest and least targeted.
3. **MFP:** an MFP-required client may refuse our unprotected M1; detect and
   skip (reuse the `mfp_*` parsing from B).
4. **De-dup with the AP-side attack:** if we already have this ESSID's real AP
   captured, is the ap-less pair redundant? No — different PMK only if different
   passphrase; keep both, dedup by (bssid, client) as today.
5. **Rate/air budget:** reuse `ATTACK_PER_TICK`-style caps; a burst of probing
   clients shouldn't flood TX. Per-client cooldown.
6. **PTK/MIC validation:** we don't verify the MIC (we can't without the
   passphrase) — same as now; hashcat does nonce-error correction. Set the
   message-pair byte's bit 0x80 if we can't confirm the replay counter.

## Rough effort / phasing

- **Phase 1 (this item):** directed-probe rogue-AP → M1 → M2 capture, gated off
  by default. New `src/apless.c` (~300–400 LoC) + `inject.c` responders +
  `handshake_note_injected_m1`. Estimate: a focused multi-day build with ASAN +
  a frame-level unit test (craft a probe→auth→assoc→M2 exchange, assert a
  `.22000` WPA*02 line is produced).
- **Phase 2 (later):** broadcast-probe ESSID pool, `active_beacon`/`flood_beacon`
  equivalents, an ESSID allow/deny list.

## Risks

- **Detectability / legality:** impersonating SSIDs + soliciting clients is a
  legitimate authorized-pentest technique (hcxdumptool's default) but more
  active than passive capture. Gate it, document it, keep it opt-in.
- **Driver TX load on brcmfmac:** more injected frames per second; watch for the
  known nexmon TX-queue sensitivity (we already pace deauth). Keep per-tick caps.
- **Capture-pipeline correctness:** the injected-M1 registration is the subtle
  part — get the ANONCE/MAC bookkeeping wrong and we emit junk `.22000` lines
  (the exact class of bug the per-pair gating in v0.6.5–0.6.8 fixed). ASAN +
  a dedicated unit test before shipping.
