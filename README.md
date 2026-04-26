# WiFiCapC

A native C daemon for 802.11 monitor-mode capture, channel hopping, and
handshake/PMKID acquisition. Designed as a drop-in replacement for the
bettercap surface that pwnagotchi uses.

## Status

Pre-alpha. Tracking milestones in `docs/MILESTONES.md` (TODO).

| Milestone | What works |
|-----------|------------|
| M1 | repo skeleton, IPC socket, `ping` cmd |
| M2 | (todo) monitor mode + channel hop |
| M3 | (todo) AP/STA passive recon |
| M4 | (todo) handshake/PMKID capture, hcxpcapngtool integration |
| M5 | (todo) deauth/assoc injection |
| M6 | (todo) pwnagotchi `wificapc.py` adapter |
| M7 | (todo) aarch64 cross-compile, Pi Zero 2 W image stage |

## Architecture

```
            ┌──────────────────────────────┐
  802.11 ──>│ wificapc                     │
  monitor   │   AF_PACKET RX               │
            │   radiotap parse             │
            │   AP/STA in-memory table     │
            │   channel-hop scheduler      │
            │   pcapng writer              │
            │   handshake / PMKID detector │──> .pcapng + .22000
            └────────────┬─────────────────┘     (via hcxpcapngtool)
                         │ Unix socket
                         │ line-delimited JSON
                         ▼
                    pwnagotchi
                    (or any client)
```

## Protocol (line-delimited JSON over a Unix socket)

Request:
```json
{"id": 1, "cmd": "ping"}
```
Reply:
```json
{"id": 1, "ok": true, "data": {"pong": true}}
```
Event (server-initiated, no id):
```json
{"event": "handshake.captured", "data": {"file": "...", "ap": "...", "sta": "..."}}
```

## Build

```sh
make
```

## Run

```sh
./wificapc --socket /tmp/wificapc.sock --foreground
```

In another shell:
```sh
echo '{"id":1,"cmd":"ping"}' | nc -U /tmp/wificapc.sock
```

## License

GPL-3.0-or-later. See `LICENSE`.
