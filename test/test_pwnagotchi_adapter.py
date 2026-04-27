#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Verify pwnagotchi/wificapc.py against a live wificapc daemon.

Run from anywhere:
    python3 test/test_pwnagotchi_adapter.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

REPO_ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIFICAPC_BIN    = os.path.join(REPO_ROOT, "wificapc")
PWN_REPO        = os.environ.get("PWN_REPO", "/home/asif/projects/pwnagotchi")

assert os.path.exists(WIFICAPC_BIN),     f"build wificapc first: missing {WIFICAPC_BIN}"
assert os.path.isdir(PWN_REPO),          f"PWN_REPO not found: {PWN_REPO}"
sys.path.insert(0, PWN_REPO)

from pwnagotchi.wificapc import Client, _translate_event   # noqa


def assert_eq(got, want, label):
    if got == want:
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}\n  got : {got!r}\n  want: {want!r}", file=sys.stderr)
        sys.exit(1)


def test_event_translation():
    print("# event translation")
    cases = [
        # raw input                                                         expected tag
        ({"event": "ap.new",    "data": {"bssid": "x", "ssid": "y"}},      "wifi.ap.new"),
        ({"event": "ap.lost",   "data": {"bssid": "x"}},                   "wifi.ap.lost"),
        ({"event": "sta.new",   "data": {"mac":   "x"}},                   "wifi.client.new"),
        ({"event": "sta.lost",  "data": {"mac":   "x"}},                   "wifi.client.lost"),
        ({"event": "handshake.captured",
          "data": {"file": "/p.pcap", "ap_bssid": "a", "sta_mac": "b"}},   "wifi.client.handshake"),
        ({"event": "pmkid.captured",
          "data": {"file": "/p.pcap", "ap_bssid": "a", "sta_mac": "b"}},   "wifi.client.handshake"),
        ({"event": "iface.channel", "data": {"channel": 6}},               None),
        ({"event": "iface.mode",    "data": {"mode": "monitor"}},          None),
        ({"event": "handshake.done","data": {}},                           None),
    ]
    for raw, want in cases:
        out = _translate_event(json.dumps(raw))
        got = out["tag"] if out else None
        assert_eq(got, want, f"{raw['event']} → {want}")

    # Replies (have id) must be filtered out
    assert_eq(_translate_event('{"id":1,"ok":true,"data":{}}'), None, "reply filtered")
    assert_eq(_translate_event('not json'),                     None, "garbage filtered")

    # Key renames for the handshake path
    out = _translate_event(json.dumps({
        "event": "handshake.captured",
        "data": {"file": "/x.pcap", "ap_bssid": "AA:..", "sta_mac": "BB:..", "channel": 6, "rssi": -50},
    }))
    assert_eq(out["data"].get("ap"),      "AA:..", "handshake renames ap_bssid → ap")
    assert_eq(out["data"].get("station"), "BB:..", "handshake renames sta_mac  → station")
    assert_eq(out["data"].get("file"),    "/x.pcap", "handshake preserves file")


def test_against_live_daemon():
    print("# live daemon round-trip")
    sock = tempfile.mktemp(prefix="wificapc.adapter.", suffix=".sock")
    log  = tempfile.mktemp(prefix="wificapc.adapter.", suffix=".log")

    p = subprocess.Popen([WIFICAPC_BIN, "--socket", sock, "--foreground"],
                         stdout=open(log, "wb"), stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.05)
        assert os.path.exists(sock), f"socket never appeared (see {log})"

        c = Client(socket_path=sock)

        # Translated commands
        assert_eq(c.run("set wifi.rssi.min -200")["ok"],         True, "set wifi.rssi.min translates")
        assert_eq(c.run("set wifi.handshakes.aggregate false")["ok"], True, "aggregate is a no-op")
        assert_eq(c.run("set wifi.handshakes.file /tmp/wpa.test")["ok"], True, "handshakes.file → set_handshake_dir")
        assert_eq(c.run("events.ignore foo")["ok"],              True, "events.ignore is a no-op")
        assert_eq(c.run("wifi.clear")["ok"],                     True, "wifi.clear → clear")
        assert_eq(c.run("set wifi.interface nope0")["ok"],       False, "iface_set on bogus iface fails")

        # session() shape
        s = c.session()
        assert_eq(set(s.keys()) >= {"wifi", "modules", "started_at"}, True,
                  "session() returns bettercap-shape dict")
        assert_eq(isinstance(s["wifi"]["aps"], list),           True, "session.wifi.aps is a list")
        assert_eq(isinstance(s["modules"],     list),           True, "session.modules is a list")

        # session/wifi sub-extract
        sw = c.session("session/wifi")
        assert_eq("aps" in sw, True, "session('session/wifi') returns just the wifi block")

        # garbage commands silently no-op (legacy bettercap had many; we ignore them)
        assert_eq(c.run("module.never.exists arg1 arg2")["ok"], True, "unknown command is a no-op")
    finally:
        p.terminate()
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill()
        if os.path.exists(sock): os.unlink(sock)
        if os.path.exists(log):  os.unlink(log)


if __name__ == "__main__":
    test_event_translation()
    test_against_live_daemon()
    print("\nall good")
