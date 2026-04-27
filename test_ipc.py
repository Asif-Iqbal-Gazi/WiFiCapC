import socket
import json
import time

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("/tmp/wificapc.sock")
    print("Connected to WiFiCapC daemon")
except Exception as e:
    print(f"Error connecting to socket: {e}")
    print("Did you start WiFiCapC? (sudo ./wificapc)")
    exit(1)

s.setblocking(False)

def send(cmd, args=None):
    req = {"id": int(time.time() * 1000), "cmd": cmd}
    if args: req["args"] = args
    s.sendall((json.dumps(req) + "\n").encode())
    print(f"-> {req}")

# Send sequence
send("iface_set", {"name": "wlx00c0cab79cb7"})
time.sleep(1)
send("monitor_on")
time.sleep(1)
send("recon_start")

print("Waiting for events (15 seconds)...")
print("You should see AP/STA discovery and auto-attacks (inject.assoc/inject.deauth)")
for _ in range(15):
    time.sleep(1)
    try:
        data = s.recv(4096)
        if data:
            for line in data.decode().splitlines():
                print(f"<- {line}")
    except BlockingIOError:
        pass

send("list_aps")
time.sleep(1)
try:
    data = s.recv(4096)
    if data:
        for line in data.decode().splitlines():
            print(f"<- {line}")
except:
    pass

send("recon_stop")
