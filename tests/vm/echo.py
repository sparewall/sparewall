#!/usr/bin/python3
# Echo servers and clients for the VM suites.
#
#   echo.py server            TCP echo on 7000, a thread per connection
#   echo.py udpserver         UDP echo on 7001
#   echo.py client HOST [T]   a line every 0.5 s on one connection,
#                             printing the count of echoes ("broken" if
#                             one comes back wrong; T is the read timeout)
#   echo.py udpclient HOST    a datagram every 0.3 s, logging each reply
import socket, sys, threading, time
def serve(c):
    f = c.makefile("rwb", buffering=0)
    for line in f:
        f.write(line)
if sys.argv[1] == "server":
    # One thread per connection: the LAN and VPN clients run at once.
    s = socket.create_server(("0.0.0.0", 7000))
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
elif sys.argv[1] == "udpserver":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 7001))
    while True:
        d, a = s.recvfrom(64)
        s.sendto(d, a)
elif sys.argv[1] == "udpclient":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    n = 0
    while True:
        n += 1
        s.sendto(str(n).encode(), (sys.argv[2], 7001))
        try:
            s.recvfrom(64)
            print(f"[{time.time():.6f}] reply {n}", flush=True)
        except socket.timeout:
            print(f"[{time.time():.6f}] lost {n}", flush=True)
        time.sleep(0.3)
else:
    c = socket.create_connection((sys.argv[2], 7000), timeout=5)
    c.settimeout(float(sys.argv[3]) if len(sys.argv) > 3 else 30)
    f = c.makefile("rwb", buffering=0)
    n = 0
    while True:
        f.write(b"ping\n")
        if f.readline() != b"ping\n":
            print("broken", flush=True)
            sys.exit(1)
        n += 1
        print(n, flush=True)
        time.sleep(0.5)
