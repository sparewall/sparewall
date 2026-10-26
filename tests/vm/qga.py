#!/usr/bin/python3
# Ask the node's QEMU guest agent, through the socket QEMU serves its
# channel on, and print each reply as a line of JSON.
#
#   qga.py SOCKET COMMAND[:ARGS-JSON]...
import json, random, socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(30)
s.connect(sys.argv[1])
f = s.makefile("rwb", buffering=0)
def send(m):
    f.write(json.dumps(m).encode() + b"\n")
def reply():
    while True:
        line = f.readline()
        if not line:
            sys.exit("qga.py: the agent closed the connection")
        try:
            return json.loads(line)
        except ValueError:
            continue
# guest-sync first: the channel may still hold an earlier client's reply.
n = random.randrange(1 << 31)
send({"execute": "guest-sync", "arguments": {"id": n}})
while reply().get("return") != n:
    pass
for a in sys.argv[2:]:
    cmd, _, args = a.partition(":")
    send({"execute": cmd, **({"arguments": json.loads(args)} if args else {})})
    print(json.dumps(reply()), flush=True)
