#!/usr/bin/env python3
"""A DNS-over-TLS forwarder for the VM tests (#356).

    dot-stub.py CERT KEY PORT ADDRESS

Listens on 127.0.0.1:PORT (the VMs' 10.0.2.2) with CERT and KEY, and
answers every A query with ADDRESS, every other query with no records,
so a node can resolve through it, or fail to when it doesn't trust it.
Each query's name is printed, for the test's log.
"""
import socket
import ssl
import struct
import sys
import threading

cert, key, port, address = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]


def answer(q: bytes) -> bytes:
    # The question's end: its name's labels, then type and class.
    i = 12
    while q[i]:
        i += 1 + q[i]
    qtype = struct.unpack("!H", q[i + 1 : i + 3])[0]
    question = q[12 : i + 5]
    name = []
    j = 12
    while q[j]:
        name.append(q[j + 1 : j + 1 + q[j]].decode(errors="replace"))
        j += 1 + q[j]
    print(".".join(name) + ".", qtype, flush=True)
    # The ID; QR, RD and RA, NOERROR; one question, one answer or none.
    head = q[:2] + bytes([0x81 | (q[2] & 0x01), 0x80])
    if qtype == 1:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
        return head + struct.pack("!HHHH", 1, 1, 0, 0) + question + rr
    return head + struct.pack("!HHHH", 1, 0, 0, 0) + question


def serve(conn: ssl.SSLSocket) -> None:
    with conn:
        try:
            while True:
                n = conn.recv(2)
                if len(n) < 2:
                    return
                want = struct.unpack("!H", n)[0]
                q = b""
                while len(q) < want:
                    chunk = conn.recv(want - len(q))
                    if not chunk:
                        return
                    q += chunk
                r = answer(q)
                conn.sendall(struct.pack("!H", len(r)) + r)
        except (OSError, IndexError, struct.error):
            return


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(16)
while True:
    c, _ = s.accept()
    try:
        t = ctx.wrap_socket(c, server_side=True)
    except (ssl.SSLError, OSError):
        c.close()
        continue
    threading.Thread(target=serve, args=(t,), daemon=True).start()
