#!/usr/bin/python3
# A DynDNS2 update server for the VM suites (#316).
#
#   ddns-stub.py PORT LOG    on 127.0.0.1:PORT (10.0.2.2:PORT from the
#                            VMs): each update's path and query, a line
#                            in LOG, answered "good <myip>"
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

port, log = int(sys.argv[1]), sys.argv[2]


class Update(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlsplit(self.path).query)
        ok = self.headers.get("Authorization", "").startswith("Basic ")
        with open(log, "a") as f:
            f.write(self.path + ("" if ok else " (no credentials)") + "\n")
        body = ("good " + q.get("myip", [""])[0] if ok else "badauth").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", port), Update).serve_forever()
