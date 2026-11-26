#!/usr/bin/env python3
"""Transparent HTTP logger in front of testnet that records each request's User-Agent (checks net.ua → core).
   python3 qa/scenarios/review-logic-core/ua_logger.py LISTEN_PORT UPSTREAM_PORT LOGFILE"""
import http.server, sys, urllib.request, urllib.error
LP, UP, LOG = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]


class H(http.server.BaseHTTPRequestHandler):
    def _go(self):
        with open(LOG, "a") as f:
            f.write("%s %s\t%s\n" % (self.command, self.path, self.headers.get("User-Agent")))
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (UP, self.path), data=body, method=self.command,
                                     headers={k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")})
        try:
            r = urllib.request.urlopen(req, timeout=60); code, hdr, data = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            code, hdr, data = e.code, e.headers, e.read()
        self.send_response(code)
        for k, v in hdr.items():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    do_GET = do_POST = do_HEAD = _go

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", LP), H).serve_forever()
