#!/usr/bin/env python3
"""
Intentionally "weak" local web server used to demo the scanner safely.

It binds to 127.0.0.1 only and serves FAKE data:
  * advertises an old Apache/PHP version in its headers
  * sends no security headers
  * sets an insecure cookie
  * exposes a fake /.env file

Run:  python demo/vulnerable_server.py   (listens on http://127.0.0.1:8081)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class WeakHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.2.8"
    sys_version = "(Ubuntu) PHP/5.2.4"

    def do_GET(self):
        if self.path == "/.env":
            body = b"DB_PASSWORD=not_a_real_password\nSECRET_KEY=fake_demo_key\n"
        elif self.path == "/":
            body = b"<html><title>Demo target</title><body>Hello from the weak demo server</body></html>"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/5.2.4")
        self.send_header("Set-Cookie", "sessionid=demo123; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Demo target running on http://127.0.0.1:8081  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8081), WeakHandler).serve_forever()
