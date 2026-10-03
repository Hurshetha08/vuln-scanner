#!/usr/bin/env python3
"""
Mini Vulnerability Scanner
==========================
A small, dependency-free (standard library only) scanner that:

  1. Scans for open TCP ports and flags risky / weakly configured services
  2. Grabs banners and flags outdated software versions
  3. Runs basic web checks (security headers, cookies, TLS, exposed files)
  4. Generates a vulnerability report (Markdown, JSON and HTML)

LEGAL NOTICE: Only scan systems you own or have explicit written permission
to test. Unauthorised scanning may be illegal.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import html
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional, Tuple

VERSION = "1.0.0"
USER_AGENT = f"MiniVulnScanner/{VERSION}"
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
WEIGHTS = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}

# --------------------------------------------------------------------------- #
# Knowledge base
# --------------------------------------------------------------------------- #
COMMON_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443}
HTTP_PORTS = {80, 8000, 8080, 8081, 8888}

# port -> (severity, issue, recommendation)
RISKY_SERVICES: Dict[int, Tuple[str, str, str]] = {
    21: ("Medium", "FTP sends credentials in clear text",
         "Use SFTP/FTPS or disable FTP if not needed."),
    23: ("High", "Telnet sends everything (including passwords) in clear text",
         "Disable Telnet and use SSH instead."),
    25: ("Low", "SMTP exposed to the network",
         "Ensure it is not an open relay and requires authentication/TLS."),
    111: ("Medium", "RPC portmapper exposed",
          "Block rpcbind from untrusted networks with a firewall."),
    135: ("Medium", "Windows RPC endpoint mapper exposed",
          "Restrict MSRPC to internal networks."),
    139: ("Medium", "NetBIOS session service exposed",
          "Disable NetBIOS over TCP/IP or firewall it."),
    445: ("High", "SMB exposed to the network",
          "Block SMB from the internet; disable SMBv1; patch regularly."),
    1433: ("High", "Database port (MSSQL) reachable remotely",
           "Restrict database access to application servers only."),
    1521: ("High", "Database port (Oracle) reachable remotely",
           "Restrict database access to application servers only."),
    2049: ("High", "NFS exposed to the network",
           "Restrict NFS exports to trusted hosts only."),
    3306: ("High", "Database port (MySQL) reachable remotely",
           "Bind to localhost or firewall it from untrusted networks."),
    3389: ("High", "Remote Desktop (RDP) exposed",
           "Put RDP behind a VPN, enable NLA and MFA."),
    5432: ("High", "Database port (PostgreSQL) reachable remotely",
           "Restrict with pg_hba.conf and firewall rules."),
    5900: ("High", "VNC exposed (often weak or no authentication)",
           "Tunnel VNC through SSH/VPN and require strong passwords."),
    6379: ("Critical", "Redis exposed (no authentication by default)",
           "Bind to localhost, enable requirepass and firewall it."),
    9200: ("High", "Elasticsearch exposed (often unauthenticated)",
           "Enable security features and restrict network access."),
    11211: ("High", "Memcached exposed (no authentication by default)",
            "Bind to localhost or firewall it."),
    27017: ("High", "MongoDB exposed (check authentication is enabled)",
            "Enable auth and bind to trusted interfaces only."),
}

# (product, banner regex, minimum acceptable version, note)
# NOTE: baselines are illustrative. Keep them updated or plug in a CVE feed
# such as the NVD API for production use.
SOFTWARE_RULES = [
    ("Apache HTTP Server", r"Apache/(\d+(?:\.\d+){1,2})", "2.4.58"),
    ("nginx", r"nginx/(\d+(?:\.\d+){1,2})", "1.24.0"),
    ("OpenSSH", r"OpenSSH[_-](\d+\.\d+)", "9.0"),
    ("vsftpd", r"vsftpd (\d+(?:\.\d+){1,2})", "3.0.3"),
    ("ProFTPD", r"ProFTPD (\d+(?:\.\d+){1,2})", "1.3.7"),
    ("PHP", r"PHP/(\d+(?:\.\d+){1,2})", "8.2.0"),
    ("Microsoft IIS", r"Microsoft-IIS/(\d+(?:\.\d+)?)", "10.0"),
    ("OpenSSL", r"OpenSSL/(\d+\.\d+\.\d+)", "3.0.0"),
]

# Specific, well-known dangerous versions
KNOWN_BAD = {
    ("vsftpd", "2.3.4"): ("Critical",
                          "vsftpd 2.3.4 shipped with a malicious backdoor (CVE-2011-2523)."),
}

SECURITY_HEADERS = [
    ("Content-Security-Policy", "Medium",
     "Helps prevent XSS and data injection attacks."),
    ("X-Frame-Options", "Medium",
     "Protects against clickjacking (or use CSP frame-ancestors)."),
    ("X-Content-Type-Options", "Low", "Prevents MIME-type sniffing ('nosniff')."),
    ("Referrer-Policy", "Low", "Controls how much referrer data is leaked."),
    ("Permissions-Policy", "Low", "Restricts access to powerful browser features."),
]

# path -> (severity, title, regex that must match the body)
SENSITIVE_PATHS = {
    "/.git/HEAD": ("High", "Exposed .git repository", r"^ref:\s"),
    "/.env": ("Critical", "Exposed .env file", r"(?m)^[A-Z][A-Z0-9_]*\s*="),
    "/phpinfo.php": ("Medium", "phpinfo() page exposed", r"phpinfo\(\)|PHP Version"),
    "/server-status": ("Medium", "Apache server-status exposed", r"Apache Server Status"),
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    recommendation: str
    port: Optional[int] = None


class Results:
    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self._seen = set()

    def add(self, severity, category, title, detail, recommendation, port=None):
        key = (severity, category, title, port)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(severity, category, title, detail,
                                     recommendation, port))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def parse_ports(spec: str) -> List[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"invalid port(s): {bad}")
    return sorted(ports)


def parse_target(raw: str) -> Tuple[str, Optional[str], Optional[int]]:
    """Return (host, scheme, port) from 'host', 'host:port' or a full URL."""
    text = raw if "://" in raw else "//" + raw
    u = urllib.parse.urlparse(text)
    if not u.hostname:
        raise ValueError(f"cannot parse target: {raw!r}")
    scheme = u.scheme or None
    port = u.port
    if scheme and port is None:
        port = 443 if scheme == "https" else 80
    return u.hostname, scheme, port


def version_tuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


# --------------------------------------------------------------------------- #
# 1. Port scanning + banner grabbing
# --------------------------------------------------------------------------- #
def grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    if port in TLS_PORTS:
        return ""
    sock.settimeout(min(timeout, 1.0))
    try:
        data = sock.recv(1024)  # many services (ssh, ftp, smtp) speak first
    except socket.timeout:
        try:  # otherwise try a harmless HTTP probe
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                         f"User-Agent: {USER_AGENT}\r\n\r\n".encode())
            data = sock.recv(2048)
        except OSError:
            return ""
    except OSError:
        return ""
    return data.decode("utf-8", "replace").strip()


def probe_port(host: str, port: int, timeout: float) -> Tuple[int, Optional[str]]:
    """Return (port, banner) if open, else (port, None)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return port, grab_banner(s, host, port, timeout)
    except OSError:
        return port, None


def scan_ports(host: str, ports: List[int], timeout: float,
               threads: int) -> Dict[int, str]:
    open_ports: Dict[int, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        for port, banner in pool.map(lambda p: probe_port(host, p, timeout), ports):
            if banner is not None:
                open_ports[port] = banner
    return dict(sorted(open_ports.items()))


# --------------------------------------------------------------------------- #
# 2. Analysis: risky services & outdated software
# --------------------------------------------------------------------------- #
def check_software_versions(text: str, port: Optional[int], source: str,
                            res: Results) -> None:
    for product, pattern, minimum in SOFTWARE_RULES:
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            continue
        found = m.group(1)
        label = f"{product} {found}"
        bad = KNOWN_BAD.get((product, found))
        if bad:
            res.add(bad[0], "Outdated Software", f"{label} has a known critical flaw",
                    f"{bad[1]} (detected via {source}).",
                    "Upgrade immediately to a supported release.", port)
        elif version_tuple(found) < version_tuple(minimum):
            behind_minor = version_tuple(found)[:2] < version_tuple(minimum)[:2]
            res.add("High" if behind_minor else "Medium", "Outdated Software",
                    f"Outdated {label}",
                    f"Detected via {source}. Scanner baseline is {minimum}; older "
                    f"releases may contain known vulnerabilities.",
                    f"Upgrade {product} to the latest stable release and review "
                    f"its CVEs (https://nvd.nist.gov).", port)
        # Version disclosure itself is a (low) information leak
        res.add("Low", "Information Disclosure",
                f"Software version disclosed: {label}",
                f"The version string is visible in the {source}.",
                "Hide version details (e.g. ServerTokens Prod, server_tokens off).",
                port)


def analyze_open_ports(open_ports: Dict[int, str], res: Results) -> None:
    for port, banner in open_ports.items():
        svc = service_name(port)
        res.add("Info", "Open Port", f"Port {port}/tcp open ({svc})",
                (f"Banner: {banner.splitlines()[0][:120]}" if banner
                 else "No banner received."),
                "Close the port if the service is not required.", port)
        if port in RISKY_SERVICES:
            sev, issue, fix = RISKY_SERVICES[port]
            res.add(sev, "Weak Configuration", issue,
                    f"Port {port} ({svc}) is reachable from the scanning host.",
                    fix, port)
        if banner:
            check_software_versions(banner, port, "service banner", res)


# --------------------------------------------------------------------------- #
# 3. Web checks
# --------------------------------------------------------------------------- #
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def http_get(url: str, timeout: float, follow: bool = True):
    """Return (status, headers, body) or None on connection failure."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # certificate validity is checked separately
    handlers: list = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:  # 3xx/4xx/5xx still carry useful headers
        resp = e
    except (urllib.error.URLError, OSError, ValueError):
        return None
    try:
        body = resp.read(65536).decode("utf-8", "replace")
    except OSError:
        body = ""
    status = getattr(resp, "status", None) or getattr(resp, "code", 0)
    return status, resp.headers, body


def check_security_headers(url, scheme, headers, port, res):
    for name, sev, why in SECURITY_HEADERS:
        if headers.get(name) is None:
            if name == "X-Frame-Options" and "frame-ancestors" in (
                    headers.get("Content-Security-Policy") or ""):
                continue
            res.add(sev, "Missing Security Header", f"Missing {name} header",
                    f"{url} does not send {name}. {why}",
                    f"Add the {name} response header.", port)
    if scheme == "https" and headers.get("Strict-Transport-Security") is None:
        res.add("Medium", "Missing Security Header",
                "Missing Strict-Transport-Security (HSTS) header",
                f"{url} does not enforce HTTPS on future visits.",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                port)


def check_cookies(url, scheme, headers, port, res):
    for cookie in headers.get_all("Set-Cookie") or []:
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if scheme == "https" and "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            res.add("Medium" if "HttpOnly" in missing or "Secure" in missing else "Low",
                    "Insecure Cookie", f"Cookie '{name}' missing {', '.join(missing)}",
                    f"Set-Cookie from {url} lacks recommended attributes.",
                    "Set HttpOnly, Secure (HTTPS) and SameSite on session cookies.", port)


def check_sensitive_paths(base: str, timeout: float, port: int, res: Results):
    for path, (sev, title, signature) in SENSITIVE_PATHS.items():
        r = http_get(base + path, timeout)
        if r and r[0] == 200 and re.search(signature, r[2]):
            res.add(sev, "Exposed Resource", f"{title} ({path})",
                    f"{base}{path} returned content that matches a sensitive file.",
                    "Remove the file or block access in the web server config.", port)
    r = http_get(base + "/", timeout)
    if r and r[0] == 200 and re.search(r"<title>Index of /", r[2], re.IGNORECASE):
        res.add("Medium", "Weak Configuration", "Directory listing enabled",
                f"{base}/ shows an auto-generated directory index.",
                "Disable directory indexing (e.g. 'Options -Indexes').", port)


def check_tls(host: str, port: int, timeout: float, res: Results) -> None:
    def handshake(verify: bool):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return s.getpeercert(), s.version()

    cert, tls_version = None, None
    try:
        cert, tls_version = handshake(True)
    except ssl.SSLCertVerificationError as e:
        res.add("Medium", "TLS/SSL", "TLS certificate failed verification",
                f"{e.verify_message} (host: {host}:{port}).",
                "Install a valid certificate from a trusted CA that matches the hostname.",
                port)
        try:
            _, tls_version = handshake(False)
        except (ssl.SSLError, OSError):
            pass
    except (ssl.SSLError, OSError):
        return

    if tls_version:
        sev = "High" if tls_version in ("SSLv3", "TLSv1", "TLSv1.1") else "Info"
        res.add(sev, "TLS/SSL", f"Negotiated protocol: {tls_version}",
                "Legacy protocols are insecure." if sev == "High"
                else "Modern TLS version in use.",
                "Disable SSLv3/TLS 1.0/1.1; allow TLS 1.2+ only.", port)
    if cert and "notAfter" in cert:
        days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
        if days < 0:
            res.add("High", "TLS/SSL", "TLS certificate has expired",
                    f"Expired {abs(int(days))} day(s) ago.", "Renew the certificate.", port)
        elif days < 30:
            res.add("Medium", "TLS/SSL", "TLS certificate expires soon",
                    f"Expires in {int(days)} day(s).", "Renew the certificate.", port)


def run_web_checks(host: str, web_ports: Dict[int, str], open_ports: Dict[int, str],
                   timeout: float, res: Results) -> None:
    for port, scheme in web_ports.items():
        default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        base = f"{scheme}://{host}" + ("" if default else f":{port}")
        r = http_get(base + "/", timeout)
        if r is None:
            continue
        status, headers, _ = r
        res.add("Info", "Web", f"Web service reachable at {base} (HTTP {status})",
                f"Server header: {headers.get('Server', 'not sent')}",
                "-", port)
        check_security_headers(base, scheme, headers, port, res)
        check_cookies(base, scheme, headers, port, res)
        for hdr in ("Server", "X-Powered-By", "X-AspNet-Version"):
            if headers.get(hdr):
                check_software_versions(headers[hdr], port, f"{hdr} header", res)
        check_sensitive_paths(base, timeout, port, res)
        if scheme == "https":
            check_tls(host, port, timeout, res)
        elif scheme == "http":
            if 443 in open_ports:
                nr = http_get(base + "/", timeout, follow=False)
                loc = (nr[1].get("Location") or "") if nr else ""
                if nr and not (300 <= nr[0] < 400 and loc.startswith("https://")):
                    res.add("Medium", "Weak Configuration",
                            "HTTP does not redirect to HTTPS",
                            f"{base} serves content over plain HTTP although HTTPS is available.",
                            "Redirect all HTTP traffic to HTTPS (301).", port)
            else:
                res.add("Medium", "Weak Configuration", "Site served over unencrypted HTTP only",
                        f"{base} has no HTTPS counterpart on port 443.",
                        "Enable HTTPS with a valid certificate.", port)


def detect_web_ports(open_ports: Dict[int, str], hint: Optional[Tuple[int, str]]) -> Dict[int, str]:
    web: Dict[int, str] = {}
    for port, banner in open_ports.items():
        if port in TLS_PORTS and port in (443, 8443):
            web[port] = "https"
        elif port in HTTP_PORTS or banner.upper().startswith("HTTP/"):
            web[port] = "http"
    if hint and hint[0] in open_ports:
        web[hint[0]] = hint[1]
    return web


# --------------------------------------------------------------------------- #
# 4. Reporting
# --------------------------------------------------------------------------- #
def summarise(findings: List[Finding]) -> Dict[str, object]:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    score = min(100, sum(WEIGHTS[f.severity] for f in findings))
    rating = ("Critical" if counts["Critical"] else "High" if counts["High"] else
              "Medium" if counts["Medium"] else "Low" if counts["Low"] else "Clean")
    return {"counts": counts, "risk_score": score, "overall_rating": rating}


def sorted_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), f.port or 0))


def build_report(meta: dict, findings: List[Finding]) -> dict:
    return {"meta": meta, "summary": summarise(findings),
            "findings": [asdict(f) for f in sorted_findings(findings)]}


def to_markdown(report: dict) -> str:
    m, s = report["meta"], report["summary"]
    lines = [
        "# Vulnerability Scan Report", "",
        f"- **Target:** {m['target']} ({m['ip']})",
        f"- **Scan date:** {m['started']}",
        f"- **Ports scanned:** {m['ports_scanned']}  |  **Open:** {m['open_ports']}",
        f"- **Overall rating:** {s['overall_rating']}  |  **Risk score:** {s['risk_score']}/100",
        "", "## Summary", "", "| Severity | Count |", "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in s["counts"].items()]
    lines += ["", "## Findings", ""]
    for i, f in enumerate(report["findings"], 1):
        port = f" (port {f['port']})" if f["port"] else ""
        lines += [f"### {i}. [{f['severity']}] {f['title']}{port}", "",
                  f"- **Category:** {f['category']}",
                  f"- **Details:** {f['detail']}",
                  f"- **Recommendation:** {f['recommendation']}", ""]
    lines += ["---", "*Generated by Mini Vulnerability Scanner. Findings are "
              "indicators, not proof; verify manually.*"]
    return "\n".join(lines)


def to_html(report: dict) -> str:
    m, s = report["meta"], report["summary"]
    colors = {"Critical": "#b71c1c", "High": "#e65100", "Medium": "#f9a825",
              "Low": "#1565c0", "Info": "#546e7a"}
    rows = "".join(
        f"<tr><td><span class='b' style='background:{colors[f['severity']]}'>"
        f"{f['severity']}</span></td><td>{html.escape(f['category'])}</td>"
        f"<td>{html.escape(f['title'])}</td>"
        f"<td>{f['port'] or ''}</td><td>{html.escape(f['detail'])}</td>"
        f"<td>{html.escape(f['recommendation'])}</td></tr>"
        for f in report["findings"])
    cards = "".join(
        f"<div class='card' style='border-top:4px solid {colors[k]}'><b>{v}</b><br>{k}</div>"
        for k, v in s["counts"].items())
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Vulnerability Scan Report</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#222}}
.cards{{display:flex;gap:1rem;margin:1rem 0}}
.card{{padding:1rem 1.5rem;background:#f5f5f5;border-radius:6px;text-align:center}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}
th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}
th{{background:#263238;color:#fff}}.b{{color:#fff;padding:2px 8px;border-radius:4px}}
</style></head><body>
<h1>Vulnerability Scan Report</h1>
<p><b>Target:</b> {html.escape(m['target'])} ({m['ip']})<br>
<b>Date:</b> {m['started']}<br>
<b>Ports scanned:</b> {m['ports_scanned']} | <b>Open:</b> {m['open_ports']}<br>
<b>Overall rating:</b> {s['overall_rating']} | <b>Risk score:</b> {s['risk_score']}/100</p>
<div class="cards">{cards}</div>
<table><tr><th>Severity</th><th>Category</th><th>Issue</th><th>Port</th>
<th>Details</th><th>Recommendation</th></tr>{rows}</table>
<p><i>Generated by Mini Vulnerability Scanner. Findings are indicators, not proof.</i></p>
</body></html>"""


def write_reports(report: dict, out_dir: str, fmts: List[str]) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", report["meta"]["target"])
    base = os.path.join(out_dir, f"report_{safe}_{stamp}")
    writers: Dict[str, Callable[[], str]] = {
        "md": lambda: to_markdown(report),
        "json": lambda: json.dumps(report, indent=2),
        "html": lambda: to_html(report),
    }
    paths = []
    for fmt in fmts:
        path = f"{base}.{fmt}"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(writers[fmt]())
        paths.append(path)
    return paths


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Mini Vulnerability Scanner - open ports, outdated software, "
                    "weak web configuration and report generation.",
        epilog="Only scan systems you own or are authorised to test.")
    p.add_argument("target", help="hostname, IP, host:port or URL (e.g. http://127.0.0.1:8081)")
    p.add_argument("-p", "--ports", help="ports, e.g. '1-1024,3306,8080' "
                                         "(default: ~35 common ports)")
    p.add_argument("--top-1000", action="store_true",
                   help="scan ports 1-1024 plus the common list")
    p.add_argument("-t", "--timeout", type=float, default=1.0,
                   help="socket timeout in seconds (default 1.0)")
    p.add_argument("--threads", type=int, default=100, help="worker threads (default 100)")
    p.add_argument("-o", "--output-dir", default="reports", help="report folder")
    p.add_argument("-f", "--formats", default="md,json,html",
                   help="comma list of: md,json,html")
    p.add_argument("--no-web", action="store_true", help="skip HTTP/TLS checks")
    p.add_argument("-y", "--yes", action="store_true",
                   help="confirm you are authorised to scan the target (no prompt)")
    p.add_argument("--version", action="version", version=VERSION)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    fmts = [f.strip() for f in args.formats.split(",") if f.strip()]
    if any(f not in ("md", "json", "html") for f in fmts):
        print("error: --formats must be a subset of md,json,html")
        return 2
    try:
        host, scheme, url_port = parse_target(args.target)
        if args.ports:
            ports = parse_ports(args.ports)
        else:
            ports = set(COMMON_PORTS)
            if args.top_1000:
                ports |= set(range(1, 1025))
            ports = sorted(ports)
        if url_port and url_port not in ports:
            ports = sorted(set(ports) | {url_port})
    except ValueError as e:
        print(f"error: {e}")
        return 2

    if not args.yes:
        print("WARNING: scanning systems without permission may be illegal.")
        if input(f"Do you have authorisation to scan {host}? [y/N] ").lower() != "y":
            print("Aborted.")
            return 1

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"error: cannot resolve {host}")
        return 2

    started = dt.datetime.now()
    print(f"[*] Target: {host} ({ip})  |  scanning {len(ports)} port(s)")
    open_ports = scan_ports(ip, ports, args.timeout, args.threads)
    print(f"[+] {len(open_ports)} open port(s): "
          f"{', '.join(f'{p}/{service_name(p)}' for p in open_ports) or 'none'}")

    res = Results()
    analyze_open_ports(open_ports, res)

    if not args.no_web:
        hint = (url_port, scheme) if scheme and url_port else None
        web_ports = detect_web_ports(open_ports, hint)
        if web_ports:
            print(f"[*] Running web checks on: {', '.join(map(str, web_ports))}")
            run_web_checks(host, web_ports, open_ports, args.timeout, res)

    meta = {"target": args.target, "ip": ip, "started": started.strftime("%Y-%m-%d %H:%M:%S"),
            "ports_scanned": len(ports), "open_ports": len(open_ports),
            "tool_version": VERSION}
    report = build_report(meta, res.findings)

    print("\n=== SUMMARY ===")
    for sev, n in report["summary"]["counts"].items():
        print(f"  {sev:<9}{n}")
    print(f"  Rating: {report['summary']['overall_rating']}  "
          f"(risk score {report['summary']['risk_score']}/100)\n")
    for f in report["findings"]:
        if f["severity"] != "Info":
            print(f"  [{f['severity']:<8}] {f['title']}" +
                  (f"  (port {f['port']})" if f["port"] else ""))

    for path in write_reports(report, args.output_dir, fmts):
        print(f"[+] Report written: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
