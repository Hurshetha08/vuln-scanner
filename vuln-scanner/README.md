# 🛡️ Mini Vulnerability Scanner

A lightweight, dependency-free Python tool that scans a host or web application for common security weaknesses and produces a vulnerability report. Built as a learning project for **penetration testing and vulnerability assessment** fundamentals.

> ⚠️ **Legal notice:** Only scan systems you own or have explicit written permission to test. Unauthorised scanning may be illegal. Safe practice targets: `127.0.0.1`, the bundled demo server, or `scanme.nmap.org` (explicitly provided by the Nmap project for testing).

## ✨ Features

| Area | What it does |
|---|---|
| **Port scanning** | Multithreaded TCP connect scan (common ports, custom ranges, or 1-1024) |
| **Weak configurations** | Flags risky exposed services (Telnet, FTP, SMB, RDP, Redis, MongoDB, DB ports…), missing security headers, insecure cookies, HTTP without HTTPS/redirect, directory listing, exposed `.env` / `.git` / `phpinfo` files, TLS certificate problems |
| **Outdated software** | Banner grabbing + `Server` / `X-Powered-By` header parsing, compared against a version baseline table (Apache, nginx, OpenSSH, PHP, IIS, vsftpd, ProFTPD, OpenSSL) plus known-bad versions |
| **Reporting** | Severity-ranked report (Critical → Info) with risk score and remediation advice in **Markdown, JSON and HTML** |

## 📁 Project structure

```
vuln-scanner/
├── scanner.py                 # the scanner (single file, stdlib only)
├── demo/vulnerable_server.py  # intentionally weak LOCAL target for safe testing
├── sample_report/             # example output (md / json / html)
├── requirements.txt
├── LICENSE
└── README.md
```

## 🚀 Usage

Requires **Python 3.8+**. No installation needed.

```bash
git clone https://github.com/Hurshetha08/vuln-scanner.git
cd vuln-scanner

# 1) Try it safely on the bundled demo target
python demo/vulnerable_server.py &            # starts http://127.0.0.1:8081
python scanner.py http://127.0.0.1:8081 -y

# 2) Scan a host you are authorised to test
python scanner.py 127.0.0.1
python scanner.py scanme.nmap.org -p 1-1024 -y
python scanner.py example.com --top-1000 -f html,json
```

### Options

| Flag | Description |
|---|---|
| `target` | hostname, IP, `host:port` or URL |
| `-p, --ports` | e.g. `22,80,443` or `1-1024` (default: ~32 common ports) |
| `--top-1000` | scan ports 1-1024 + common ports |
| `-t, --timeout` | socket timeout in seconds (default `1.0`) |
| `--threads` | worker threads (default `100`) |
| `-f, --formats` | any of `md,json,html` (default all) |
| `-o, --output-dir` | report folder (default `reports/`) |
| `--no-web` | skip HTTP/TLS checks |
| `-y, --yes` | confirm authorisation (otherwise you are prompted) |

## 📊 Sample output

```
[*] Target: 127.0.0.1 (127.0.0.1)  |  scanning 32 port(s)
[+] 1 open port(s): 8081/unknown

=== SUMMARY ===
  Critical 1 | High 2 | Medium 4 | Low 5 | Info 2
  Rating: Critical  (risk score 45/100)

  [Critical] Exposed .env file (/.env)
  [High    ] Outdated Apache HTTP Server 2.2.8
  [High    ] Outdated PHP 5.2.4
  [Medium  ] Missing Content-Security-Policy header
  [Medium  ] Cookie 'sessionid' missing HttpOnly, SameSite
  ...
```

Full reports: [`sample_report.md`](sample_report/sample_report.md), [`sample_report.html`](sample_report/sample_report.html), [`sample_report.json`](sample_report/sample_report.json).

## 🔍 How it works

1. **Discovery:** threaded `connect()` scan finds open TCP ports.
2. **Fingerprinting:** reads service banners (and sends a harmless `HEAD` request to web ports).
3. **Analysis:** regex-extracts product/version, compares with the baseline table, and maps ports to known risky services.
4. **Web checks:** inspects response headers, cookies, TLS certificate/protocol and probes a few well-known sensitive paths.
5. **Report:** findings are de-duplicated, ranked by severity, scored and exported.

## ⚠️ Limitations

- Version baselines are **illustrative**; a real tool should query a CVE feed such as the [NVD API](https://nvd.nist.gov/developers).
- Banner-based detection can be wrong (banners can be hidden or spoofed, and distros backport patches).
- TCP connect scan only; no UDP, no exploitation, no authenticated scanning.
- Results are indicators to verify manually, not proof of exploitability.

## 🔮 Future improvements

- NVD/CVE API integration for live version lookups
- UDP and service-specific checks (SSH algorithms, SMB signing)
- Crawler for XSS/SQLi detection in forms
- CSV export and CI integration

## 📜 License

MIT: see [LICENSE](LICENSE).
