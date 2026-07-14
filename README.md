# Origin IP Resolver — OSINT Reconnaissance Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/release-v2.0.0-brightgreen)](https://github.com/ShantanuRauthan/OriginIPResolver/releases)

> A reconnaissance tool that uncovers the real origin IP addresses of websites hidden behind CDNs, proxies, and reverse proxies. Built for security researchers, penetration testers, and OSINT enthusiasts.

---

## What's New in v2.0

| Feature | Description |
|---------|-------------|
| **Historical DNS Lookup** | Queries AlienVault OTX, RapidDNS, and HackerTarget passive DNS databases to find IPs the domain resolved to BEFORE the CDN was added — the single most effective technique for origin discovery |
| **Port Scanning** | Concurrent TCP connect scan on discovered origin IPs to find exposed services (SSH, databases, admin panels) with banner grabbing |

---

## Table of Contents

- [Why This Tool Exists](#why-this-tool-exists)
- [How It Works — The Full Breakdown](#how-it-works--the-full-breakdown)
  - [1. DNS Record Analysis](#1-dns-record-analysis)
  - [2. Certificate Transparency Logs (crt.sh)](#2-certificate-transparency-logs-crtsh)
  - [3. CDN Detection & Fingerprinting](#3-cdn-detection--fingerprinting)
  - [4. Subdomain Enumeration](#4-subdomain-enumeration)
  - [5. Historical DNS Lookup](#5-historical-dns-lookup)
  - [6. HTTP Header Analysis](#6-http-header-analysis)
  - [7. SSL/TLS Certificate Analysis](#7-ssltls-certificate-analysis)
  - [8. Port Scanning](#8-port-scanning)
- [Installation](#installation)
- [Usage](#usage)
- [Output Explained](#output-explained)
- [Ethical & Legal Disclaimer](#ethical--legal-disclaimer)
- [References](#references)

---

## Why This Tool Exists

Modern websites use **Content Delivery Networks (CDNs)** like Cloudflare, Akamai, and Fastly to protect their origin servers. The CDN acts as a reverse proxy — all traffic hits the CDN's IPs, and the real server IP stays hidden.

But the origin IP can still leak through various channels. Finding it is a critical step in:

- **Penetration testing** — bypassing CDN protections to attack the real server
- **OSINT investigations** — understanding a target's infrastructure
- **Red team exercises** — discovering exposed services not meant to be public
- **Bug bounty hunting** — finding misconfigured origins that leak IPs

This tool automates the process of finding those leaked origin IPs and gathering recon data.

---

## How It Works — The Full Breakdown

```
User Input (domain)
        │
        ▼
┌────────────────────────────────────────────────────────┐
│                  1. DNS Record Analysis                 │
│   Resolves A, AAAA, CNAME, NS, MX, TXT, PTR records    │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│             2. Certificate Transparency (crt.sh)         │
│   Queries public CT logs for certificates & subdomains  │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│              3. CDN Detection & Fingerprinting           │
│   Compares IPs against known CDN ranges & CNAMEs       │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│             4. Subdomain Enumeration                     │
│   Probes ~100 common subdomains for non-CDN IPs         │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│              5. Historical DNS Lookup [v2]               │
│   Queries passive DNS databases for pre-CDN IPs         │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│            6. HTTP & SSL/TLS Analysis                     │
│   Fetches headers, detects tech stack, parses certs     │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│            7. Port Scanning [v2]                         │
│   TCP connect scan on discovered origin IPs             │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│                  Consolidated Results                    │
│   Origin candidates, CDN providers, subdomains, OSINT   │
└────────────────────────────────────────────────────────┘
```

### 1. DNS Record Analysis

**Service used:** `dnspython` library + system resolver

**What we query & why:**

| Record | What it reveals | Why it helps find origin IPs |
|--------|----------------|------------------------------|
| **A** | IPv4 addresses of the domain | The most basic record; if the site isn't behind a CDN, this IS the origin IP |
| **AAAA** | IPv6 addresses | Some admins forget to put IPv6 behind the CDN, leaking the real IP |
| **CNAME** | Canonical name (alias target) | Following the CNAME chain often reveals the CDN provider (e.g., `.cloudflare.net`) or even the origin hostname |
| **NS** | Nameservers | Can reveal hosting provider; misconfigured NS records sometimes expose internal infrastructure |
| **MX** | Mail exchange servers | Mail servers (like `mail.example.com`) are often NOT behind the CDN. If they share an IP range with the web server, you've found the origin |
| **TXT** | Text records (SPF, DKIM, etc.) | Contains infrastructure details, third-party service references, sometimes internal hostnames |
| **PTR** | Reverse DNS (IP → hostname) | Given an IP, tells you what hostname points to it. Often reveals the hosting provider or internal naming scheme |

**Why use it:** DNS is the foundation of the internet. Every domain must have DNS records, and misconfigurations are the #1 cause of origin IP leaks.

### 2. Certificate Transparency Logs (crt.sh)

**Service used:** `crt.sh` (free, no API key required)

**What it does:** Certificate Transparency (CT) is a public ledger of all SSL/TLS certificates issued by trusted Certificate Authorities (CAs). Every certificate issued for a domain must be logged in a CT log.

**What we get from it:**
- Every subdomain that has an SSL certificate (even internal/admin ones!)
- IP addresses embedded in certificate metadata
- Historical certificates (revealing old infrastructure)
- Subject Alternative Names (SANs) — other domains on the same certificate

**Why it's powerful:** Companies often issue certificates that include ALL their subdomains (wildcards and SANs). By querying CT logs, we discover subdomains the company never intended to publicize — staging servers, dev environments, admin panels. Many of these aren't behind the CDN.

**Example:** A certificate for `*.example.com` might list `admin.example.com`, `staging.example.com`, and `internal.example.com` as SANs. The CT log returns all of them, and some may point directly to the origin server.

### 3. CDN Detection & Fingerprinting

**Technique used:** IP range comparison + CNAME pattern matching + HTTP header analysis

**What we check:**

| Method | How it works | Example |
|--------|-------------|---------|
| **IP Range** | Compare resolved IPs against known CDN CIDR ranges | `104.16.x.x` → Cloudflare |
| **CNAME Pattern** | Check if CNAME contains CDN-specific patterns | `*.cloudfront.net` → AWS CloudFront |
| **HTTP Headers** | Look for CDN-specific response headers | `cf-ray` header → Cloudflare |
| **Server Header** | Parse the `Server` header for CDN signatures | `server: cloudflare` → Cloudflare |

**CDN providers we detect:** Cloudflare, Akamai, Fastly, AWS CloudFront, StackPath, Incapsula, Sucuri, Azure CDN, Google Cloud CDN, GitHub Pages, OVH

**Why it's essential:** Before looking for origin IPs, you MUST identify the CDN. All the IPs you resolve for the main domain will be CDN IPs, not origin. Only by filtering out CDN ranges can you separate real origin IPs from proxy IPs.

### 4. Subdomain Enumeration

**Technique used:** DNS brute-force with a curated wordlist

**What we do:** We take ~100 common subdomain prefixes and resolve each one against the target domain. If the subdomain exists and its IP is NOT in a CDN range, we flag it as a potential origin.

**Example wordlist entries:**
- `origin`, `direct`, `origin-www`, `origin-server` — common naming for origin servers
- `mail`, `smtp`, `ftp`, `ssh`, `vpn` — services often bypass CDN
- `admin`, `cpanel`, `api`, `dev`, `staging`, `test`, `beta` — dev/admin panels
- `ns1`, `dns1`, `mx1` — infrastructure subdomains

**Why it works:** Companies put their main domain (`www.example.com`) behind a CDN, but they often forget to do the same for:
- Internal tools (`admin.example.com`, `jenkins.example.com`)
- Development servers (`dev.example.com`, `staging.example.com`)
- API endpoints (`api.example.com`)
- Legacy infrastructure (`www2.example.com`, `old.example.com`)

These "forgotten" subdomains often resolve directly to the origin IP.

### 5. Historical DNS Lookup [v2]

**Services used:** AlienVault OTX, RapidDNS, HackerTarget (all free, no API keys required)

**What it does:** Queries passive DNS databases that have archived the domain's DNS resolution history. These services have been crawling and storing DNS records for years.

**What we get from it:**

| Source | Data returned |
|--------|---------------|
| **AlienVault OTX** | Historical A/AAAA/CNAME records with first-seen and last-seen timestamps |
| **RapidDNS** | Current and historical subdomain-to-IP mappings scraped from DNS |
| **HackerTarget** | Subdomain discovery via DNS zone transfer and brute-force |

**Why it's the #1 technique for finding origin IPs:** When a company moves their website behind a CDN (like Cloudflare), they change the DNS records to point to the CDN's IPs. However:

- **Old DNS records remain in passive DNS databases** — sometimes for years after the change
- **The original IP is still operational** — the origin server is still there, just hidden
- **Multiple subdomains might still point to the old IP** — forgotten staging environments, admin panels, or legacy services

**Real-world example:** When scanning `github.com`, historical DNS reveals IPs like `143.55.70.2` (`alive-staging.github.com`) and `150.171.109.74` (`copilot-reports.github.com`) — these are origin servers NOT behind the CDN, exposed directly to the internet.

**Why it's free:** These services offer free tiers for research and OSINT purposes. No API keys are required.

### 6. HTTP Header Analysis

**Service used:** `requests` library (Python)

**What we extract:**

| Header/Field | What it reveals |
|-------------|-----------------|
| `Server` | Web server software (nginx, Apache, IIS, etc.) |
| `X-Powered-By` | Programming language / framework |
| `Set-Cookie` | Session cookies reveal backend technology (PHPSESSID → PHP, JSESSIONID → Java, ASPSESSIONID → ASP.NET) |
| `CF-Ray` | Confirms Cloudflare |
| `X-Amz-Cf-Id` | Confirms AWS CloudFront |
| `X-Served-By` | Often reveals Fastly node names |
| `X-Cache` | Cache status (HIT/MISS) reveals CDN behavior |

**Why it matters:** Technology fingerprinting helps in:
- Identifying the operating system and web server
- Finding outdated software versions with known vulnerabilities
- Understanding the hosting architecture (shared hosting, dedicated server, cloud)

### 7. SSL/TLS Certificate Analysis

**Service used:** `pyOpenSSL` library

**What we extract:**

| Field | What it reveals |
|-------|-----------------|
| **Subject CN** | Common Name — the primary domain the cert was issued for |
| **Issuer** | Certificate Authority (Let's Encrypt, DigiCert, etc.) — can reveal certificate management practices |
| **Validity period** | NotBefore / NotAfter — when the cert was issued and expires |
| **Subject Alternative Names (SANs)** | ALL domains covered by this certificate — a goldmine for discovering related domains and subdomains |
| **Signature algorithm** | Cryptographic strength (SHA256-RSA, ECDSA, etc.) |
| **Serial number** | Unique identifier — can be used for certificate fingerprinting |

**Why it matters:** SANs from a certificate often reveal infrastructure domains like `internal.example.com`, `admin-api.example.com`, or `origin-www.example.com`. If you find a certificate that has both `www.example.com` AND `origin.example.com` as SANs, the origin server is likely at `origin.example.com`.

### 8. Port Scanning [v2]

**Technique used:** TCP connect scan with `ThreadPoolExecutor`

**What it does:** After discovering potential origin IPs, this module performs a TCP connect scan on each IP to determine which ports are open and what services are running.

**Ports scanned:**
- **Web services:** 80 (HTTP), 443 (HTTPS), 8080, 8443, 8000, 8888
- **Remote access:** 22 (SSH), 3389 (RDP), 5900 (VNC)
- **File transfer:** 21 (FTP), 445 (SMB)
- **Email:** 25 (SMTP), 587 (Submission), 465 (SMTPS), 110 (POP3), 143 (IMAP)
- **Databases:** 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB), 1433 (MSSQL)
- **Management:** 2082/2083 (cPanel), 8443 (Plesk), 10000 (Webmin), 9090 (Cisco)
- **And ~200 more common ports**

**Banner grabbing:** For open ports known to use text-based protocols (HTTP, SSH, SMTP), the tool attempts to read the service banner to identify the exact software and version.

**Why it's important:** Finding SSH on an origin IP confirms it's a live server and may be a direct attack surface. Finding a MySQL database exposed to the internet is a critical finding. Port scanning turns a theoretical origin IP into actionable intelligence.

---

## Installation

```bash
git clone https://github.com/yourusername/OriginIPResolver.git
cd OriginIPResolver
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Requirements:** Python 3.8+, `pip`

**Dependencies:**
- `requests` — HTTP requests for crt.sh, historical DNS, and header fetching
- `dnspython` — DNS record resolution (A, AAAA, CNAME, MX, NS, TXT, PTR)
- `pyOpenSSL` — SSL certificate parsing and analysis

---

## Usage

```bash
# Basic scan (all techniques enabled)
python main.py example.com

# Full scan with all techniques (default)
python main.py example.com --verbose

# Skip historical DNS lookup
python main.py example.com --no-historical

# Skip port scanning
python main.py example.com --no-portscan

# Custom ports to scan (comma-separated or ranges)
python main.py example.com --ports 22,80,443,8080
python main.py example.com --ports 1-1024

# Skip subdomain enumeration (faster)
python main.py example.com --no-subenum

# Skip certificate transparency lookup
python main.py example.com --no-crtsh

# Skip SSL certificate analysis
python main.py example.com --no-ssl

# JSON output (for programmatic consumption)
python main.py example.com --json -o results.json

# Save output to file
python main.py example.com -o scan_results.txt

# Minimal scan (fastest)
python main.py example.com --no-subenum --no-crtsh --no-ssl --no-portscan
```

---

## Output Explained

The output is divided into several sections:

```
======================================================================
  ORIGIN IP RESOLVER - OSINT RECONNAISSANCE TOOL
======================================================================
  Target: example.com
======================================================================

[!] CDN DETECTED:
    -> Cloudflare                ◄── The CDN protecting this domain

[+] CNAME CHAIN:
 ├─ www.example.com              ◄── Our target
 └─ example.cloudflare.net       ◄── CDN origin CNAME (not real origin)

[+] DNS RECORDS:
    A:
      - 104.16.x.x              ◄── Cloudflare proxy IPs
    MX:
      - mail.example.com         ◄── Mail server (could share IP with origin)

[!] POTENTIAL ORIGIN IPs (Non-CDN):
    IP: 203.0.113.5 (mail.example.com)
    Source: subdomain_enumeration:mail.example.com | Confidence: HIGH
                                  ◄── Found via subdomain enumeration!
                                  ◄── This is NOT behind Cloudflare
                                  ◄── Likely the origin IP range

    IP: 198.51.100.20 (staging.example.com)
    Source: historical_dns:hackertarget | Confidence: MEDIUM
                                  ◄── Found via historical DNS!
                                  ◄── This was the old IP before CDN

[!] CNAME-Only Resolutions (No Direct IP):
    staging.example.com -> internal-lb.example.com
                                  ◄── Reveals internal hostname

[+] HISTORICAL DNS RECORDS: [v2]
    IP: 198.51.100.20 (staging.example.com) [hackertarget]
    IP: 203.0.113.10 (dev-api.example.com) [rapiddns]
                                  ◄── IPs found in passive DNS archives

[+] DISCOVERED SUBDOMAINS:
    api.example.com -> IPs: 104.16.x.x
    dev.example.com -> IPs: 198.51.100.10
                                  ◄── dev.example.com bypasses CDN!
    mail.example.com -> IPs: 203.0.113.5

[+] SSL/TLS CERTIFICATE:
    SANs: www.example.com, api.example.com, admin.example.com
                                  ◄── Revealed by CT logs

[+] TECHNOLOGY FINGERPRINT:
    - Server: nginx/1.24.0       ◄── Web server & version
    - X-Powered-By: PHP/8.2      ◄── Backend technology

[+] PORT SCAN RESULTS: [v2]
    198.51.100.20:
      Port    22/SSH - SSH-2.0-OpenSSH_8.9    ◄── SSH accessible!
      Port    80/HTTP - nginx/1.24.0           ◄── Web server exposed
      Port   443/HTTPS                          ◄── HTTPS on origin

    203.0.113.5:
      Port    25/SMTP                           ◄── Mail server exposed
```

---

## Ethical & Legal Disclaimer

**This tool is for authorized security testing and educational purposes only.**

- Only scan domains you own or have explicit written permission to test
- Unauthorized scanning may violate computer fraud laws (CFAA in US, CMA in UK, etc.)
- Public CT logs contain only publicly issued certificate data — no private information
- DNS resolution is a standard internet function and is legal for any domain
- Historical DNS queries are made to public, freely accessible databases
- Port scanning may be restricted in some jurisdictions — check local laws before use
- The authors are not responsible for misuse of this tool

**Responsible disclosure:** If you find an origin IP leak, report it to the domain owner through their responsible disclosure program or security contact.

---

## References

- [Certificate Transparency (RFC 6962)](https://datatracker.ietf.org/doc/html/rfc6962)
- [crt.sh — Certificate Search](https://crt.sh/)
- [AlienVault OTX — Passive DNS](https://otx.alienvault.com/)
- [RapidDNS — DNS Search](https://rapiddns.io/)
- [HackerTarget — Host Search](https://hackertarget.com/hostsearch/)
- [Cloudflare IP Ranges](https://www.cloudflare.com/ips/)
- [AWS CloudFront IP Ranges](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html)
- [Fastly's publicly accessible IP ranges](https://api.fastly.com/public-ip-list)
- [Akamai IP Ranges](https://techdocs.akamai.com/cloud-security/docs/akamai-edge-ips)
- [OWASP — Enumerate Subdomains](https://owasp.org/www-community/attacks/Subdomain_enumeration)
- [dnspython documentation](https://dnspython.readthedocs.io/)
- [pyOpenSSL documentation](https://www.pyopenssl.org/)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
