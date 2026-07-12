# Origin IP Resolver — OSINT Reconnaissance Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> A reconnaissance tool that uncovers the real origin IP addresses of websites hidden behind CDNs, proxies, and reverse proxies. Built for security researchers, penetration testers, and OSINT enthusiasts.

---

## Table of Contents

- [Why This Tool Exists](#why-this-tool-exists)
- [How It Works — The Full Breakdown](#how-it-works--the-full-breakdown)
  - [1. DNS Record Analysis](#1-dns-record-analysis)
  - [2. Certificate Transparency Logs (crt.sh)](#2-certificate-transparency-logs-crtsh)
  - [3. CDN Detection & Fingerprinting](#3-cdn-detection--fingerprinting)
  - [4. Subdomain Enumeration](#4-subdomain-enumeration)
  - [5. HTTP Header Analysis](#5-http-header-analysis)
  - [6. SSL/TLS Certificate Analysis](#6-ssltls-certificate-analysis)
- [Techniques to Find Origin IPs](#techniques-to-find-origin-ips)
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
│          5. HTTP & SSL/TLS Analysis                      │
│   Fetches headers, detects tech stack, parses certs     │
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

**Advanced theory:** Even when origin IPs are found behind CDN IPs, the origin IP might respond on different ports. Subdomain enumeration combined with port scanning (future enhancement) can reveal services like SSH, RDP, or databases exposed directly to the internet.

### 5. HTTP Header Analysis

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

### 6. SSL/TLS Certificate Analysis

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
- `requests` — HTTP requests for crt.sh and header fetching
- `dnspython` — DNS record resolution (A, AAAA, CNAME, MX, NS, TXT, PTR)
- `pyOpenSSL` — SSL certificate parsing and analysis

---

## Usage

```bash
# Basic scan
python main.py example.com

# Full scan with all techniques (default)
python main.py example.com --verbose

# Skip subdomain enumeration (faster, less thorough)
python main.py example.com --no-subenum

# Skip certificate transparency lookup
python main.py example.com --no-crtsh

# Skip SSL certificate analysis
python main.py example.com --no-ssl

# JSON output (for programmatic consumption)
python main.py example.com --json -o results.json

# Save output to file
python main.py example.com -o scan_results.txt
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

[!] CNAME-Only Resolutions (No Direct IP):
    staging.example.com -> internal-lb.example.com
                                  ◄── Reveals internal hostname

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
```

---

## Ethical & Legal Disclaimer

**This tool is for authorized security testing and educational purposes only.**

- Only scan domains you own or have explicit written permission to test
- Unauthorized scanning may violate computer fraud laws (CFAA in US, CMA in UK, etc.)
- Public CT logs contain only publicly issued certificate data — no private information
- DNS resolution is a standard internet function and is legal for any domain
- The authors are not responsible for misuse of this tool

**Responsible disclosure:** If you find an origin IP leak, report it to the domain owner through their responsible disclosure program or security contact.

---

## References

- [Certificate Transparency (RFC 6962)](https://datatracker.ietf.org/doc/html/rfc6962)
- [crt.sh — Certificate Search](https://crt.sh/)
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
