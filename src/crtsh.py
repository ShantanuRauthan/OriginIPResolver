import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote


CRTSH_URL = "https://crt.sh/?q={}&output=json"
CRTSH_IDENTITY_URL = "https://crt.sh/?identity={}&output=json"


def fetch_certificates(domain, wildcard=True):
    try:
        query = "%25.{}".format(domain) if wildcard else domain
        url = CRTSH_URL.format(quote(query))
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    try:
        url = CRTSH_IDENTITY_URL.format(quote(domain))
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    return []


def extract_subdomains(certificates, domain):
    subdomains = set()
    for cert in certificates:
        name_value = cert.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and ("*." + domain in name or name.endswith("." + domain) or name == domain):
                subdomains.add(name.lstrip("*."))
    return sorted(subdomains)


def extract_ips_from_certificates(certificates):
    ips = set()
    for cert in certificates:
        if "ip_addresses" in cert and cert["ip_addresses"]:
            for ip in cert["ip_addresses"]:
                ips.add(ip.strip())
        if "ip" in cert and cert["ip"]:
            ips.add(cert["ip"].strip())
    return sorted(ips)


def get_certificate_details(domain):
    certs = fetch_certificates(domain)
    subdomains = extract_subdomains(certs, domain)
    ips = extract_ips_from_certificates(certs)
    return {
        "certificates_count": len(certs),
        "subdomains": subdomains,
        "ips": ips,
    }
