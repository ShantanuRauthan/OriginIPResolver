import requests
from src.config import API_KEYS


SECURITYTRAILS_API_URL = "https://api.securitytrails.com/v1"


def get_subdomains(domain, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("securitytrails", "")
    if not api_key:
        return []
    try:
        url = f"{SECURITYTRAILS_API_URL}/domain/{domain}/subdomains"
        headers = {"apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        subdomains = data.get("subdomains", [])
        return [f"{sub}.{domain}" for sub in subdomains]
    except Exception:
        return []


def get_historical_dns(domain, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("securitytrails", "")
    if not api_key:
        return []
    try:
        url = f"{SECURITYTRAILS_API_URL}/domain/{domain}/history"
        headers = {"apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        records = []
        for record_type, entries in data.items():
            if isinstance(entries, list):
                for entry in entries:
                    records.append({
                        "ip": entry.get("ip", ""),
                        "hostname": entry.get("hostname", domain),
                        "record_type": record_type,
                        "first_seen": entry.get("first_seen", ""),
                        "last_seen": entry.get("last_seen", ""),
                        "source": "securitytrails",
                    })
        return records
    except Exception:
        return []


def get_whois(domain, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("securitytrails", "")
    if not api_key:
        return None
    try:
        url = f"{SECURITYTRAILS_API_URL}/domain/{domain}/whois"
        headers = {"apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def get_dns(domain, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("securitytrails", "")
    if not api_key:
        return {}
    try:
        url = f"{SECURITYTRAILS_API_URL}/domain/{domain}/dns"
        headers = {"apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return {}
        return resp.json()
    except Exception:
        return {}
