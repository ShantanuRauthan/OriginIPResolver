import requests
from src.config import API_KEYS


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"


def get_subdomains(domain, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("virustotal", "")
    if not api_key:
        return []
    try:
        url = f"{VIRUSTOTAL_API_URL}/domains/{domain}/subdomains"
        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        subdomains = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            subdomain = attrs.get("last_dns_records", [])
            name = item.get("id", "")
            if name:
                subdomains.append(name)
        return subdomains
    except Exception:
        return []


def get_resolutions(domain, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("virustotal", "")
    if not api_key:
        return []
    try:
        url = f"{VIRUSTOTAL_API_URL}/domains/{domain}/resolutions"
        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        resolutions = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            host = attrs.get("host_name", "")
            ip = attrs.get("ip_address", "")
            if ip:
                resolutions.append({
                    "ip": ip,
                    "hostname": host,
                    "record_type": "A",
                    "first_seen": "",
                    "last_seen": "",
                    "source": "virustotal",
                })
        return resolutions
    except Exception:
        return []


def get_communicating_files(ip, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("virustotal", "")
    if not api_key:
        return []
    try:
        url = f"{VIRUSTOTAL_API_URL}/ip_addresses/{ip}/communicating_files"
        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        files = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            files.append({
                "sha256": attrs.get("sha256", ""),
                "detection": attrs.get("last_analysis_stats", {}),
                "source": "virustotal",
            })
        return files
    except Exception:
        return []


def get_ip_report(ip, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("virustotal", "")
    if not api_key:
        return None
    try:
        url = f"{VIRUSTOTAL_API_URL}/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {}).get("attributes", {})
        return {
            "ip": ip,
            "as_owner": data.get("as_owner", ""),
            "asn": data.get("asn", ""),
            "country": data.get("country", ""),
            "reputation": data.get("reputation", 0),
            "network": data.get("network", ""),
            "source": "virustotal",
        }
    except Exception:
        return None
