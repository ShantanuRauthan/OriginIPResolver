import requests
from src.config import API_KEYS


SHODAN_API_URL = "https://api.shodan.io"


def search_host(ip, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("shodan", "")
    if not api_key:
        return None
    try:
        url = f"{SHODAN_API_URL}/shodan/host/{ip}?key={api_key}"
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            return None
        data = resp.json()
        services = []
        for service in data.get("data", []):
            services.append({
                "port": service.get("port"),
                "transport": service.get("transport", "tcp"),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "banner": (service.get("data", "") or "")[:200],
                "module": service.get("_shodan", {}).get("module", ""),
            })
        return {
            "ip": ip,
            "org": data.get("org", ""),
            "os": data.get("os", ""),
            "isp": data.get("isp", ""),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "ports": data.get("ports", []),
            "services": services,
            "vulns": data.get("vulns", []),
            "source": "shodan",
        }
    except Exception:
        return None


def search_domain(domain, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("shodan", "")
    if not api_key:
        return []
    try:
        url = f"{SHODAN_API_URL}/dns/domain/{domain}?key={api_key}"
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        records = []
        for record in data.get("data", []):
            records.append({
                "subdomain": record.get("subdomain", ""),
                "type": record.get("type", ""),
                "value": record.get("value", ""),
                "source": "shodan",
            })
        return records
    except Exception:
        return []


def reverse_dns_batch(ips, api_key=None):
    if not api_key:
        api_key = API_KEYS.get("shodan", "")
    if not api_key:
        return {}
    results = {}
    for ip in ips[:50]:
        host = search_host(ip, api_key)
        if host:
            results[ip] = host
    return results
