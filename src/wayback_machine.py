import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_AVAILABILITY_URL = "https://archive.org/wayback/available"


def query_wayback_cdx(domain, match_type="domain", limit=500):
    try:
        params = {
            "url": f"*.{domain}" if match_type == "domain" else domain,
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype",
            "limit": limit,
            "collapse": "urlkey",
            "filter": "statuscode:200",
        }
        resp = requests.get(WAYBACK_CDX_URL, params=params, timeout=30,
                           headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        if not data or len(data) < 2:
            return []
        headers = data[0]
        results = []
        for row in data[1:]:
            entry = dict(zip(headers, row))
            results.append({
                "url": entry.get("original", ""),
                "timestamp": entry.get("timestamp", ""),
                "status": entry.get("statuscode", ""),
                "mime_type": entry.get("mimetype", ""),
                "source": "wayback_machine",
            })
        return results
    except Exception:
        return []


def extract_ips_from_wayback(domain, max_workers=5):
    urls = query_wayback_cdx(domain)
    ips_found = []
    url_set = set()

    for entry in urls:
        url = entry.get("url", "")
        if url and url not in url_set:
            url_set.add(url)

    def extract_ip_from_url(url):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return None
            import ipaddress
            try:
                ipaddress.ip_address(hostname)
                return hostname
            except ValueError:
                return None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(extract_ip_from_url, url): url for url in url_set}
        for future in as_completed(futures):
            try:
                ip = future.result()
                if ip and ip not in ips_found:
                    ips_found.append(ip)
            except Exception:
                pass

    return ips_found


def get_wayback_snapshots(domain, limit=10):
    try:
        params = {
            "url": domain,
            "output": "json",
            "fl": "timestamp,original,statuscode",
            "limit": limit,
            "sort": "desc",
        }
        resp = requests.get(WAYBACK_CDX_URL, params=params, timeout=30,
                           headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        if not data or len(data) < 2:
            return []
        headers = data[0]
        results = []
        for row in data[1:]:
            entry = dict(zip(headers, row))
            results.append({
                "timestamp": entry.get("timestamp", ""),
                "url": entry.get("original", ""),
                "status": entry.get("statuscode", ""),
            })
        return results
    except Exception:
        return []


def extract_historical_subdomains_from_wayback(domain):
    urls = query_wayback_cdx(domain)
    subdomains = set()

    for entry in urls:
        url = entry.get("url", "")
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname and hostname.endswith("." + domain):
                subdomains.add(hostname)
            elif hostname and hostname == domain:
                subdomains.add(hostname)
        except Exception:
            pass

    return sorted(subdomains)
