import requests
import base64
from src.config import API_KEYS


CENSYS_API_URL = "https://search.censys.io/api/v2"


def _get_auth():
    censys_id = API_KEYS.get("censys_id", "")
    censys_secret = API_KEYS.get("censys_secret", "")
    if not censys_id or not censys_secret:
        return None
    return (censys_id, censys_secret)


def search_hosts(query, per_page=25):
    auth = _get_auth()
    if not auth:
        return []
    try:
        url = f"{CENSYS_API_URL}/hosts/search"
        params = {
            "q": query,
            "per_page": per_page,
        }
        resp = requests.get(url, params=params, auth=auth, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for hit in data.get("result", {}).get("hits", []):
            results.append({
                "ip": hit.get("ip", ""),
                "services": [
                    {
                        "port": s.get("port"),
                        "service_name": s.get("service_name", ""),
                        "transport_protocol": s.get("transport_protocol", ""),
                    }
                    for s in hit.get("services", [])
                ],
                "autonomous_system": {
                    "asn": hit.get("autonomous_system", {}).get("asn", ""),
                    "name": hit.get("autonomous_system", {}).get("name", ""),
                },
                "location": {
                    "country": hit.get("location", {}).get("country", ""),
                    "city": hit.get("location", {}).get("city", ""),
                },
                "source": "censys",
            })
        return results
    except Exception:
        return []


def search_certificates(domain, per_page=25):
    auth = _get_auth()
    if not auth:
        return []
    try:
        url = f"{CENSYS_API_URL}/certificates"
        params = {
            "q": f"parsed.subject.common_name:{domain} OR parsed.names:{domain}",
            "per_page": per_page,
        }
        resp = requests.get(url, params=params, auth=auth, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for hit in data.get("result", {}).get("hits", []):
            parsed = hit.get("parsed", {})
            names = parsed.get("names", [])
            subject = parsed.get("subject", {})
            issuer = parsed.get("issuer", {})
            results.append({
                "fingerprint": hit.get("fingerprint_sha256", ""),
                "names": names,
                "subject_cn": subject.get("common_name", [""]),
                "issuer_cn": issuer.get("common_name", [""]),
                "source": "censys",
            })
        return results
    except Exception:
        return []


def get_host_details(ip):
    auth = _get_auth()
    if not auth:
        return None
    try:
        url = f"{CENSYS_API_URL}/hosts/{ip}"
        resp = requests.get(url, auth=auth, timeout=30)
        if resp.status_code != 200:
            return None
        data = resp.json().get("result", {})
        services = []
        for service in data.get("services", []):
            services.append({
                "port": service.get("port"),
                "service_name": service.get("service_name", ""),
                "transport_protocol": service.get("transport_protocol", ""),
                "extended_service_name": service.get("extended_service_name", ""),
            })
        return {
            "ip": ip,
            "services": services,
            "autonomous_system": {
                "asn": data.get("autonomous_system", {}).get("asn", ""),
                "name": data.get("autonomous_system", {}).get("name", ""),
            },
            "location": {
                "country": data.get("location", {}).get("country", ""),
                "city": data.get("location", {}).get("city", ""),
            },
            "operating_system": data.get("operating_system", {}).get("product", ""),
            "source": "censys",
        }
    except Exception:
        return None
