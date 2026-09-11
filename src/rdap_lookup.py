import requests
import ipaddress


RDAP_BOOTSTRAP_URL = "https://rdap.org/ip/"


def query_rdap_ip(ip):
    try:
        url = f"{RDAP_BOOTSTRAP_URL}{ip}"
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return None
        data = resp.json()
        name = data.get("name", "")
        handle = data.get("handle", "")
        country = ""
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                pass
        for attr in data.get("entities", []):
            roles = attr.get("roles", [])
            if "registrant" in roles or "technical" in roles:
                vcards = attr.get("vcardArray", [])
                if len(vcards) > 1:
                    for item in vcards[1]:
                        if item[0] == "fn":
                            name = item[3]
                        if item[0] == "adr":
                            pass
        remarks = data.get("remarks", [])
        description = ""
        for remark in remarks:
            if remark.get("title") == "Network Information":
                for desc in remark.get("description", []):
                    description = desc

        return {
            "ip": ip,
            "name": name,
            "handle": handle,
            "country": country,
            "description": description,
            "cidr": _extract_cidr(data),
            "parent_handle": data.get("parentHandle", ""),
            "source": "rdap",
        }
    except Exception:
        return None


def _extract_cidr(data):
    cidrs = data.get("cidr0_cidrs", [])
    if cidrs:
        return cidrs[0] if isinstance(cidrs[0], str) else str(cidrs[0])
    start = data.get("startAddress", "")
    end = data.get("endAddress", "")
    if start and end:
        return f"{start} - {end}"
    return ""


def query_rdap_asn(asn):
    try:
        asn_num = asn.replace("AS", "").replace("as", "")
        url = f"https://rdap.org/autnum/{asn_num}"
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return None
        data = resp.json()
        return {
            "asn": asn,
            "name": data.get("name", ""),
            "handle": data.get("handle", ""),
            "country": data.get("country", ""),
            "source": "rdap",
        }
    except Exception:
        return None


def batch_lookup_ips(ips):
    results = {}
    for ip in ips[:30]:
        try:
            ipaddress.ip_address(ip)
            result = query_rdap_ip(ip)
            if result:
                results[ip] = result
        except ValueError:
            pass
    return results
