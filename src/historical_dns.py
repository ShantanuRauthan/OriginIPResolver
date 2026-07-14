import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.config import HISTORICAL_DNS_SOURCES


def query_alienvault(domain):
    try:
        url = HISTORICAL_DNS_SOURCES["alienvault"].format(domain=domain)
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        records = data.get("passive_dns", []) if isinstance(data, dict) else data
        results = []
        for r in records:
            host = r.get("hostname", "")
            ip = r.get("address", "")
            record_type = r.get("record_type", "")
            first_seen = r.get("first_seen", "")
            last_seen = r.get("last_seen", "")
            if ip and host:
                results.append({
                    "ip": ip,
                    "hostname": host,
                    "record_type": record_type,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "source": "alienvault_otx",
                })
        return results
    except Exception:
        return []


def query_rapiddns(domain):
    try:
        url = HISTORICAL_DNS_SOURCES["rapiddns"].format(domain=domain)
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return []
        html = resp.text
        results = []
        table_match = re.search(r'<table[^>]+id="table"[^>]*>.*?<tbody>(.*?)</tbody>', html, re.DOTALL)
        if not table_match:
            return []
        tbody = table_match.group(1)
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', tbody, re.DOTALL)
        for row in rows:
            cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
            if len(cells) >= 3:
                host = re.sub(r'<[^>]+>', '', cells[0]).strip()
                ip = re.sub(r'<[^>]+>', '', cells[1]).strip()
                record_type = re.sub(r'<[^>]+>', '', cells[2]).strip()
            if ip and host and record_type in ("A", "AAAA", "CNAME"):
                results.append({
                    "ip": ip,
                    "hostname": host,
                    "record_type": record_type,
                    "first_seen": "",
                    "last_seen": "",
                    "source": "rapiddns",
                })
        return results
    except Exception:
        return []


def query_hackertarget(domain):
    try:
        url = HISTORICAL_DNS_SOURCES["hackertarget"].format(domain=domain)
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return []
        results = []
        for line in resp.text.strip().split("\n"):
            parts = line.split(",")
            if len(parts) == 2:
                host, ip = parts[0].strip(), parts[1].strip()
                if ip and host:
                    results.append({
                        "ip": ip,
                        "hostname": host,
                        "record_type": "A",
                        "first_seen": "",
                        "last_seen": "",
                        "source": "hackertarget",
                    })
        return results
    except Exception:
        return []


def query_all(domain, max_workers=5):
    all_results = []

    def query_source(source_name):
        if source_name == "alienvault":
            return query_alienvault(domain)
        elif source_name == "rapiddns":
            return query_rapiddns(domain)
        elif source_name == "hackertarget":
            return query_hackertarget(domain)
        return []

    sources = list(HISTORICAL_DNS_SOURCES.keys())
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(query_source, s): s for s in sources}
        for future in as_completed(future_map):
            source = future_map[future]
            try:
                results = future.result()
                all_results.extend(results)
            except Exception:
                pass

    seen = set()
    deduped = []
    for r in all_results:
        key = (r["ip"], r["hostname"], r["source"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped


def extract_historical_ips(domain, use_alienvault=True, use_rapiddns=True, use_hackertarget=True):
    results = query_all(domain)
    filtered = []
    for r in results:
        source = r["source"]
        if not use_alienvault and source == "alienvault_otx":
            continue
        if not use_rapiddns and source == "rapiddns":
            continue
        if not use_hackertarget and source == "hackertarget":
            continue
        filtered.append(r)
    return filtered
