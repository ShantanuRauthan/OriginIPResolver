import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


DOH_PROVIDERS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}


def resolve_doh(domain, record_type="A", provider="google"):
    try:
        url = DOH_PROVIDERS.get(provider, DOH_PROVIDERS["google"])
        params = {
            "name": domain,
            "type": record_type,
        }
        headers = {"Accept": "application/dns-json"}
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
        answers = data.get("Answer", [])
        results = []
        for answer in answers:
            rtype = answer.get("type", 0)
            rdata = answer.get("data", "")
            if rtype == 1 and record_type == "A":
                results.append(rdata)
            elif rtype == 28 and record_type == "AAAA":
                results.append(rdata)
            elif rtype == 5 and record_type == "CNAME":
                results.append(rdata.rstrip("."))
            elif rtype == 15 and record_type == "MX":
                parts = rdata.split(" ", 1)
                if len(parts) == 2:
                    results.append((parts[1].rstrip("."), int(parts[0])))
                else:
                    results.append((rdata.rstrip("."), 0))
            elif rtype == 16 and record_type == "TXT":
                results.append(rdata.strip('"'))
            elif rtype == 2 and record_type == "NS":
                results.append(rdata.rstrip("."))
            else:
                results.append(rdata)
        return results
    except Exception:
        return []


def resolve_all_doh(domain, record_types=None):
    if record_types is None:
        record_types = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]

    results = {}

    def resolve_for_provider(provider):
        provider_results = {}
        for rtype in record_types:
            answers = resolve_doh(domain, rtype, provider)
            if answers:
                provider_results[rtype] = answers
        return provider_results

    with ThreadPoolExecutor(max_workers=len(DOH_PROVIDERS)) as executor:
        future_map = {executor.submit(resolve_for_provider, p): p for p in DOH_PROVIDERS}
        for future in as_completed(future_map):
            provider = future_map[future]
            try:
                provider_results = future.result()
                for rtype, answers in provider_results.items():
                    if rtype not in results:
                        results[rtype] = {}
                    results[rtype][provider] = answers
            except Exception:
                pass

    return results


def cross_check_ips(domain):
    all_ips = set()
    for provider in DOH_PROVIDERS:
        ips = resolve_doh(domain, "A", provider)
        all_ips.update(ips)
    return sorted(all_ips)


def resolve_subdomain_doh(subdomain, record_type="A"):
    results = {}
    for provider in DOH_PROVIDERS:
        answers = resolve_doh(subdomain, record_type, provider)
        if answers:
            results[provider] = answers
    return results
