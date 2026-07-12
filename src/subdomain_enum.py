from concurrent.futures import ThreadPoolExecutor, as_completed
from src.config import SUBDOMAIN_WORDLIST
from src.dns_utils import resolve_a, resolve_aaaa, resolve_cname


def generate_subdomain_list(domain, wordlist=None):
    if wordlist is None:
        wordlist = SUBDOMAIN_WORDLIST
    return [f"{sub}.{domain}" for sub in wordlist]


def enumerate_subdomains(domain, wordlist=None, max_workers=30):
    candidates = generate_subdomain_list(domain, wordlist)
    found = {"a": {}, "cname": {}}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        a_futures = {}
        cname_futures = {}
        for sub in candidates:
            a_futures[executor.submit(resolve_a, sub)] = sub
            a_futures[executor.submit(resolve_aaaa, sub)] = sub
            cname_futures[executor.submit(resolve_cname, sub)] = sub

        for future in as_completed(a_futures):
            sub = a_futures[future]
            try:
                result = future.result()
                if result:
                    if sub not in found["a"]:
                        found["a"][sub] = set()
                    found["a"][sub].update(result)
            except Exception:
                pass

        for future in as_completed(cname_futures):
            sub = cname_futures[future]
            try:
                result = future.result()
                if result:
                    found["cname"][sub] = result
            except Exception:
                pass

    return found
