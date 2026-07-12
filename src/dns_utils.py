import socket
import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor, as_completed


def resolve_a(domain, nameserver=None):
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        answers = resolver.resolve(domain, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


def resolve_aaaa(domain, nameserver=None):
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        answers = resolver.resolve(domain, "AAAA")
        return [str(r) for r in answers]
    except Exception:
        return []


def resolve_cname(domain, nameserver=None):
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        answers = resolver.resolve(domain, "CNAME")
        return [str(r).rstrip(".") for r in answers]
    except Exception:
        return []


def resolve_ns(domain):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, "NS")
        return [str(r).rstrip(".") for r in answers]
    except Exception:
        return []


def resolve_mx(domain):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, "MX")
        return [(str(r.exchange).rstrip("."), r.preference) for r in answers]
    except Exception:
        return []


def resolve_txt(domain):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, "TXT")
        return [" ".join(r.strings) for r in answers]
    except Exception:
        return []


def resolve_ptr(ip):
    try:
        addr = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(addr, "PTR")
        return [str(r).rstrip(".") for r in answers]
    except Exception:
        return []


def reverse_dns_lookup(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except Exception:
        return None


def bulk_resolve(domains, record_type="A", max_workers=20):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        if record_type == "A":
            future_map = {executor.submit(resolve_a, d): d for d in domains}
        elif record_type == "CNAME":
            future_map = {executor.submit(resolve_cname, d): d for d in domains}
        else:
            return results
        for future in as_completed(future_map):
            domain = future_map[future]
            try:
                results[domain] = future.result()
            except Exception:
                results[domain] = []
    return results
