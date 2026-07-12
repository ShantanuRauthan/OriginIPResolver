import socket
import ipaddress
from src.config import CDN_RANGES, CDN_HEADERS, CDN_CNAME_PATTERNS


def _ip_in_cdn_ranges(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for provider, ranges in CDN_RANGES.items():
            for cidr in ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return provider
    except ValueError:
        pass
    return None


def detect_by_ip(ips):
    results = set()
    for ip in ips:
        provider = _ip_in_cdn_ranges(ip)
        if provider:
            results.add(provider)
    return list(results)


def detect_by_cname(cname_records):
    for cname in cname_records:
        cname_lower = cname.lower()
        for provider, patterns in CDN_CNAME_PATTERNS.items():
            for pattern in patterns:
                if pattern in cname_lower:
                    return provider
    return None


def detect_by_headers(headers):
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for header, provider in CDN_HEADERS.items():
        if header.lower() in headers_lower:
            return provider
    return None


def detect_by_server_header(headers):
    server = headers.get("Server", "") or headers.get("server", "")
    if not server:
        return None
    server_lower = server.lower()
    if "cloudflare" in server_lower:
        return "Cloudflare"
    if "akamai" in server_lower:
        return "Akamai"
    if "cloudfront" in server_lower:
        return "CloudFront"
    if "fastly" in server_lower:
        return "Fastly"
    return None


def detect_all(ips, cname_records, headers):
    providers = set()

    ip_providers = detect_by_ip(ips)
    providers.update(ip_providers)

    cname_provider = detect_by_cname(cname_records)
    if cname_provider:
        providers.add(cname_provider)

    header_provider = detect_by_headers(headers)
    if header_provider:
        providers.add(header_provider)

    server_provider = detect_by_server_header(headers)
    if server_provider:
        providers.add(server_provider)

    return list(providers)
