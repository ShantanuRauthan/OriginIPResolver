import json


def format_results(origin_results, osint_results, cert_data=None):
    lines = []
    lines.append("=" * 70)
    lines.append("  ORIGIN IP RESOLVER - OSINT RECONNAISSANCE TOOL")
    lines.append("=" * 70)
    lines.append(f"  Target: {origin_results['domain']}")
    lines.append("=" * 70)
    lines.append("")

    cdn = osint_results.get("cdn", []) or origin_results.get("cdn_providers", [])
    if cdn:
        lines.append("[!] CDN DETECTED:")
        for p in cdn:
            lines.append(f"    -> {p}")
        lines.append("")

    cname_chain = origin_results.get("cname_chain", [])
    if len(cname_chain) > 1:
        lines.append("[+] CNAME CHAIN:")
        for i, cname in enumerate(cname_chain):
            prefix = " └─ " if i == len(cname_chain) - 1 else " ├─ "
            lines.append(f"    {prefix}{cname}")
        lines.append("")

    lines.append("[+] DNS RECORDS:")
    dns = osint_results.get("dns", {})
    for rtype in ["a", "aaaa", "cname", "ns", "mx"]:
        records = dns.get(rtype, [])
        if records:
            lines.append(f"    {rtype.upper()}:")
            for r in records:
                if isinstance(r, tuple):
                    lines.append(f"      - {r[0]} (priority: {r[1]})")
                else:
                    lines.append(f"      - {r}")

    if dns.get("txt"):
        lines.append("    TXT:")
        for r in dns["txt"]:
            lines.append(f"      - {r[:120]}")

    if dns.get("ptr"):
        lines.append("    PTR (Reverse DNS):")
        for ip, hostnames in dns["ptr"].items():
            for h in hostnames:
                lines.append(f"      - {ip} -> {h}")
    lines.append("")

    origin_candidates = origin_results.get("origin_candidates", [])
    non_cdn_origins = [c for c in origin_candidates if not c.get("cdn")]
    cdn_origins = [c for c in origin_candidates if c.get("cdn")]
    cname_only = [c for c in origin_candidates if c["ip"] is None and c.get("cname")]

    if non_cdn_origins:
        lines.append("[!] POTENTIAL ORIGIN IPs (Non-CDN):")
        seen = set()
        for c in sorted(non_cdn_origins, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["confidence"], 3)):
            if c["ip"] is None:
                continue
            if c["ip"] in seen:
                continue
            seen.add(c["ip"])
            host_str = f" ({c['hostname']})" if c["hostname"] else ""
            lines.append(f"    IP: {c['ip']}{host_str}")
            lines.append(f"    Source: {c['source']} | Confidence: {c['confidence'].upper()}")
            lines.append("")

    if cname_only:
        lines.append("[!] CNAME-Only Resolutions (No Direct IP):")
        for c in cname_only:
            lines.append(f"    {c['hostname']} -> {c['cname']}")
        lines.append("")

    if cdn_origins:
        lines.append("[+] CDN IPs (Behind CDN, Not Origin):")
        seen = set()
        for c in cdn_origins:
            if c["ip"] is None:
                continue
            if c["ip"] in seen:
                continue
            seen.add(c["ip"])
            lines.append(f"    IP: {c['ip']} ({c.get('cdn', 'Unknown CDN')})")
        lines.append("")

    subdomains = origin_results.get("subdomains", {})
    if subdomains:
        lines.append("[+] DISCOVERED SUBDOMAINS:")
        for sub, info in sorted(subdomains.items()):
            parts = []
            ips = info.get("ips", [])
            cname = info.get("cname")
            if ips:
                parts.append(f"IPs: {', '.join(ips)}")
            if cname:
                parts.append(f"CNAME: {cname}")
            if parts:
                lines.append(f"    {sub} -> {' | '.join(parts)}")
        lines.append("")

    ssl = osint_results.get("ssl")
    if ssl:
        lines.append("[+] SSL/TLS CERTIFICATE:")
        subject = ssl.get("subject", {})
        issuer = ssl.get("issuer", {})
        lines.append(f"    Subject CN: {subject.get('CN', 'N/A')}")
        lines.append(f"    Issuer: {issuer.get('O', 'N/A')} ({issuer.get('CN', 'N/A')})")
        lines.append(f"    Valid: {ssl.get('not_before', 'N/A')} -> {ssl.get('not_after', 'N/A')}")
        lines.append(f"    Expired: {ssl.get('is_expired', 'N/A')}")
        lines.append(f"    Signature Algorithm: {ssl.get('signature_algorithm', 'N/A')}")
        lines.append(f"    Serial: {ssl.get('serial_number', 'N/A')}")
        san = ssl.get("san", [])
        if san:
            lines.append(f"    SANs ({len(san)} entries):")
            for name in san[:15]:
                lines.append(f"      - {name}")
            if len(san) > 15:
                lines.append(f"      ... and {len(san) - 15} more")
        lines.append("")

    http = osint_results.get("http")
    if http:
        lines.append("[+] HTTP RESPONSE:")
        lines.append(f"    Status Code: {http['status_code']}")
        lines.append(f"    Final URL: {http['final_url']}")
        lines.append("")

        tech = osint_results.get("technologies", [])
        if tech:
            lines.append("[+] TECHNOLOGY FINGERPRINT:")
            for t in tech:
                lines.append(f"    - {t}")
            lines.append("")

    lines.append("=" * 70)
    lines.append("  Scan Complete")
    lines.append("=" * 70)

    return "\n".join(lines)


def output_json(origin_results, osint_results, cert_data=None):
    output = {
        "domain": origin_results["domain"],
        "cdn_providers": osint_results.get("cdn", []) or origin_results.get("cdn_providers", []),
        "cname_chain": origin_results.get("cname_chain", []),
        "dns_records": osint_results.get("dns", {}),
        "origin_candidates": origin_results.get("origin_candidates", []),
        "subdomains": origin_results.get("subdomains", {}),
        "ssl_certificate": osint_results.get("ssl"),
        "http_response": osint_results.get("http"),
        "technologies": osint_results.get("technologies", []),
    }
    return json.dumps(output, indent=2, default=str)
