import json
import ipaddress


def _is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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
            prefix = " \u2514\u2500 " if i == len(cname_chain) - 1 else " \u251c\u2500 "
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

    doh = origin_results.get("doh_records", {})
    if doh:
        lines.append("[+] DNS OVER HTTPS (Cross-validation):")
        for rtype, providers in doh.items():
            lines.append(f"    {rtype}:")
            for provider, answers in providers.items():
                for ans in answers:
                    if isinstance(ans, tuple):
                        lines.append(f"      - {ans[0]} (via {provider})")
                    else:
                        lines.append(f"      - {ans} (via {provider})")
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

    historical = origin_results.get("historical_records", [])
    if historical:
        lines.append("[+] HISTORICAL DNS RECORDS:")
        by_ip = {}
        for r in historical:
            if not _is_valid_ip(r["ip"]):
                continue
            ip = r["ip"]
            if ip not in by_ip:
                by_ip[ip] = {"sources": set(), "hostnames": set()}
            by_ip[ip]["sources"].add(r["source"])
            by_ip[ip]["hostnames"].add(r["hostname"])
        for ip, info in sorted(by_ip.items()):
            sources = ", ".join(sorted(info["sources"]))
            hostname = list(info["hostnames"])[0] if info["hostnames"] else ""
            lines.append(f"    IP: {ip} ({hostname}) [{sources}]")
        lines.append("")

    wayback = origin_results.get("wayback_records", [])
    if wayback:
        lines.append("[+] WAYBACK MACHINE SUBDOMAINS:")
        for sub in wayback[:30]:
            lines.append(f"    {sub}")
        if len(wayback) > 30:
            lines.append(f"    ... and {len(wayback) - 30} more")
        lines.append("")

    zone_transfer = origin_results.get("zone_transfer", {})
    if zone_transfer.get("zone_transfer_allowed"):
        lines.append("[!] ZONE TRANSFER SUCCESSFUL:")
        for record in zone_transfer.get("records", [])[:20]:
            lines.append(f"    {record['name']}.{origin_results['domain']} -> {record['type']}: {record['data']}")
        lines.append("")
    elif zone_transfer.get("errors"):
        lines.append("[+] ZONE TRANSFER:")
        for err in zone_transfer.get("errors", []):
            lines.append(f"    {err}")
        lines.append("")

    securitytrails_subs = origin_results.get("securitytrails_subdomains", [])
    virustotal_subs = origin_results.get("virustotal_subdomains", [])
    if securitytrails_subs or virustotal_subs:
        lines.append("[+] API SUBDOMAIN DISCOVERY:")
        if securitytrails_subs:
            lines.append(f"    SecurityTrails: {len(securitytrails_subs)} subdomains found")
            for sub in securitytrails_subs[:10]:
                lines.append(f"      - {sub}")
            if len(securitytrails_subs) > 10:
                lines.append(f"      ... and {len(securitytrails_subs) - 10} more")
        if virustotal_subs:
            lines.append(f"    VirusTotal: {len(virustotal_subs)} subdomains found")
            for sub in virustotal_subs[:10]:
                lines.append(f"      - {sub}")
            if len(virustotal_subs) > 10:
                lines.append(f"      ... and {len(virustotal_subs) - 10} more")
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

    rdap = osint_results.get("rdap", {})
    if rdap:
        lines.append("[+] RDAP / IP REGISTRY INFO:")
        for ip, info in sorted(rdap.items()):
            lines.append(f"    {ip}:")
            lines.append(f"      Owner: {info.get('name', 'N/A')}")
            lines.append(f"      Handle: {info.get('handle', 'N/A')}")
            lines.append(f"      CIDR: {info.get('cidr', 'N/A')}")
            lines.append(f"      Description: {info.get('description', 'N/A')}")
        lines.append("")

    shodan = osint_results.get("shodan", {})
    if shodan:
        lines.append("[+] SHODAN INTEL:")
        for ip, info in sorted(shodan.items()):
            lines.append(f"    {ip}:")
            lines.append(f"      Org: {info.get('org', 'N/A')}")
            lines.append(f"      ISP: {info.get('isp', 'N/A')}")
            lines.append(f"      OS: {info.get('os', 'N/A')}")
            lines.append(f"      Country: {info.get('country', 'N/A')}")
            open_ports = info.get("ports", [])
            if open_ports:
                lines.append(f"      Ports: {', '.join(map(str, open_ports[:20]))}")
            for svc in info.get("services", [])[:5]:
                product = svc.get("product", "")
                version = svc.get("version", "")
                banner = svc.get("banner", "")[:80]
                port = svc.get("port", "")
                svc_str = f"Port {port}: {product} {version}".strip()
                if banner:
                    svc_str += f" - {banner}"
                lines.append(f"        {svc_str}")
            vulns = info.get("vulns", [])
            if vulns:
                lines.append(f"      Vulns: {', '.join(vulns[:5])}")
        lines.append("")

    censys = osint_results.get("censys", [])
    if censys:
        lines.append("[+] CENSYS DATA:")
        for host in censys:
            ip = host.get("ip", "")
            lines.append(f"    {ip}:")
            as_info = host.get("autonomous_system", {})
            if as_info.get("asn"):
                lines.append(f"      ASN: {as_info.get('asn')} ({as_info.get('name', '')})")
            loc = host.get("location", {})
            if loc.get("country"):
                lines.append(f"      Location: {loc.get('city', '')}, {loc.get('country', '')}")
            for svc in host.get("services", [])[:5]:
                lines.append(f"      Port {svc.get('port')}: {svc.get('service_name', '')} ({svc.get('transport_protocol', '')})")
            if host.get("operating_system"):
                lines.append(f"      OS: {host.get('operating_system')}")
        lines.append("")

    port_scan = osint_results.get("port_scan", {})
    if port_scan:
        lines.append("[+] PORT SCAN RESULTS:")
        for ip, ports in sorted(port_scan.items()):
            lines.append(f"    {ip}:")
            for p in ports:
                banner_str = f" - {p['banner']}" if p.get("banner") else ""
                lines.append(f"      Port {p['port']:>5}/{p['service']}{banner_str}")
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
        "doh_records": origin_results.get("doh_records", {}),
        "historical_dns_records": origin_results.get("historical_records", []),
        "origin_candidates": origin_results.get("origin_candidates", []),
        "subdomains": origin_results.get("subdomains", {}),
        "wayback_subdomains": origin_results.get("wayback_records", []),
        "zone_transfer": origin_results.get("zone_transfer", {}),
        "securitytrails_subdomains": origin_results.get("securitytrails_subdomains", []),
        "virustotal_subdomains": origin_results.get("virustotal_subdomains", []),
        "ssl_certificate": osint_results.get("ssl"),
        "http_response": osint_results.get("http"),
        "technologies": osint_results.get("technologies", []),
        "rdap": osint_results.get("rdap", {}),
        "shodan": osint_results.get("shodan", {}),
        "censys": osint_results.get("censys", []),
        "port_scan": osint_results.get("port_scan", {}),
    }
    return json.dumps(output, indent=2, default=str)
