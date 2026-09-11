import ipaddress
from src.dns_utils import resolve_a, resolve_aaaa, resolve_cname, resolve_ns, resolve_ptr
from src.crtsh import fetch_certificates, extract_subdomains, extract_ips_from_certificates
from src.cdn_detector import detect_all as detect_cdn
from src.subdomain_enum import enumerate_subdomains
from src.historical_dns import extract_historical_ips
from src.config import CDN_RANGES


def is_cdn_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for provider, ranges in CDN_RANGES.items():
            for cidr in ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return provider
    except ValueError:
        pass
    return None


def find_origin_ips(domain, use_crtsh=True, use_subenum=True, use_historical=True,
                    use_wayback=True, use_doh=True, use_zone_transfer=True,
                    use_securitytrails=True, use_virustotal=True):
    results = {
        "domain": domain,
        "cdn_providers": [],
        "origin_candidates": [],
        "subdomains": {},
        "cname_chain": [],
        "historical_records": [],
        "wayback_records": [],
        "doh_records": {},
        "zone_transfer": {},
        "securitytrails_subdomains": [],
        "virustotal_subdomains": [],
    }

    a_records = resolve_a(domain)
    aaaa_records = resolve_aaaa(domain)
    cname_records = resolve_cname(domain)
    ns_records = resolve_ns(domain)

    results["dns"] = {
        "a": a_records,
        "aaaa": aaaa_records,
        "cname": cname_records,
        "ns": ns_records,
    }

    all_resolved_ips = list(set(a_records + aaaa_records))
    cdn_providers = detect_cdn(all_resolved_ips, cname_records, {})
    results["cdn_providers"] = cdn_providers

    cname_chain = [domain]
    current = domain
    for _ in range(10):
        cnames = resolve_cname(current)
        if cnames:
            cname_chain.append(cnames[0])
            current = cnames[0]
        else:
            break
    results["cname_chain"] = cname_chain

    if cname_records and not cdn_providers:
        results["origin_candidates"].append({
            "ip": None,
            "source": "cname_chain",
            "hostname": cname_records[0],
            "confidence": "medium",
        })

    cert_data = None
    if use_crtsh:
        try:
            certs = fetch_certificates(domain)
            crt_info = extract_subdomains(certs, domain)
            crt_ips = extract_ips_from_certificates(certs)
            for ip in crt_ips:
                results["origin_candidates"].append({
                    "ip": ip,
                    "source": "certificate_transparency",
                    "hostname": None,
                    "confidence": "medium",
                })
            cert_data = {
                "subdomains": crt_info,
                "ips": crt_ips,
            }
        except Exception:
            pass

    if use_subenum:
        try:
            enum_results = enumerate_subdomains(domain)
            a_results = enum_results.get("a", {})
            cname_results = enum_results.get("cname", {})

            all_subs = set(list(a_results.keys()) + list(cname_results.keys()))
            for sub in sorted(all_subs):
                ips = a_results.get(sub, [])
                cnames = cname_results.get(sub, [])

                results["subdomains"][sub] = {
                    "ips": ips,
                    "cname": cnames[0] if cnames else None,
                }

                for ip in ips:
                    cdn_provider = is_cdn_ip(ip)
                    entry = {
                        "ip": ip,
                        "source": f"subdomain_enumeration:{sub}",
                        "hostname": sub,
                        "confidence": "high" if not cdn_provider else "low",
                    }
                    if cdn_provider:
                        entry["cdn"] = cdn_provider
                    results["origin_candidates"].append(entry)

                if cnames and not ips:
                    results["origin_candidates"].append({
                        "ip": None,
                        "source": f"subdomain_enumeration:{sub}",
                        "hostname": sub,
                        "cname": cnames[0],
                        "confidence": "low",
                    })
        except Exception:
            pass

    if use_wayback:
        try:
            from src.wayback_machine import extract_historical_subdomains_from_wayback
            wayback_subs = extract_historical_subdomains_from_wayback(domain)
            results["wayback_records"] = wayback_subs
            for sub in wayback_subs:
                if sub not in results["subdomains"]:
                    ips = resolve_a(sub)
                    if ips:
                        results["subdomains"][sub] = {"ips": ips, "cname": None}
                        for ip in ips:
                            cdn_provider = is_cdn_ip(ip)
                            results["origin_candidates"].append({
                                "ip": ip,
                                "source": f"wayback_machine:{sub}",
                                "hostname": sub,
                                "confidence": "high" if not cdn_provider else "low",
                            })
        except Exception:
            pass

    if use_doh:
        try:
            from src.doh_resolver import resolve_all_doh
            doh_results = resolve_all_doh(domain)
            results["doh_records"] = doh_results
            for rtype, providers in doh_results.items():
                for provider, answers in providers.items():
                    if rtype == "A":
                        for ip in answers:
                            if ip not in all_resolved_ips:
                                all_resolved_ips.append(ip)
                                cdn_provider = is_cdn_ip(ip)
                                results["origin_candidates"].append({
                                    "ip": ip,
                                    "source": f"doh:{provider}",
                                    "hostname": domain,
                                    "confidence": "high" if not cdn_provider else "medium",
                                })
        except Exception:
            pass

    if use_zone_transfer:
        try:
            from src.dns_zone_transfer import attempt_zone_transfer, extract_ips_from_zone, extract_subdomains_from_zone
            zone_results = attempt_zone_transfer(domain)
            results["zone_transfer"] = zone_results
            zone_ips = extract_ips_from_zone(zone_results)
            zone_subs = extract_subdomains_from_zone(zone_results, domain)
            for ip in zone_ips:
                cdn_provider = is_cdn_ip(ip)
                results["origin_candidates"].append({
                    "ip": ip,
                    "source": "zone_transfer",
                    "hostname": domain,
                    "confidence": "high" if not cdn_provider else "low",
                })
            for sub in zone_subs:
                if sub not in results["subdomains"]:
                    ips = resolve_a(sub)
                    if ips:
                        results["subdomains"][sub] = {"ips": ips, "cname": None}
        except Exception:
            pass

    if use_securitytrails:
        try:
            from src.securitytrails import get_subdomains
            st_subs = get_subdomains(domain)
            results["securitytrails_subdomains"] = st_subs
            for sub in st_subs:
                if sub not in results["subdomains"]:
                    ips = resolve_a(sub)
                    if ips:
                        results["subdomains"][sub] = {"ips": ips, "cname": None}
                        for ip in ips:
                            cdn_provider = is_cdn_ip(ip)
                            results["origin_candidates"].append({
                                "ip": ip,
                                "source": f"securitytrails:{sub}",
                                "hostname": sub,
                                "confidence": "high" if not cdn_provider else "low",
                            })
        except Exception:
            pass

    if use_virustotal:
        try:
            from src.virustotal import get_subdomains
            vt_subs = get_subdomains(domain)
            results["virustotal_subdomains"] = vt_subs
            for sub in vt_subs:
                if sub not in results["subdomains"]:
                    ips = resolve_a(sub)
                    if ips:
                        results["subdomains"][sub] = {"ips": ips, "cname": None}
                        for ip in ips:
                            cdn_provider = is_cdn_ip(ip)
                            results["origin_candidates"].append({
                                "ip": ip,
                                "source": f"virustotal:{sub}",
                                "hostname": sub,
                                "confidence": "high" if not cdn_provider else "low",
                            })
        except Exception:
            pass

    for ip in all_resolved_ips:
        cdn_provider = is_cdn_ip(ip)
        ptr_records = resolve_ptr(ip)
        entry = {
            "ip": ip,
            "source": "direct_dns_resolution",
            "hostname": ptr_records[0] if ptr_records else None,
            "confidence": "high" if not cdn_provider else "low",
        }
        if cdn_provider:
            entry["cdn"] = cdn_provider
        results["origin_candidates"].append(entry)

    if use_historical:
        try:
            historical_records = extract_historical_ips(domain)
            results["historical_records"] = historical_records
            seen_historical_ips = set()
            for r in historical_records:
                ip = r["ip"]
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if ip in seen_historical_ips:
                    continue
                seen_historical_ips.add(ip)
                cdn_provider = is_cdn_ip(ip)
                if not cdn_provider:
                    results["origin_candidates"].append({
                        "ip": ip,
                        "source": f"historical_dns:{r['source']}",
                        "hostname": r["hostname"],
                        "confidence": "medium",
                    })
        except Exception:
            pass

    return results, cert_data
