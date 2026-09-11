import dns.resolver
import dns.query
import dns.zone
import dns.rdatatype
from src.dns_utils import resolve_ns


def attempt_zone_transfer(domain, nameserver=None):
    results = {
        "domain": domain,
        "nameservers": [],
        "zone_transfer_allowed": False,
        "records": [],
        "errors": [],
    }

    if nameserver:
        nameservers = [nameserver]
    else:
        nameservers = resolve_ns(domain)
        if not nameservers:
            results["errors"].append("No nameservers found")
            return results

    results["nameservers"] = nameservers

    for ns in nameservers:
        try:
            ns_ip = _resolve_ns_ip(ns)
            if not ns_ip:
                results["errors"].append(f"Could not resolve NS IP for {ns}")
                continue

            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, lifetime=15),
                    relativize=False,
                )
                results["zone_transfer_allowed"] = True

                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            record_type = dns.rdatatype.to_text(rdataset.rdtype)
                            record_data = str(rdata)
                            if record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
                                results["records"].append({
                                    "name": str(name).rstrip("."),
                                    "type": record_type,
                                    "data": record_data.rstrip("."),
                                    "nameserver": ns,
                                    "source": "zone_transfer",
                                })
                break
            except dns.query.TransferError:
                results["errors"].append(f"Zone transfer refused by {ns}")
            except Exception as e:
                results["errors"].append(f"Zone transfer failed for {ns}: {str(e)[:100]}")

        except Exception as e:
            results["errors"].append(f"Error querying {ns}: {str(e)[:100]}")

    return results


def _resolve_ns_ip(nameserver):
    try:
        answers = dns.resolver.resolve(nameserver, "A")
        return str(list(answers)[0])
    except Exception:
        try:
            import socket
            return socket.gethostbyname(nameserver)
        except Exception:
            return None


def extract_ips_from_zone(zone_results):
    ips = set()
    for record in zone_results.get("records", []):
        if record["type"] in ("A",):
            ips.add(record["data"])
        elif record["type"] in ("AAAA",):
            ips.add(record["data"])
    return sorted(ips)


def extract_subdomains_from_zone(zone_results, domain):
    subdomains = set()
    for record in zone_results.get("records", []):
        name = record.get("name", "")
        if name and domain in name:
            fqdn = f"{name}.{domain}" if not name.endswith(domain) else name
            subdomains.add(fqdn)
    return sorted(subdomains)
