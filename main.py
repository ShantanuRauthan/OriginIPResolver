#!/usr/bin/env python3
import sys
import argparse
import warnings
import urllib3
warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from src.origin_finder import find_origin_ips
from src.osint_gatherer import gather_osint
from src.output import format_results, output_json
from src.config import COMMON_SCAN_PORTS


def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start.strip()), int(end.strip()) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Origin IP Resolver - OSINT Tool for finding origin IPs behind CDNs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --json -o results.json
  python main.py example.com --no-subenum --no-crtsh --no-historical
  python main.py example.com --verbose --no-ssl
  python main.py example.com --ports 22,80,443,8080
  python main.py example.com --no-portscan
  python main.py example.com --all-api
  python main.py example.com --shodan --censys --virustotal
        """,
    )
    parser.add_argument("domain", help="Target domain or subdomain")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--no-crtsh", action="store_true", help="Skip certificate transparency lookup")
    parser.add_argument("--no-subenum", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--no-historical", action="store_true", help="Skip historical DNS lookup")
    parser.add_argument("--no-portscan", action="store_true", help="Skip port scanning")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL certificate analysis")
    parser.add_argument("--no-wayback", action="store_true", help="Skip Wayback Machine lookup")
    parser.add_argument("--no-doh", action="store_true", help="Skip DNS over HTTPS")
    parser.add_argument("--no-zonetransfer", action="store_true", help="Skip DNS zone transfer attempt")
    parser.add_argument("--shodan", action="store_true", help="Enable Shodan API lookups (requires SHODAN_API_KEY)")
    parser.add_argument("--censys", action="store_true", help="Enable Censys API lookups (requires CENSYS_API_ID + CENSYS_API_SECRET)")
    parser.add_argument("--securitytrails", action="store_true", help="Enable SecurityTrails API (requires SECURITYTRAILS_API_KEY)")
    parser.add_argument("--virustotal", action="store_true", help="Enable VirusTotal API (requires VIRUSTOTAL_API_KEY)")
    parser.add_argument("--all-api", action="store_true", help="Enable all API-based modules")
    parser.add_argument("--ports", help="Comma-separated ports or ranges to scan (e.g. 22,80,443,8000-8100)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return parser.parse_args()


def main():
    args = parse_args()
    domain = args.domain.lower().strip()

    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    if not args.verbose:
        import logging
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    print(f"[*] Target: {domain}", file=sys.stderr)
    print("[*] Resolving origin IP and gathering OSINT...\n", file=sys.stderr)

    use_shodan = args.shodan or args.all_api
    use_censys = args.censys or args.all_api
    use_securitytrails = args.securitytrails or args.all_api
    use_virustotal = args.virustotal or args.all_api

    if use_shodan:
        print("[*] Shodan API: enabled", file=sys.stderr)
    if use_censys:
        print("[*] Censys API: enabled", file=sys.stderr)
    if use_securitytrails:
        print("[*] SecurityTrails API: enabled", file=sys.stderr)
    if use_virustotal:
        print("[*] VirusTotal API: enabled", file=sys.stderr)
    print("", file=sys.stderr)

    try:
        origin_results, cert_data = find_origin_ips(
            domain,
            use_crtsh=not args.no_crtsh,
            use_subenum=not args.no_subenum,
            use_historical=not args.no_historical,
            use_wayback=not args.no_wayback,
            use_doh=not args.no_doh,
            use_zone_transfer=not args.no_zonetransfer,
            use_securitytrails=use_securitytrails,
            use_virustotal=use_virustotal,
        )
    except Exception as e:
        print(f"[!] Error during origin IP resolution: {e}", file=sys.stderr)
        sys.exit(1)

    scan_ips_list = []
    non_cdn_candidates = [c for c in origin_results.get("origin_candidates", [])
                          if c.get("ip") and not c.get("cdn")]
    for c in non_cdn_candidates:
        ip = c["ip"]
        if ip and ip not in scan_ips_list:
            scan_ips_list.append(ip)

    custom_ports = None
    if args.ports:
        try:
            custom_ports = parse_ports(args.ports)
            print(f"[*] Using custom ports: {len(custom_ports)} ports to scan", file=sys.stderr)
        except ValueError as e:
            print(f"[!] Invalid port specification: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        osint_results = gather_osint(
            domain,
            ssl=not args.no_ssl,
            portscan=not args.no_portscan,
            scan_ports=custom_ports,
            scan_ips_list=scan_ips_list if not args.no_portscan else None,
            use_rdap=True,
            use_shodan=use_shodan,
            use_censys=use_censys,
        )
    except Exception as e:
        print(f"[!] Error during OSINT gathering: {e}", file=sys.stderr)
        osint_results = {"domain": domain, "dns": {}, "cdn": origin_results.get("cdn_providers", [])}

    if args.json:
        result = output_json(origin_results, osint_results, cert_data)
    else:
        result = format_results(origin_results, osint_results, cert_data)

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(result)
            print(f"[+] Results saved to {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"[!] Failed to save output: {e}", file=sys.stderr)

    print(result)


if __name__ == "__main__":
    main()
