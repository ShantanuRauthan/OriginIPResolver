from src.dns_utils import resolve_a, resolve_aaaa, resolve_cname, resolve_ns, resolve_mx, resolve_txt, resolve_ptr
from src.http_analyzer import fetch_headers, get_ssl_certificate, detect_technologies
from src.cdn_detector import detect_all as detect_cdn
from src.port_scanner import scan_ips
from src.config import COMMON_SCAN_PORTS


def gather_osint(domain, ssl=True, portscan=True, scan_ports=None, scan_ips_list=None,
                 use_rdap=True, use_shodan=True, use_censys=True):
    result = {
        "domain": domain,
        "dns": {},
        "http": None,
        "ssl": None,
        "technologies": [],
        "cdn": [],
        "port_scan": {},
        "rdap": {},
        "shodan": {},
        "censys": [],
    }

    result["dns"]["a"] = resolve_a(domain)
    result["dns"]["aaaa"] = resolve_aaaa(domain)
    result["dns"]["cname"] = resolve_cname(domain)
    result["dns"]["ns"] = resolve_ns(domain)
    result["dns"]["mx"] = resolve_mx(domain)
    result["dns"]["txt"] = resolve_txt(domain)

    for ip in result["dns"]["a"]:
        ptr = resolve_ptr(ip)
        if ptr:
            if "ptr" not in result["dns"]:
                result["dns"]["ptr"] = {}
            result["dns"]["ptr"][ip] = ptr

    http_result = fetch_headers(f"https://{domain}")
    if http_result is None:
        http_result = fetch_headers(f"http://{domain}")

    if http_result:
        result["http"] = http_result
        result["technologies"] = detect_technologies(http_result["headers"])

        all_ips = list(set(result["dns"]["a"] + result["dns"]["aaaa"]))
        result["cdn"] = detect_cdn(
            all_ips,
            result["dns"]["cname"],
            http_result["headers"],
        )

    if ssl:
        ssl_info = get_ssl_certificate(domain)
        if ssl_info:
            result["ssl"] = ssl_info

    if use_rdap and scan_ips_list:
        try:
            from src.rdap_lookup import batch_lookup_ips
            result["rdap"] = batch_lookup_ips(scan_ips_list)
        except Exception:
            pass

    if use_shodan and scan_ips_list:
        try:
            from src.shodan_lookup import search_host
            for ip in scan_ips_list[:10]:
                shodan_info = search_host(ip)
                if shodan_info:
                    result["shodan"][ip] = shodan_info
        except Exception:
            pass

    if use_censys and scan_ips_list:
        try:
            from src.censys_lookup import get_host_details
            for ip in scan_ips_list[:10]:
                censys_info = get_host_details(ip)
                if censys_info:
                    result["censys"].append(censys_info)
        except Exception:
            pass

    if portscan and scan_ips_list:
        ports_to_scan = scan_ports if scan_ports else COMMON_SCAN_PORTS
        result["port_scan"] = scan_ips(scan_ips_list, ports=ports_to_scan)

    return result
