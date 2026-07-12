import requests
import ssl
import socket
import OpenSSL.crypto
from datetime import datetime
from src.config import USER_AGENTS


def fetch_headers(url, timeout=15):
    headers_to_try = [
        {"User-Agent": USER_AGENTS[0]},
        {"User-Agent": USER_AGENTS[1]},
        {"User-Agent": USER_AGENTS[2]},
    ]
    for attempt, headers in enumerate(headers_to_try):
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            resp.raise_for_status()
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "final_url": str(resp.url),
            }
        except requests.exceptions.RequestException:
            continue
    return None


def get_ssl_certificate(hostname, port=443, timeout=10):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1, der_cert
                )
                return _parse_cert(cert)
    except Exception:
        return None


def _parse_cert(cert):
    subject = dict(cert.get_subject().get_components())
    issuer = dict(cert.get_issuer().get_components())

    not_before = cert.get_notBefore().decode("utf-8")
    not_after = cert.get_notAfter().decode("utf-8")

    san_extracted = []
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            san_str = str(ext)
            for item in san_str.split(", "):
                if item.startswith("DNS:"):
                    san_extracted.append(item[4:])

    return {
        "subject": {k.decode(): v.decode() for k, v in subject.items()},
        "issuer": {k.decode(): v.decode() for k, v in issuer.items()},
        "serial_number": hex(cert.get_serial_number()),
        "version": cert.get_version(),
        "not_before": _parse_asn1_time(not_before),
        "not_after": _parse_asn1_time(not_after),
        "is_expired": datetime.now() > _parse_asn1_time(not_after),
        "san": san_extracted,
        "signature_algorithm": cert.get_signature_algorithm().decode("utf-8"),
    }


def _parse_asn1_time(asn1_time):
    fmt = "%Y%m%d%H%M%SZ"
    return datetime.strptime(asn1_time.decode() if isinstance(asn1_time, bytes) else asn1_time, fmt)


def detect_technologies(headers):
    tech = set()
    server = headers.get("Server", "")
    if server:
        tech.add(f"Server: {server}")

    x_powered = headers.get("X-Powered-By", "")
    if x_powered:
        tech.add(f"X-Powered-By: {x_powered}")

    cf_ray = headers.get("CF-Ray", "")
    if cf_ray:
        tech.add("Cloudflare")

    set_cookie = headers.get("Set-Cookie", "")
    if "PHPSESSID" in set_cookie:
        tech.add("PHP")
    if "JSESSIONID" in set_cookie:
        tech.add("Java/JSP")
    if "ASP.NET" in set_cookie or "ASPSESSIONID" in set_cookie:
        tech.add("ASP.NET")
    if "laravel_session" in set_cookie:
        tech.add("Laravel (PHP)")
    if "drupal" in set_cookie:
        tech.add("Drupal")

    return sorted(tech)
