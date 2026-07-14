import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.config import COMMON_SCAN_PORTS, SCAN_PORTS, WELL_KNOWN_PORTS, PORT_SCAN_TIMEOUT, PORT_SCAN_WORKERS


def _tcp_connect(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = WELL_KNOWN_PORTS.get(port, "unknown")
            banner = _grab_banner(sock, port, timeout)
            sock.close()
            return port, service, banner
        sock.close()
    except Exception:
        pass
    return None


def _grab_banner(sock, port, timeout):
    try:
        sock.settimeout(timeout)
        if port in {80, 443, 8080, 8443, 8000, 8008, 8888, 8090}:
            sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif port in {22}:
            sock.sendall(b"SSH-2.0-OpenSSH_Check\r\n")
        elif port in {21}:
            pass
        elif port in {25, 587, 465}:
            sock.sendall(b"EHLO check\r\n")
        elif port in {110, 995}:
            sock.sendall(b"USER check\r\n")
        elif port in {143, 993}:
            sock.sendall(b"a001 LOGIN check check\r\n")
        data = sock.recv(256)
        text = data.decode("utf-8", errors="ignore").strip()
        text = " ".join(text.split())[:200]
        return text if text else None
    except Exception:
        return None


def scan_ip(ip, ports=None, timeout=None, max_workers=None):
    if ports is None:
        ports = COMMON_SCAN_PORTS
    if timeout is None:
        timeout = PORT_SCAN_TIMEOUT
    if max_workers is None:
        max_workers = PORT_SCAN_WORKERS

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_tcp_connect, ip, p, timeout): p for p in ports}
        for future in as_completed(future_map):
            try:
                result = future.result()
                if result:
                    port, service, banner = result
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                    })
            except Exception:
                pass

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def scan_ips(ips, ports=None, timeout=None, max_workers=None):
    if ports is None:
        ports = COMMON_SCAN_PORTS
    if timeout is None:
        timeout = PORT_SCAN_TIMEOUT
    if max_workers is None:
        max_workers = PORT_SCAN_WORKERS

    results = {}
    for ip in ips:
        try:
            open_ports = scan_ip(ip, ports, timeout, max_workers)
            if open_ports:
                results[ip] = open_ports
        except Exception:
            pass

    return results
