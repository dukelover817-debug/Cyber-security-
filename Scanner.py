# scanner.py
import socket
from typing import List, Dict

def parse_ports(ports_spec):
    if not ports_spec:
        return list(range(1, 1025))
    if isinstance(ports_spec, list):
        return ports_spec
    if isinstance(ports_spec, str) and '-' in ports_spec:
        start, end = ports_spec.split('-',1)
        return list(range(int(start), int(end)+1))
    # single port as string/number
    return [int(ports_spec)]

def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

def scan_ports(host: str, ports_spec=None) -> Dict:
    ports = parse_ports(ports_spec)
    open_ports = []
    for p in ports:
        if scan_port(host, p):
            open_ports.append(p)
    return {"host": host, "open_ports": open_ports, "count": len(open_ports)}
