"""Find this computer's private (LAN / Wi-Fi) IPv4 addresses.

CapShare binds only to a private address plus loopback - never to 0.0.0.0 - and the
API additionally refuses any client whose address is not private/loopback/link-local.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess


_PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def is_lan_address(text: str) -> bool:
    """True for loopback, link-local and RFC1918/ULA addresses; False for public ones."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local:
        return True
    # Explicit private ranges only (ipaddress.is_private also covers documentation and
    # other reserved blocks, which are not "my Wi-Fi").
    return any(ip in net for net in _PRIVATE_NETWORKS if net.version == ip.version)


def private_ipv4_addresses() -> list[str]:
    found: list[str] = []

    def add(addr: str) -> None:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return
        if ip.version == 4 and is_lan_address(addr) and not ip.is_loopback \
                and not ip.is_link_local and addr not in found:
            found.append(addr)

    # 1. "which interface would be used to reach a private network?" (no packet is sent)
    for probe in ("192.168.255.255", "10.255.255.255", "172.31.255.255"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                add(s.getsockname()[0])
        except OSError:
            pass
    # 2. Linux: ask `ip` for every IPv4 address (covers VMs with several adapters)
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True,
                                 text=True, timeout=3).stdout
            for match in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/", out):
                add(match.group(1))
        except (OSError, subprocess.TimeoutExpired):
            pass
    # 3. fallback: whatever the hostname resolves to
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except OSError:
        pass
    return found
