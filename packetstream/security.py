"""
Security validation module for PacketStream exit node.
Replicates github.com/packetstream/ecosystem/exit-node/core/security:
- BlockLocalAccess: rejects private/loopback/link-local/carrier-grade NAT IP ranges
- Rejects reserved and local TLDs (localhost, .local, .internal, .lan, .corp, etc.)
- Prevents DNS rebinding by resolving and validating target IP before connection
"""

import asyncio
import ipaddress
import logging
import socket
from typing import List, Tuple

logger = logging.getLogger("packetstream.security")

# Reserved / Local hostnames and TLDs
RESERVED_HOSTS = {
    "localhost",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
}

BLOCKED_TLDS = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".onion",
    ".arpa",
    ".test",
    ".example",
    ".invalid",
)

# Additional subnets to block (beyond standard ipaddress.is_private)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("10.0.0.0/8"),        # Private-Use
    ipaddress.ip_network("100.64.0.0/10"),     # Shared Address Space (Carrier NAT)
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link Local
    ipaddress.ip_network("172.16.0.0/12"),     # Private-Use
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),    # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),    # Private-Use
    ipaddress.ip_network("198.18.0.0/15"),     # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"),# Limited Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("fc00::/7"),          # Unique Local
    ipaddress.ip_network("fe80::/10"),         # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),          # Multicast
]


class SecurityError(Exception):
    """Raised when an outbound proxy destination violates local access security rules."""
    pass


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks if an IP address belongs to any blocked / private / loopback range."""
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True

    return False


def validate_hostname(host: str) -> None:
    """Validates destination hostname against reserved hostnames and local TLDs."""
    host_clean = host.strip().lower().rstrip(".")
    if not host_clean:
        raise SecurityError("Target host is empty")

    if host_clean in RESERVED_HOSTS:
        raise SecurityError(f"Reserved hostname '{host}' is not allowed")

    for tld in BLOCKED_TLDS:
        if host_clean.endswith(tld):
            raise SecurityError(f"Local TLD in '{host}' is not allowed")


async def resolve_and_validate_destination(
    host: str,
    port: int
) -> List[Tuple[int, int, int, str, Tuple[str, int]]]:
    """
    Validates destination hostname and resolves DNS, ensuring none of the resolved IPs
    point to private/loopback/link-local subnets (prevents SSRF and local LAN penetration).

    Returns:
        List of safe addrinfo entries suitable for socket connection.
    """
    validate_hostname(host)

    # Check if host is already an IP address literal
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if is_ip_blocked(ip):
            raise SecurityError(f"Direct connection to private/reserved IP {ip} is blocked")
        # Direct IP literal is safe
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (str(ip), port))]
    except ValueError:
        # Not an IP literal, proceed to DNS resolution
        pass

    loop = asyncio.get_running_loop()
    try:
        addr_infos = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as e:
        raise SecurityError(f"DNS resolution failed for '{host}': {e}")

    safe_addrs = []
    for family, socktype, proto, canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip):
                logger.warning(f"Blocking resolved private/reserved IP {ip} for host '{host}'")
                continue
            safe_addrs.append((family, socktype, proto, canonname, sockaddr))
        except ValueError:
            continue

    if not safe_addrs:
        raise SecurityError(f"All resolved IP addresses for '{host}' are private or reserved")

    return safe_addrs
