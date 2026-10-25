"""IP helpers: turn a client IP into the list entry we approve, and match IPs against entries.

IPv4 addresses are approved one at a time. IPv6 clients rotate through addresses inside their
household's /64 every few hours, so an IPv6 address is approved as its whole /64 (configurable).
"""
import ipaddress


def entry_for(ip: str, ipv6_prefix: int = 64) -> str:
    """Canonical list entry for a client IP: '1.2.3.4' or '2001:db8:1:2::/64'."""
    addr = ipaddress.ip_address(ip.strip())
    if addr.version == 4:
        return str(addr)
    return str(ipaddress.ip_network(f"{addr}/{ipv6_prefix}", strict=False))


def normalize_entry(entry: str) -> str:
    """Normalize a list entry the way Cloudflare stores it (single IPv4 without /32, compressed IPv6)."""
    entry = entry.strip()
    if "/" not in entry:
        return str(ipaddress.ip_address(entry))
    net = ipaddress.ip_network(entry, strict=False)
    if net.version == 4 and net.prefixlen == 32:
        return str(net.network_address)
    if net.version == 6 and net.prefixlen == 128:
        return str(net.network_address)
    return str(net)


def network(entry: str):
    return ipaddress.ip_network(entry, strict=False)


class EntryMatcher:
    """Finds which allowlist entry (if any) covers a given IP."""

    def __init__(self, entries):
        self._exact = {}
        self._nets = []
        for e in entries:
            n = network(e)
            if n.num_addresses == 1:
                self._exact[str(n.network_address)] = e
            else:
                self._nets.append((n, e))

    def match(self, ip: str):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        hit = self._exact.get(str(addr))
        if hit:
            return hit
        for n, e in self._nets:
            if addr.version == n.version and addr in n:
                return e
        return None
