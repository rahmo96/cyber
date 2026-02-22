"""
Traffic Filter Module for NetGuard-CLI

Provides a composable, BPF-style filtering system for PacketInfo objects.
Filters can be combined with the & (AND), | (OR), and ~ (NOT) operators.

Example usage:

    # Accept only HTTP/HTTPS traffic from the 10.0.0.0/8 subnet
    f = IPRangeFilter("10.0.0.0/8") & ProtocolFilter("HTTP", "TLS")

    if f.matches(packet):
        process(packet)

    # Build programmatically from CLI args
    f = build_filter(ip_ranges=["192.168.0.0/16"], protocols=["DNS"])
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import ip_address, ip_network
from typing import List, Optional

from sniffer import PacketInfo


# ---------------------------------------------------------------------------
# Base class and boolean combinators
# ---------------------------------------------------------------------------

class TrafficFilter(ABC):
    """Abstract base class for all traffic filters."""

    @abstractmethod
    def matches(self, packet: PacketInfo) -> bool:
        """Return True if the packet passes this filter."""

    def __and__(self, other: TrafficFilter) -> _AndFilter:
        return _AndFilter(self, other)

    def __or__(self, other: TrafficFilter) -> _OrFilter:
        return _OrFilter(self, other)

    def __invert__(self) -> _NotFilter:
        return _NotFilter(self)


class _AndFilter(TrafficFilter):
    def __init__(self, left: TrafficFilter, right: TrafficFilter) -> None:
        self._left = left
        self._right = right

    def matches(self, packet: PacketInfo) -> bool:
        return self._left.matches(packet) and self._right.matches(packet)


class _OrFilter(TrafficFilter):
    def __init__(self, left: TrafficFilter, right: TrafficFilter) -> None:
        self._left = left
        self._right = right

    def matches(self, packet: PacketInfo) -> bool:
        return self._left.matches(packet) or self._right.matches(packet)


class _NotFilter(TrafficFilter):
    def __init__(self, inner: TrafficFilter) -> None:
        self._inner = inner

    def matches(self, packet: PacketInfo) -> bool:
        return not self._inner.matches(packet)


# ---------------------------------------------------------------------------
# Concrete filter implementations
# ---------------------------------------------------------------------------

class AcceptAllFilter(TrafficFilter):
    """Pass-through filter — accepts every packet."""

    def matches(self, packet: PacketInfo) -> bool:
        return True


class IPRangeFilter(TrafficFilter):
    """
    Accept packets whose source OR destination IP falls within any of the
    given CIDR ranges.

    Args:
        *cidr_ranges:   One or more CIDR strings, e.g. "192.168.0.0/16".
        match_source:   Check the source IP (default True).
        match_dest:     Check the destination IP (default True).
    """

    def __init__(
        self,
        *cidr_ranges: str,
        match_source: bool = True,
        match_dest: bool = True,
    ) -> None:
        self._networks = [ip_network(r, strict=False) for r in cidr_ranges]
        self._match_source = match_source
        self._match_dest = match_dest

    def matches(self, packet: PacketInfo) -> bool:
        try:
            src = ip_address(packet.source_ip)
            dst = ip_address(packet.dest_ip)
        except ValueError:
            return False

        for net in self._networks:
            if self._match_source and src in net:
                return True
            if self._match_dest and dst in net:
                return True
        return False


class ProtocolFilter(TrafficFilter):
    """
    Accept packets whose transport protocol (TCP / UDP / Other) OR
    application-layer protocol (from DPI) matches any of the given values.
    Comparison is case-insensitive.

    Example:
        ProtocolFilter("HTTP", "TLS", "DNS")
    """

    def __init__(self, *protocols: str) -> None:
        self._protocols = {p.upper() for p in protocols}

    def matches(self, packet: PacketInfo) -> bool:
        if packet.protocol.upper() in self._protocols:
            return True
        app = getattr(packet, "app_protocol", "Unknown")
        if app.upper() in self._protocols:
            return True
        return False


class PortFilter(TrafficFilter):
    """
    Accept packets that involve any of the given port numbers (source or dest).
    """

    def __init__(self, *ports: int) -> None:
        self._ports = set(ports)

    def matches(self, packet: PacketInfo) -> bool:
        return (
            (packet.source_port is not None and packet.source_port in self._ports)
            or (packet.dest_port is not None and packet.dest_port in self._ports)
        )


class TimestampFilter(TrafficFilter):
    """
    Accept packets captured within a Unix-timestamp range (inclusive).

    Args:
        start:  Earliest allowed timestamp (or None for no lower bound).
        end:    Latest allowed timestamp  (or None for no upper bound).
    """

    def __init__(
        self,
        start: Optional[float] = None,
        end: Optional[float] = None,
    ) -> None:
        self._start = start
        self._end = end

    def matches(self, packet: PacketInfo) -> bool:
        if self._start is not None and packet.timestamp < self._start:
            return False
        if self._end is not None and packet.timestamp > self._end:
            return False
        return True


class MinSizeFilter(TrafficFilter):
    """Accept only packets whose payload is at least *min_bytes* bytes."""

    def __init__(self, min_bytes: int) -> None:
        self._min = min_bytes

    def matches(self, packet: PacketInfo) -> bool:
        return packet.payload_size >= self._min


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def build_filter(
    ip_ranges: Optional[List[str]] = None,
    protocols: Optional[List[str]] = None,
    ports: Optional[List[int]] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
) -> TrafficFilter:
    """
    Build a single AND-combined filter from optional individual criteria.

    Returns an AcceptAllFilter if no criteria are provided, so callers can
    always call ``f.matches(packet)`` without null-checks.

    Args:
        ip_ranges:   List of CIDR strings, e.g. ["10.0.0.0/8", "192.168.0.0/16"].
        protocols:   List of protocol names, e.g. ["HTTP", "DNS", "TLS"].
        ports:       List of port numbers, e.g. [80, 443, 8080].
        start_time:  Unix timestamp lower bound.
        end_time:    Unix timestamp upper bound.

    Returns:
        A TrafficFilter instance.
    """
    active: List[TrafficFilter] = []

    if ip_ranges:
        active.append(IPRangeFilter(*ip_ranges))
    if protocols:
        active.append(ProtocolFilter(*protocols))
    if ports:
        active.append(PortFilter(*ports))
    if start_time is not None or end_time is not None:
        active.append(TimestampFilter(start=start_time, end=end_time))

    if not active:
        return AcceptAllFilter()

    result: TrafficFilter = active[0]
    for f in active[1:]:
        result = result & f
    return result
