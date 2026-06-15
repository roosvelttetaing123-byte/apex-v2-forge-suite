"""Forge C2 — Transport package.

Exports all transport classes and helpers for clean imports::

    from forge_c2.transport import HTTPTransport, DNSTransport, TCPTransport
    from forge_c2.transport import get_profile, MalleableProfile
"""
from __future__ import annotations

from forge_c2.transport.base_transport import (
    BaseTransport,
    MalleableProfile,
    TransportStats,
    TransportType,
    get_profile,
    PROFILES,
)
from forge_c2.transport.http_transport import (
    HTTPTransport,
    DomainFrontConfig,
    ProxyConfig,
)
from forge_c2.transport.dns_transport import (
    DNSTransport,
    DNSConfig,
)
from forge_c2.transport.tcp_transport import (
    TCPTransport,
    TCPConfig,
    SMBTransport,
)

__all__ = [
    "BaseTransport",
    "MalleableProfile",
    "TransportStats",
    "TransportType",
    "get_profile",
    "PROFILES",
    "HTTPTransport",
    "DomainFrontConfig",
    "ProxyConfig",
    "DNSTransport",
    "DNSConfig",
    "TCPTransport",
    "TCPConfig",
    "SMBTransport",
]
