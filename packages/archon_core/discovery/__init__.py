"""Local agent-config client discovery (sprint 80)."""

from archon_core.discovery.clients import (
    KNOWN_CLIENTS,
    ClientSpec,
    DiscoveredClient,
    discover_clients,
    summarize_discovery,
)

__all__ = [
    "KNOWN_CLIENTS",
    "ClientSpec",
    "DiscoveredClient",
    "discover_clients",
    "summarize_discovery",
]
