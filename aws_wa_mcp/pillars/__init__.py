"""Well-Architected pillar scanners.

Each pillar module exposes a ``PILLAR`` name and a ``CHECKS`` list of
decorated, read-only check functions. ``PILLARS`` below is the canonical
registry used by the MCP server to build one tool per pillar.
"""

from __future__ import annotations

from . import (
    cost_optimization,
    operational_excellence,
    performance_efficiency,
    reliability,
    security,
    sustainability,
)

# Ordered registry: tool suffix -> module. The suffix becomes ``scan_<suffix>``.
PILLARS = {
    "cost_optimization": cost_optimization,
    "reliability": reliability,
    "performance_efficiency": performance_efficiency,
    "operational_excellence": operational_excellence,
    "security": security,
    "sustainability": sustainability,
}

__all__ = ["PILLARS"]
