"""MCP server exposing read-only AWS Well-Architected scans.

Targets the ``mcp`` 2.x SDK, where the server class is ``MCPServer`` imported
from ``mcp.server.mcpserver`` (this was ``FastMCP`` in ``mcp.server.fastmcp`` on
the 1.x SDK; the tool functions are otherwise unchanged). Its ``add_tool`` /
``tool`` / ``run`` APIs are signature-compatible with the 1.x ``FastMCP``.

Transport is stdio, for local use with Claude Desktop / Claude Code.

Every tool is strictly read-only: it only triggers boto3 Describe/List/Get
calls via the pillar check functions. Nothing here creates, modifies or deletes
AWS resources.
"""

from __future__ import annotations

import os
from statistics import mean
from typing import Optional

import boto3
from mcp.server.mcpserver import MCPServer

from . import __version__
from .pillars import PILLARS
from .pillars.common import Finding, run_checks

mcp = MCPServer("aws-wa-mcp-server", version=__version__)

# Number of account-wide findings surfaced by scan_all_pillars.
_TOP_FINDINGS = 15


def _build_session(region: Optional[str], profile: Optional[str]):
    """Build a boto3 session and resolve the effective region.

    Region resolution order: explicit arg -> session default (profile/config)
    -> AWS_REGION -> AWS_DEFAULT_REGION -> us-east-1.
    """
    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(**session_kwargs)
    resolved_region = (
        region
        or session.region_name
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )
    return session, resolved_region


def _scan_one(module, region: Optional[str], profile: Optional[str]) -> dict:
    session, resolved_region = _build_session(region, profile)
    result = run_checks(module.CHECKS, session, resolved_region, module.PILLAR)
    return result.to_dict()


def _make_pillar_tool(suffix: str, module):
    """Create and register a ``scan_<suffix>`` tool bound to ``module``."""

    def scan_pillar(region: Optional[str] = None, profile: Optional[str] = None) -> dict:
        return _scan_one(module, region, profile)

    check_titles = "\n".join(
        f"  - {getattr(fn, 'check_id', '?')}: {getattr(fn, 'title', fn.__name__)}"
        for fn in module.CHECKS
    )
    description = (
        f"Run a live, read-only AWS Well-Architected scan of the "
        f"{module.PILLAR} pillar against the target account/region.\n\n"
        f"Checks performed:\n{check_titles}\n\n"
        "Args: region (optional AWS region, defaults to the profile/env "
        "region), profile (optional named AWS profile). Returns findings sorted "
        "by severity, a 0-100 pillar health score, and a checks_skipped list "
        "for any check blocked by missing permissions or API errors."
    )

    scan_pillar.__name__ = f"scan_{suffix}"
    mcp.add_tool(scan_pillar, name=f"scan_{suffix}", description=description)


for _suffix, _module in PILLARS.items():
    _make_pillar_tool(_suffix, _module)


@mcp.tool()
def scan_all_pillars(
    region: Optional[str] = None, profile: Optional[str] = None
) -> dict:
    """Run all six Well-Architected pillar scans and score the account.

    Executes every pillar's read-only checks against the target account/region,
    then returns:
      - overall_health_score: 0-100, the mean of the six per-pillar
        severity-weighted health scores.
      - pillar_scores: per-pillar health score.
      - pillars: full per-pillar results (findings + checks_skipped).
      - top_findings: the most severe findings account-wide.
      - totals: aggregate finding/severity/skip counts.

    Args: region (optional AWS region), profile (optional named AWS profile).
    """
    session, resolved_region = _build_session(region, profile)

    pillars_out: dict = {}
    pillar_scores: dict = {}
    all_findings: list[Finding] = []
    total_skipped = 0
    severity_totals: dict = {}

    for module in PILLARS.values():
        result = run_checks(module.CHECKS, session, resolved_region, module.PILLAR)
        pillars_out[module.PILLAR] = result.to_dict()
        pillar_scores[module.PILLAR] = result.health_score
        all_findings.extend(result.findings)
        total_skipped += len(result.checks_skipped)
        for sev, n in result.severity_counts().items():
            severity_totals[sev] = severity_totals.get(sev, 0) + n

    overall = round(mean(pillar_scores.values())) if pillar_scores else 100

    all_findings.sort(key=lambda f: f.severity.rank, reverse=True)
    top = [f.to_dict() for f in all_findings[:_TOP_FINDINGS]]

    return {
        "region": resolved_region,
        "overall_health_score": overall,
        "pillar_scores": pillar_scores,
        "totals": {
            "findings": len(all_findings),
            "checks_skipped": total_skipped,
            "severity_counts": severity_totals,
        },
        "top_findings": top,
        "pillars": pillars_out,
    }


def main() -> None:
    """Console-script entrypoint: serve over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
