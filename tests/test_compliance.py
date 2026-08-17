"""Tests for audit-grade features: compliance mapping and the scan envelope.

Covers the standards cross-reference (CIS / NIST CSF) attached to findings,
the compliance summary roll-up, and the attestation envelope returned by the
MCP tools. Uses moto for the envelope test - no real AWS calls.
"""

import boto3
from moto import mock_aws

from aws_wa_mcp.pillars.common import (
    Finding,
    Severity,
    check,
    compliance_summary,
    run_checks,
    standard_refs,
)


def _finding(check_id, severity=Severity.CRITICAL, resource_id="r"):
    return Finding(
        pillar="Test",
        check_id=check_id,
        title="t",
        severity=severity,
        resource_id=resource_id,
        region="us-east-1",
        detail="d",
        recommendation="r",
        wa_reference="http://example",
    )


def test_standard_refs_known_id():
    cis, nist = standard_refs("SEC05-BP02")
    assert cis == "CIS 5.2"
    assert nist == "PR.AC-5"


def test_standard_refs_unknown_id_is_empty():
    assert standard_refs("ZZZ99-BP99") == ("", "")


def test_run_checks_enriches_findings_with_standards():
    @check("SEC05-BP02", "sg open", "http://x")
    def sg(session, region):
        return [_finding("SEC05-BP02")]

    result = run_checks([sg], None, "us-east-1", "Security")
    f = result.findings[0]
    assert f.cis_control == "CIS 5.2"
    assert f.nist_csf == "PR.AC-5"
    # ... and the mapping survives serialisation
    assert f.to_dict()["cis_control"] == "CIS 5.2"


def test_unmapped_check_id_leaves_standards_empty():
    @check("X01-BP01", "unmapped", "http://x")
    def unmapped(session, region):
        return [_finding("X01-BP01")]

    result = run_checks([unmapped], None, "us-east-1", "Test")
    f = result.findings[0]
    assert f.cis_control == ""
    assert f.nist_csf == ""


def test_compliance_summary_counts_and_frameworks():
    findings = [_finding("SEC05-BP02"), _finding("SEC02-BP01")]
    summary = compliance_summary(findings, controls_evaluated=5)
    assert summary["controls_evaluated"] == 5
    assert summary["controls_failed"] == 2
    assert summary["controls_passed"] == 3
    cis = summary["frameworks"]["cis_aws_foundations"]["controls_flagged"]
    assert "CIS 5.2" in cis and "CIS 1.5" in cis
    assert "PR.AC-5" in summary["frameworks"]["nist_csf"]["categories_flagged"]


def test_compliance_summary_all_passed():
    summary = compliance_summary([], controls_evaluated=4)
    assert summary["controls_failed"] == 0
    assert summary["controls_passed"] == 4
    assert summary["frameworks"]["cis_aws_foundations"]["controls_flagged"] == []


@mock_aws
def test_pillar_tool_returns_audit_envelope():
    from aws_wa_mcp.server import _scan_one
    from aws_wa_mcp.pillars import security

    out = _scan_one(security, region="us-east-1", profile=None)
    audit = out["audit"]
    assert audit["read_only"] is True
    assert audit["tool_version"]
    assert audit["scan_id"]
    assert audit["generated_at"].endswith("Z")
    # moto's default account
    assert audit["account_id"] == "123456789012"
    assert audit["scanned_by"].startswith("arn:aws:")
    assert "compliance" in out
    assert out["compliance"]["controls_evaluated"] == len(security.CHECKS)


@mock_aws
def test_scan_all_pillars_has_envelope_and_compliance():
    from aws_wa_mcp.server import scan_all_pillars

    out = scan_all_pillars(region="us-east-1")
    assert set(out["audit"]) >= {
        "scan_id",
        "generated_at",
        "tool_version",
        "region",
        "read_only",
        "account_id",
        "scanned_by",
    }
    assert out["compliance"]["controls_evaluated"] > 0
