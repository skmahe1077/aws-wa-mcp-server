"""Tests for the harness in aws_wa_mcp.pillars.common.

These use plain unittest.mock-style fake checks - no AWS calls at all - to prove
the failure-isolation and scoring behaviour of run_checks.
"""

from botocore.exceptions import ClientError, NoCredentialsError

from aws_wa_mcp.pillars.common import (
    Finding,
    Severity,
    check,
    is_previous_generation,
    run_checks,
)


def _finding(severity, resource_id="r", check_id="X01-BP01"):
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


def test_run_checks_isolates_failures():
    """A failing check is recorded as skipped and does not abort the others."""

    @check("OK01-BP01", "healthy check", "http://x")
    def healthy(session, region):
        return [_finding(Severity.HIGH)]

    @check("DENY-BP01", "permission denied check", "http://x")
    def denied(session, region):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "nope"}},
            "DescribeThing",
        )

    @check("NOCRED-BP01", "no credentials check", "http://x")
    def nocreds(session, region):
        raise NoCredentialsError()

    @check("BOOM-BP01", "unexpected error check", "http://x")
    def boom(session, region):
        raise ValueError("kaboom")

    result = run_checks(
        [healthy, denied, nocreds, boom], session=None, region="us-east-1",
        pillar="Test",
    )

    assert result.checks_run == 4
    assert len(result.findings) == 1
    assert len(result.checks_skipped) == 3

    skipped_by_id = {c.check_id: c for c in result.checks_skipped}
    assert skipped_by_id["DENY-BP01"].error_type == "ClientError"
    assert "AccessDenied" in skipped_by_id["DENY-BP01"].reason
    assert skipped_by_id["NOCRED-BP01"].error_type == "NoCredentialsError"
    assert skipped_by_id["BOOM-BP01"].error_type == "ValueError"


def test_findings_sorted_by_severity():
    @check("A", "a", "http://x")
    def mixed(session, region):
        return [
            _finding(Severity.LOW, "low"),
            _finding(Severity.CRITICAL, "crit"),
            _finding(Severity.MEDIUM, "med"),
        ]

    result = run_checks([mixed], None, "us-east-1", "Test")
    order = [f.severity for f in result.findings]
    assert order == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_health_score_penalises_by_severity():
    @check("A", "a", "http://x")
    def critical(session, region):
        return [_finding(Severity.CRITICAL)]

    result = run_checks([critical], None, "us-east-1", "Test")
    # 100 - 20 (one CRITICAL) = 80
    assert result.health_score == 80


def test_clean_pillar_scores_100():
    @check("A", "a", "http://x")
    def clean(session, region):
        return []

    result = run_checks([clean], None, "us-east-1", "Test")
    assert result.health_score == 100
    assert result.findings == []


def test_include_global_filter():
    @check("G", "global check", "http://x", global_check=True)
    def global_c(session, region):
        return [_finding(Severity.HIGH, "g")]

    @check("R", "regional check", "http://x")
    def regional_c(session, region):
        return [_finding(Severity.HIGH, "r")]

    checks = [global_c, regional_c]

    with_global = run_checks(checks, None, "us-east-1", "Test", include_global=True)
    assert with_global.checks_run == 2

    without_global = run_checks(
        checks, None, "us-west-2", "Test", include_global=False
    )
    assert without_global.checks_run == 1
    assert all(f.resource_id == "r" for f in without_global.findings)


def test_is_previous_generation():
    assert is_previous_generation("m4.large")
    assert is_previous_generation("t2.micro")
    assert not is_previous_generation("m7i.large")
    assert not is_previous_generation("c7g.xlarge")
