"""Shared primitives for all Well-Architected pillar scanners.

This module deliberately contains **no** mutating AWS calls. It provides:

* :class:`Severity` - ordered severity levels with scoring weights.
* :class:`Finding` - a single Well-Architected best-practice violation.
* :class:`CheckSkipped` - a check that could not run (missing permission,
  transient API error, no credentials, ...).
* :class:`PillarScanResult` - the aggregate result for one pillar.
* :func:`check` - a decorator that attaches metadata to a check function.
* :func:`run_checks` - a fault-isolating, thread-pooled harness that runs a
  list of check functions and never lets one failing check abort the rest.

Design principle: *generate-never-mutate*. Every check only issues
Describe/List/Get calls. The harness enforces failure isolation so a missing
IAM permission on one check surfaces in ``checks_skipped`` instead of raising.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
)

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Finding severity, ordered from most to least serious.

    ``weight`` is the health-score penalty applied per finding of this
    severity (see :func:`PillarScanResult.health_score`).
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Sort key: higher means more severe."""
        return _SEVERITY_RANK[self]

    @property
    def weight(self) -> int:
        """Health-score penalty for one finding at this severity."""
        return _SEVERITY_WEIGHT[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

# Base URL for Well-Architected best-practice documentation. Individual checks
# supply the anchor page via the ``wa_reference`` argument to :func:`check`.
WA_DOCS_BASE = "https://docs.aws.amazon.com/wellarchitected/latest"


@dataclass
class Finding:
    """A single detected Well-Architected best-practice violation.

    ``cis_control`` and ``nist_csf`` are compliance-framework cross-references
    (CIS AWS Foundations Benchmark control, NIST CSF category) populated
    centrally from :data:`CONTROL_MAP` when the finding passes through
    :func:`run_checks`. They stay empty for check IDs with no published
    mapping, so a finding always carries its own audit-grade control lineage.
    """

    pillar: str
    check_id: str
    title: str
    severity: Severity
    resource_id: str
    region: str
    detail: str
    recommendation: str
    wa_reference: str
    cis_control: str = ""
    nist_csf: str = ""

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        return d


@dataclass
class CheckSkipped:
    """A check that could not complete, recorded instead of a finding."""

    check_id: str
    title: str
    reason: str
    error_type: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class PillarScanResult:
    """Aggregate result for scanning one pillar in one region."""

    pillar: str
    region: str
    findings: List[Finding] = field(default_factory=list)
    checks_skipped: List[CheckSkipped] = field(default_factory=list)
    checks_run: int = 0

    @property
    def health_score(self) -> int:
        """0-100 score for this pillar, penalised by finding severity.

        Starts at 100 and subtracts each finding's severity weight, floored
        at 0. A clean pillar (or one whose checks were all skipped) scores 100.
        """
        penalty = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - penalty)

    def severity_counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "pillar": self.pillar,
            "region": self.region,
            "health_score": self.health_score,
            "checks_run": self.checks_run,
            "findings_count": len(self.findings),
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
            "checks_skipped": [c.to_dict() for c in self.checks_skipped],
        }


# ---------------------------------------------------------------------------
# Compliance framework mapping
# ---------------------------------------------------------------------------

# Cross-reference each Well-Architected best-practice ID to a recognised
# compliance control, so findings carry audit-grade lineage beyond the WA
# framework itself:
#   * cis  - CIS AWS Foundations Benchmark control (empty when no direct
#            benchmark control exists for the check).
#   * nist - NIST Cybersecurity Framework (CSF) subcategory.
# These are indicative mappings for continuous control monitoring; they are
# conservative and only claim a CIS number where a genuine control exists.
CONTROL_MAP = {
    # Security
    "SEC02-BP01": ("CIS 1.5", "PR.AC-1"),    # root user MFA
    "SEC02-BP02": ("CIS 1.4", "PR.AC-1"),    # no root access keys
    "SEC03-BP07": ("CIS 2.1.4", "PR.DS-5"),  # S3 Block Public Access
    "SEC04-BP01": ("", "DE.CM-1"),           # GuardDuty threat detection
    "SEC05-BP02": ("CIS 5.2", "PR.AC-5"),    # SG open to 0.0.0.0/0
    # Reliability
    "REL09-BP01": ("", "PR.IP-4"),           # backups
    "REL10-BP01": ("", "PR.PT-5"),           # multi-AZ resilience
    # Cost Optimization
    "COST02-BP05": ("", "ID.BE-3"),          # budgets
    "COST04-BP03": ("", "ID.AM-1"),          # decommission unused resources
    "COST06-BP02": ("", "ID.AM-1"),          # right-size instance types
    # Performance Efficiency
    "PERF02-BP01": ("", "ID.AM-1"),          # current-gen compute
    "PERF02-BP03": ("", "DE.CM-1"),          # detailed monitoring
    "PERF03-BP02": ("", "ID.AM-1"),          # current-gen storage
    # Operational Excellence
    "OPS04-BP02": ("CIS 3.1", "DE.CM-1"),    # multi-region CloudTrail
    "OPS05-BP03": ("CIS 3.5", "DE.CM-1"),    # AWS Config recorder
    "OPS08-BP02": ("", "PR.PT-1"),           # log retention
    "OPS08-BP04": ("CIS 4.1", "DE.CM-1"),    # CloudWatch alarms
    # Sustainability
    "SUS02-BP01": ("", "ID.AM-1"),
    "SUS04-BP03": ("", "ID.AM-1"),
    "SUS05-BP01": ("", "ID.AM-1"),
    "SUS05-BP02": ("", "ID.AM-1"),
}


def standard_refs(check_id: str) -> tuple:
    """Return ``(cis_control, nist_csf)`` for a WA check ID, or ``("", "")``."""
    return CONTROL_MAP.get(check_id, ("", ""))


def compliance_summary(findings: List["Finding"], controls_evaluated: int) -> dict:
    """Roll findings up into a control-monitoring summary.

    A check that produced no findings is treated as a passed control; a check
    with one or more findings is a failed control. Also lists the distinct CIS
    and NIST references flagged, so the result maps onto recognised frameworks.
    """
    controls_failed = {f.check_id for f in findings}
    # Derive framework refs from the check ID directly so the summary is
    # correct whether or not the findings were enriched via run_checks.
    refs = [standard_refs(cid) for cid in controls_failed]
    cis_flagged = sorted({cis for cis, _ in refs if cis})
    nist_flagged = sorted({nist for _, nist in refs if nist})
    return {
        "controls_evaluated": controls_evaluated,
        "controls_failed": len(controls_failed),
        "controls_passed": max(0, controls_evaluated - len(controls_failed)),
        "frameworks": {
            "cis_aws_foundations": {"controls_flagged": cis_flagged},
            "nist_csf": {"categories_flagged": nist_flagged},
        },
    }


# ---------------------------------------------------------------------------
# Shared AWS reference data
# ---------------------------------------------------------------------------

# Previous-generation EC2 instance families. Newer families in the same class
# (e.g. m6i/m7i vs m4) deliver better price/performance and lower energy use,
# so several pillars flag these. Kept conservative to avoid false positives.
PREVIOUS_GEN_FAMILIES = frozenset(
    {
        "t1", "t2",
        "m1", "m2", "m3", "m4",
        "c1", "c3", "c4", "cc2",
        "cr1",
        "r3", "r4",
        "i2",
        "hi1", "hs1",
        "g2", "g3",
        "p2",
        "d2",
    }
)


def instance_family(instance_type: str) -> str:
    """Return the family prefix of an EC2 instance type (``m5.large`` -> ``m5``)."""
    return instance_type.split(".", 1)[0]


def is_previous_generation(instance_type: str) -> bool:
    """True if ``instance_type`` belongs to a previous-generation family."""
    return instance_family(instance_type) in PREVIOUS_GEN_FAMILIES


# ---------------------------------------------------------------------------
# Check decorator
# ---------------------------------------------------------------------------

# A check is a callable ``fn(session, region) -> list[Finding]`` decorated with
# metadata via :func:`check`.
CheckFn = Callable[..., List[Finding]]


def check(
    check_id: str,
    title: str,
    wa_reference: str,
    *,
    global_check: bool = False,
) -> Callable[[CheckFn], CheckFn]:
    """Attach Well-Architected metadata to a check function.

    Parameters
    ----------
    check_id:
        The real AWS Well-Architected best-practice identifier, e.g.
        ``"SEC05-BP02"``.
    title:
        Short human-readable description of what the check inspects.
    wa_reference:
        URL to the best-practice documentation page.
    global_check:
        ``True`` for checks against global services (IAM, S3 bucket namespace,
        account-level settings) whose result does not vary by region. The
        harness can skip these on all but the first region when a caller scans
        multiple regions, so they run exactly once. See ``run_checks``.
    """

    def decorator(fn: CheckFn) -> CheckFn:
        fn.check_id = check_id  # type: ignore[attr-defined]
        fn.title = title  # type: ignore[attr-defined]
        fn.wa_reference = wa_reference  # type: ignore[attr-defined]
        fn.global_check = global_check  # type: ignore[attr-defined]
        fn.is_wa_check = True  # type: ignore[attr-defined]
        return fn

    return decorator


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _describe_error(exc: BaseException) -> str:
    """Produce a concise, human-readable reason for a skipped check."""
    if isinstance(exc, NoCredentialsError):
        return "No AWS credentials found in the environment."
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "ClientError")
        message = err.get("Message", str(exc))
        return f"{code}: {message}"
    return f"{type(exc).__name__}: {exc}"


def run_checks(
    checks: List[CheckFn],
    session,
    region: str,
    pillar: str,
    *,
    max_workers: int = 8,
    include_global: bool = True,
) -> PillarScanResult:
    """Run ``checks`` concurrently with per-check failure isolation.

    Each check is invoked as ``fn(session, region)`` in a thread pool. Any
    exception it raises - most importantly :class:`NoCredentialsError` and
    :class:`ClientError` (AccessDenied, throttling, ...) - is caught and
    recorded as a :class:`CheckSkipped` rather than propagating. This
    guarantees that one missing IAM permission or transient API error cannot
    abort the rest of the scan.

    ``include_global`` controls whether ``global_check`` checks run. Callers
    that loop over multiple regions should pass ``include_global=True`` for the
    first region and ``False`` for the rest so global-service checks (IAM root
    settings, S3 bucket namespace, account budgets) execute exactly once
    instead of once per region.

    Returns a :class:`PillarScanResult` with findings sorted by descending
    severity.
    """
    selected = [
        fn for fn in checks if include_global or not getattr(fn, "global_check", False)
    ]

    result = PillarScanResult(pillar=pillar, region=region)
    result.checks_run = len(selected)

    if not selected:
        return result

    def _invoke(fn: CheckFn):
        # Executed in a worker thread. Each check builds its own boto3 clients
        # from the shared session, so no client object is shared across threads.
        return fn(session, region)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(max_workers, len(selected))
    ) as pool:
        future_to_fn = {pool.submit(_invoke, fn): fn for fn in selected}
        for future in concurrent.futures.as_completed(future_to_fn):
            fn = future_to_fn[future]
            check_id = getattr(fn, "check_id", fn.__name__)
            title = getattr(fn, "title", fn.__name__)
            try:
                findings = future.result()
            except (NoCredentialsError, ClientError, BotoCoreError) as exc:
                result.checks_skipped.append(
                    CheckSkipped(
                        check_id=check_id,
                        title=title,
                        reason=_describe_error(exc),
                        error_type=type(exc).__name__,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - defensive: never abort a scan
                result.checks_skipped.append(
                    CheckSkipped(
                        check_id=check_id,
                        title=title,
                        reason=_describe_error(exc),
                        error_type=type(exc).__name__,
                    )
                )
            else:
                for finding in findings or []:
                    # Attach compliance lineage centrally so every check
                    # inherits its CIS/NIST references without repeating them.
                    finding.cis_control, finding.nist_csf = standard_refs(
                        finding.check_id
                    )
                result.findings.extend(findings or [])

    result.findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return result
