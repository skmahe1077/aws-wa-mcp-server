"""Security pillar checks.

All checks are read-only (Describe/List/Get). Best-practice IDs are taken from
the AWS Well-Architected Security Pillar documentation.
"""

from __future__ import annotations

from typing import List

from botocore.exceptions import ClientError

from .common import Finding, Severity, check

PILLAR = "Security"

_SEC = "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar"

# Ports that are especially dangerous to expose to the public internet.
_SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL/Aurora",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    23: "Telnet",
    5984: "CouchDB",
}


def _port_range_hits(from_port, to_port) -> List[int]:
    """Return the sensitive ports covered by an ingress rule's port range."""
    if from_port is None or to_port is None:
        # All ports (e.g. protocol -1). Everything sensitive is exposed.
        return sorted(_SENSITIVE_PORTS)
    return [p for p in _SENSITIVE_PORTS if from_port <= p <= to_port]


@check(
    "SEC03-BP07",
    "S3 Block Public Access is enabled account-wide and per bucket",
    f"{_SEC}/sec_permissions_analyze_cross_account.html",
    global_check=True,
)
def s3_public_access_block(session, region) -> List[Finding]:
    """Flag missing account-level and bucket-level S3 Block Public Access.

    S3 buckets live in a single global namespace and the Block Public Access
    setting is not region-specific, so this is a global check that runs once
    over every bucket - we never call get_bucket_location per bucket.
    """
    findings: List[Finding] = []
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Account-level public access block (via the S3 Control API).
    s3control = session.client("s3control")
    account_pab_ok = False
    try:
        cfg = s3control.get_public_access_block(AccountId=account_id)[
            "PublicAccessBlockConfiguration"
        ]
        account_pab_ok = all(
            cfg.get(k, False)
            for k in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in (
            "NoSuchPublicAccessBlockConfiguration",
            "NoSuchPublicAccessBlock",
        ):
            account_pab_ok = False
        else:
            raise

    if not account_pab_ok:
        findings.append(
            Finding(
                pillar=PILLAR,
                check_id="SEC03-BP07",
                title="Account-level S3 Block Public Access is not fully enabled",
                severity=Severity.HIGH,
                resource_id=f"account:{account_id}",
                region="global",
                detail=(
                    "The account-wide S3 Block Public Access configuration does "
                    "not enable all four protections (BlockPublicAcls, "
                    "IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets)."
                ),
                recommendation=(
                    "Enable all four account-level Block Public Access settings "
                    "in the S3 console or via s3control put-public-access-block."
                ),
                wa_reference=f"{_SEC}/sec_permissions_analyze_cross_account.html",
            )
        )

    # Per-bucket public access block.
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        try:
            bcfg = s3.get_public_access_block(Bucket=name)[
                "PublicAccessBlockConfiguration"
            ]
            bucket_ok = all(
                bcfg.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"):
                bucket_ok = False
            elif code in ("AccessDenied", "AllAccessDisabled"):
                # Cannot inspect this bucket; skip it rather than abort.
                continue
            else:
                raise
        # If the account-level block is fully on, buckets are already covered.
        if not bucket_ok and not account_pab_ok:
            findings.append(
                Finding(
                    pillar=PILLAR,
                    check_id="SEC03-BP07",
                    title="S3 bucket without full Block Public Access",
                    severity=Severity.MEDIUM,
                    resource_id=name,
                    region="global",
                    detail=(
                        f"Bucket '{name}' does not have all four Block Public "
                        "Access protections enabled and no account-level block "
                        "compensates for it."
                    ),
                    recommendation=(
                        "Enable Block Public Access on the bucket, or turn on the "
                        "account-level block to cover all buckets at once."
                    ),
                    wa_reference=f"{_SEC}/sec_permissions_analyze_cross_account.html",
                )
            )
    return findings


@check(
    "SEC05-BP02",
    "Security groups do not allow unrestricted ingress from 0.0.0.0/0",
    f"{_SEC}/sec_network_protection_layered.html",
)
def security_groups_open_to_world(session, region) -> List[Finding]:
    """Flag security groups exposing sensitive ports to 0.0.0.0/0 or ::/0."""
    findings: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            sg_id = sg["GroupId"]
            for perm in sg.get("IpPermissions", []):
                open_v4 = any(
                    rng.get("CidrIp") == "0.0.0.0/0" for rng in perm.get("IpRanges", [])
                )
                open_v6 = any(
                    rng.get("CidrIpv6") == "::/0"
                    for rng in perm.get("Ipv6Ranges", [])
                )
                if not (open_v4 or open_v6):
                    continue
                ports = _port_range_hits(perm.get("FromPort"), perm.get("ToPort"))
                if not ports:
                    continue
                labels = ", ".join(f"{p} ({_SENSITIVE_PORTS[p]})" for p in ports)
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="SEC05-BP02",
                        title="Security group allows unrestricted ingress to a sensitive port",
                        severity=Severity.CRITICAL,
                        resource_id=sg_id,
                        region=region,
                        detail=(
                            f"Security group '{sg_id}' ({sg.get('GroupName', '')}) "
                            f"allows ingress from the internet to: {labels}."
                        ),
                        recommendation=(
                            "Restrict the source CIDR to known ranges, place the "
                            "resource behind a bastion/VPN, or use SSM Session "
                            "Manager instead of exposing management ports."
                        ),
                        wa_reference=f"{_SEC}/sec_network_protection_layered.html",
                    )
                )
    return findings


@check(
    "SEC02-BP02",
    "Root user has no long-lived access keys",
    f"{_SEC}/sec_identities_unique.html",
    global_check=True,
)
def root_access_keys(session, region) -> List[Finding]:
    """Flag the presence of access keys on the account root user."""
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0) == 1:
        return [
            Finding(
                pillar=PILLAR,
                check_id="SEC02-BP02",
                title="Root account has active access keys",
                severity=Severity.CRITICAL,
                resource_id="root-account",
                region="global",
                detail=(
                    "The account root user has long-lived access keys. Root keys "
                    "grant unrestricted access and cannot be scoped by IAM policy."
                ),
                recommendation=(
                    "Delete the root access keys. Use IAM roles/users with "
                    "least-privilege temporary credentials for automation."
                ),
                wa_reference=f"{_SEC}/sec_identities_unique.html",
            )
        ]
    return []


@check(
    "SEC02-BP01",
    "Root user has MFA enabled",
    f"{_SEC}/sec_identities_enforce_mechanisms.html",
    global_check=True,
)
def root_mfa_enabled(session, region) -> List[Finding]:
    """Flag a root user without MFA."""
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) != 1:
        return [
            Finding(
                pillar=PILLAR,
                check_id="SEC02-BP01",
                title="Root account does not have MFA enabled",
                severity=Severity.CRITICAL,
                resource_id="root-account",
                region="global",
                detail=(
                    "MFA is not enabled on the account root user, leaving the "
                    "most privileged identity protected only by a password."
                ),
                recommendation=(
                    "Enable a hardware or virtual MFA device on the root user "
                    "and store it securely."
                ),
                wa_reference=f"{_SEC}/sec_identities_enforce_mechanisms.html",
            )
        ]
    return []


@check(
    "SEC04-BP01",
    "Amazon GuardDuty threat detection is enabled",
    f"{_SEC}/sec_detect_investigate_events_app_service_logging.html",
)
def guardduty_enabled(session, region) -> List[Finding]:
    """Flag a region with no active GuardDuty detector."""
    gd = session.client("guardduty", region_name=region)
    detectors = gd.list_detectors().get("DetectorIds", [])
    enabled = False
    for det_id in detectors:
        status = gd.get_detector(DetectorId=det_id).get("Status")
        if status == "ENABLED":
            enabled = True
            break
    if not enabled:
        return [
            Finding(
                pillar=PILLAR,
                check_id="SEC04-BP01",
                title="GuardDuty is not enabled in this region",
                severity=Severity.HIGH,
                resource_id=f"guardduty:{region}",
                region=region,
                detail=(
                    "No enabled GuardDuty detector was found in this region, so "
                    "the account lacks managed threat detection here."
                ),
                recommendation=(
                    "Enable GuardDuty in every active region (ideally via an "
                    "Organizations delegated administrator for centralised setup)."
                ),
                wa_reference=f"{_SEC}/sec_detect_investigate_events_app_service_logging.html",
            )
        ]
    return []


CHECKS = [
    s3_public_access_block,
    security_groups_open_to_world,
    root_access_keys,
    root_mfa_enabled,
    guardduty_enabled,
]
