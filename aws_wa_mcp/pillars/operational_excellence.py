"""Operational Excellence pillar checks.

All checks are read-only (Describe/List/Get). Best-practice IDs are taken from
the AWS Well-Architected Operational Excellence Pillar documentation.
"""

from __future__ import annotations

from typing import List

from .common import Finding, Severity, check

PILLAR = "Operational Excellence"

_OPS = "https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar"


@check(
    "OPS04-BP02",
    "A multi-region CloudTrail trail records API activity",
    f"{_OPS}/ops_observability_application_telemetry.html",
    global_check=True,
)
def cloudtrail_enabled(session, region) -> List[Finding]:
    """Flag the absence of an enabled multi-region CloudTrail trail.

    CloudTrail's multi-region trails are account-global, so this runs once.
    """
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

    good_trail = None
    for trail in trails:
        if not trail.get("IsMultiRegionTrail"):
            continue
        name = trail.get("TrailARN") or trail.get("Name")
        try:
            status = ct.get_trail_status(Name=name)
        except Exception:  # noqa: BLE001 - a trail in another region we can't query
            continue
        if status.get("IsLogging"):
            good_trail = trail
            break

    if good_trail is None:
        return [
            Finding(
                pillar=PILLAR,
                check_id="OPS04-BP02",
                title="No active multi-region CloudTrail trail",
                severity=Severity.HIGH,
                resource_id="cloudtrail",
                region="global",
                detail=(
                    "No enabled multi-region CloudTrail trail was found. Without "
                    "it, account-wide API activity is not captured for operations "
                    "and audit."
                ),
                recommendation=(
                    "Create a multi-region CloudTrail trail that logs to a "
                    "durable S3 bucket and keep it in the logging state."
                ),
                wa_reference=f"{_OPS}/ops_observability_application_telemetry.html",
            )
        ]
    return []


@check(
    "OPS05-BP03",
    "AWS Config records resource configuration changes",
    f"{_OPS}/ops_dev_integ_conf_mgmt_sys.html",
)
def config_recorder_enabled(session, region) -> List[Finding]:
    """Flag a region with no active AWS Config configuration recorder."""
    cfg = session.client("config", region_name=region)
    recorders = cfg.describe_configuration_recorders().get(
        "ConfigurationRecorders", []
    )
    statuses = {
        s["name"]: s
        for s in cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", []
        )
    }
    recording = any(
        statuses.get(r["name"], {}).get("recording") for r in recorders
    )
    if not recording:
        return [
            Finding(
                pillar=PILLAR,
                check_id="OPS05-BP03",
                title="AWS Config is not recording in this region",
                severity=Severity.MEDIUM,
                resource_id=f"config:{region}",
                region=region,
                detail=(
                    "No AWS Config configuration recorder is actively recording "
                    "in this region, so resource configuration history and drift "
                    "are not tracked."
                ),
                recommendation=(
                    "Enable an AWS Config recorder (ideally organization-wide) to "
                    "capture configuration state and changes."
                ),
                wa_reference=f"{_OPS}/ops_dev_integ_conf_mgmt_sys.html",
            )
        ]
    return []


@check(
    "OPS08-BP04",
    "CloudWatch alarms exist to surface operational issues",
    f"{_OPS}/ops_workload_observability_create_alerts.html",
)
def cloudwatch_alarms_exist(session, region) -> List[Finding]:
    """Flag a region that has no CloudWatch alarms defined at all."""
    cw = session.client("cloudwatch", region_name=region)
    count = 0
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmTypes=["MetricAlarm", "CompositeAlarm"]
    ):
        count += len(page.get("MetricAlarms", []))
        count += len(page.get("CompositeAlarms", []))
        if count:
            break
    if count == 0:
        return [
            Finding(
                pillar=PILLAR,
                check_id="OPS08-BP04",
                title="No CloudWatch alarms are configured in this region",
                severity=Severity.MEDIUM,
                resource_id=f"cloudwatch:{region}",
                region=region,
                detail=(
                    "No CloudWatch alarms were found in this region, so there is "
                    "no automated alerting on metric thresholds."
                ),
                recommendation=(
                    "Create actionable alarms on key metrics (errors, latency, "
                    "saturation) wired to SNS/notification targets."
                ),
                wa_reference=f"{_OPS}/ops_workload_observability_create_alerts.html",
            )
        ]
    return []


@check(
    "OPS08-BP02",
    "CloudWatch log groups have an explicit retention policy",
    f"{_OPS}/ops_workload_observability_analyze_workload_logs.html",
)
def log_group_retention(session, region) -> List[Finding]:
    """Flag CloudWatch log groups set to never expire (no retention policy)."""
    findings: List[Finding] = []
    logs = session.client("logs", region_name=region)
    never_expire = []
    for page in logs.get_paginator("describe_log_groups").paginate():
        for lg in page.get("logGroups", []):
            if lg.get("retentionInDays") is None:
                never_expire.append(lg["logGroupName"])

    # Report once, listing the affected groups, to avoid a flood of findings.
    if never_expire:
        sample = ", ".join(never_expire[:5])
        more = "" if len(never_expire) <= 5 else f" (+{len(never_expire) - 5} more)"
        findings.append(
            Finding(
                pillar=PILLAR,
                check_id="OPS08-BP02",
                title="CloudWatch log groups have no retention policy",
                severity=Severity.LOW,
                resource_id=f"logs:{region}",
                region=region,
                detail=(
                    f"{len(never_expire)} log group(s) never expire: "
                    f"{sample}{more}. Unbounded retention grows cost and makes "
                    "logs harder to manage and analyse."
                ),
                recommendation=(
                    "Set an explicit retention period per log group aligned to "
                    "your operational and compliance requirements."
                ),
                wa_reference=f"{_OPS}/ops_workload_observability_analyze_workload_logs.html",
            )
        )
    return findings


CHECKS = [
    cloudtrail_enabled,
    config_recorder_enabled,
    cloudwatch_alarms_exist,
    log_group_retention,
]
