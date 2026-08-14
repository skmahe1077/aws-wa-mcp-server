"""Reliability pillar checks.

All checks are read-only (Describe/List/Get). Best-practice IDs are taken from
the AWS Well-Architected Reliability Pillar documentation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

from .common import Finding, Severity, check

PILLAR = "Reliability"

_REL = "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar"

# EBS volumes without a snapshot newer than this are flagged.
_SNAPSHOT_MAX_AGE_DAYS = 7


@check(
    "REL10-BP01",
    "RDS instances are deployed Multi-AZ",
    f"{_REL}/rel_fault_isolation_multiaz_region_system.html",
)
def rds_multi_az(session, region) -> List[Finding]:
    """Flag single-AZ RDS instances (no standby in another AZ)."""
    findings: List[Finding] = []
    rds = session.client("rds", region_name=region)
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            # Aurora manages AZ resilience at the cluster level; skip members.
            if db.get("Engine", "").startswith("aurora"):
                continue
            if not db.get("MultiAZ", False):
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="REL10-BP01",
                        title="RDS instance is not Multi-AZ",
                        severity=Severity.HIGH,
                        resource_id=db["DBInstanceIdentifier"],
                        region=region,
                        detail=(
                            f"RDS instance '{db['DBInstanceIdentifier']}' "
                            f"({db.get('Engine')}) runs in a single Availability "
                            "Zone, so an AZ failure causes downtime."
                        ),
                        recommendation=(
                            "Enable Multi-AZ so RDS maintains a synchronous "
                            "standby in a second AZ with automatic failover."
                        ),
                        wa_reference=f"{_REL}/rel_fault_isolation_multiaz_region_system.html",
                    )
                )
    return findings


@check(
    "REL10-BP01",
    "Load balancers span at least two Availability Zones",
    f"{_REL}/rel_fault_isolation_multiaz_region_system.html",
)
def load_balancer_multi_az(session, region) -> List[Finding]:
    """Flag ALB/NLB/GWLB and classic ELBs that span fewer than two AZs."""
    findings: List[Finding] = []

    # Application/Network/Gateway load balancers (ELBv2).
    elbv2 = session.client("elbv2", region_name=region)
    for page in elbv2.get_paginator("describe_load_balancers").paginate():
        for lb in page.get("LoadBalancers", []):
            azs = {z["ZoneName"] for z in lb.get("AvailabilityZones", [])}
            if len(azs) < 2:
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="REL10-BP01",
                        title="Load balancer is confined to a single Availability Zone",
                        severity=Severity.HIGH,
                        resource_id=lb["LoadBalancerName"],
                        region=region,
                        detail=(
                            f"{lb.get('Type', 'load balancer')} "
                            f"'{lb['LoadBalancerName']}' is attached to "
                            f"{len(azs)} AZ(s); it cannot survive an AZ failure."
                        ),
                        recommendation=(
                            "Attach subnets in at least two Availability Zones "
                            "and register targets in each."
                        ),
                        wa_reference=f"{_REL}/rel_fault_isolation_multiaz_region_system.html",
                    )
                )

    # Classic load balancers.
    elb = session.client("elb", region_name=region)
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for lb in page.get("LoadBalancerDescriptions", []):
            azs = set(lb.get("AvailabilityZones", []))
            if len(azs) < 2:
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="REL10-BP01",
                        title="Classic load balancer is confined to a single Availability Zone",
                        severity=Severity.HIGH,
                        resource_id=lb["LoadBalancerName"],
                        region=region,
                        detail=(
                            f"Classic ELB '{lb['LoadBalancerName']}' is attached "
                            f"to {len(azs)} AZ(s)."
                        ),
                        recommendation=(
                            "Enable at least two Availability Zones on the load "
                            "balancer, or migrate to an ALB/NLB."
                        ),
                        wa_reference=f"{_REL}/rel_fault_isolation_multiaz_region_system.html",
                    )
                )
    return findings


@check(
    "REL10-BP01",
    "Auto Scaling groups span multiple Availability Zones",
    f"{_REL}/rel_fault_isolation_multiaz_region_system.html",
)
def asg_multi_az(session, region) -> List[Finding]:
    """Flag Auto Scaling groups confined to a single AZ."""
    findings: List[Finding] = []
    asg = session.client("autoscaling", region_name=region)
    for page in asg.get_paginator("describe_auto_scaling_groups").paginate():
        for group in page.get("AutoScalingGroups", []):
            azs = set(group.get("AvailabilityZones", []))
            if len(azs) < 2:
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="REL10-BP01",
                        title="Auto Scaling group is confined to a single Availability Zone",
                        severity=Severity.HIGH,
                        resource_id=group["AutoScalingGroupName"],
                        region=region,
                        detail=(
                            f"Auto Scaling group "
                            f"'{group['AutoScalingGroupName']}' is limited to "
                            f"{len(azs)} AZ(s), removing cross-AZ redundancy."
                        ),
                        recommendation=(
                            "Configure the ASG across at least two AZs so it can "
                            "replace capacity lost in a single-AZ event."
                        ),
                        wa_reference=f"{_REL}/rel_fault_isolation_multiaz_region_system.html",
                    )
                )
    return findings


@check(
    "REL09-BP01",
    "EBS volumes have a recent snapshot",
    f"{_REL}/rel_backing_up_data_identified_backups_data.html",
)
def ebs_recent_snapshot(session, region) -> List[Finding]:
    """Flag in-use EBS volumes with no snapshot in the last week."""
    findings: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)

    # Map the most recent snapshot start time per source volume.
    latest_snapshot: dict = {}
    snap_paginator = ec2.get_paginator("describe_snapshots")
    for page in snap_paginator.paginate(OwnerIds=["self"]):
        for snap in page.get("Snapshots", []):
            vol_id = snap.get("VolumeId")
            start = snap.get("StartTime")
            if not vol_id or start is None:
                continue
            if vol_id not in latest_snapshot or start > latest_snapshot[vol_id]:
                latest_snapshot[vol_id] = start

    cutoff = datetime.now(timezone.utc) - timedelta(days=_SNAPSHOT_MAX_AGE_DAYS)
    vol_paginator = ec2.get_paginator("describe_volumes")
    for page in vol_paginator.paginate():
        for vol in page.get("Volumes", []):
            vol_id = vol["VolumeId"]
            # Only worry about volumes actually attached to something.
            if vol.get("State") != "in-use":
                continue
            last = latest_snapshot.get(vol_id)
            if last is None or last < cutoff:
                when = "never" if last is None else last.date().isoformat()
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="REL09-BP01",
                        title="EBS volume has no recent snapshot",
                        severity=Severity.MEDIUM,
                        resource_id=vol_id,
                        region=region,
                        detail=(
                            f"Volume '{vol_id}' ({vol.get('Size')} GiB) was last "
                            f"snapshotted: {when} (threshold "
                            f"{_SNAPSHOT_MAX_AGE_DAYS} days)."
                        ),
                        recommendation=(
                            "Automate snapshots with Amazon Data Lifecycle "
                            "Manager or AWS Backup to meet your RPO."
                        ),
                        wa_reference=f"{_REL}/rel_backing_up_data_identified_backups_data.html",
                    )
                )
    return findings


@check(
    "REL09-BP01",
    "RDS instances have automated backups enabled",
    f"{_REL}/rel_backing_up_data_identified_backups_data.html",
)
def rds_backups_enabled(session, region) -> List[Finding]:
    """Flag RDS instances with automated backups disabled (retention 0)."""
    findings: List[Finding] = []
    rds = session.client("rds", region_name=region)
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            if db.get("Engine", "").startswith("aurora"):
                continue
            if db.get("BackupRetentionPeriod", 0) == 0:
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="REL09-BP01",
                        title="RDS instance has automated backups disabled",
                        severity=Severity.HIGH,
                        resource_id=db["DBInstanceIdentifier"],
                        region=region,
                        detail=(
                            f"RDS instance '{db['DBInstanceIdentifier']}' has a "
                            "backup retention period of 0 days, so no automated "
                            "backups or point-in-time recovery exist."
                        ),
                        recommendation=(
                            "Set a backup retention period (typically 7-35 days) "
                            "to enable automated backups and point-in-time restore."
                        ),
                        wa_reference=f"{_REL}/rel_backing_up_data_identified_backups_data.html",
                    )
                )
    return findings


CHECKS = [
    rds_multi_az,
    load_balancer_multi_az,
    asg_multi_az,
    ebs_recent_snapshot,
    rds_backups_enabled,
]
