"""Sustainability pillar checks.

All checks are read-only (Describe/List/Get). Best-practice IDs are taken from
the AWS Well-Architected Sustainability Pillar documentation.
"""

from __future__ import annotations

from typing import List

from botocore.exceptions import ClientError

from .common import Finding, Severity, check, instance_family, is_previous_generation

PILLAR = "Sustainability"

_SUS = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar"


@check(
    "SUS05-BP01",
    "Idle provisioned hardware (unattached EBS) is removed",
    f"{_SUS}/sus_sus_hardware_a2.html",
)
def idle_ebs_volumes(session, region) -> List[Finding]:
    """Flag unattached EBS volumes as idle provisioned hardware."""
    findings: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(
        Filters=[{"Name": "status", "Values": ["available"]}]
    ):
        for vol in page.get("Volumes", []):
            findings.append(
                Finding(
                    pillar=PILLAR,
                    check_id="SUS05-BP01",
                    title="Unattached EBS volume represents idle provisioned storage",
                    severity=Severity.LOW,
                    resource_id=vol["VolumeId"],
                    region=region,
                    detail=(
                        f"Volume '{vol['VolumeId']}' ({vol.get('Size')} GiB) is "
                        "provisioned but attached to nothing. Idle storage still "
                        "consumes allocated capacity."
                    ),
                    recommendation=(
                        "Delete unused volumes (snapshot first if needed) so you "
                        "provision only the minimum hardware required."
                    ),
                    wa_reference=f"{_SUS}/sus_sus_hardware_a2.html",
                )
            )
    return findings


@check(
    "SUS04-BP03",
    "S3 buckets use lifecycle policies to manage data",
    f"{_SUS}/sus_sus_data_a4.html",
    global_check=True,
)
def s3_lifecycle_policies(session, region) -> List[Finding]:
    """Flag S3 buckets without any lifecycle configuration.

    Buckets are global; evaluated once without per-bucket region lookups.
    """
    findings: List[Finding] = []
    s3 = session.client("s3")
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=name)
            has_lifecycle = True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchLifecycleConfiguration":
                has_lifecycle = False
            elif code in ("AccessDenied", "AllAccessDisabled"):
                # Can't inspect this bucket; skip rather than abort the check.
                continue
            else:
                raise
        if not has_lifecycle:
            findings.append(
                Finding(
                    pillar=PILLAR,
                    check_id="SUS04-BP03",
                    title="S3 bucket has no lifecycle policy",
                    severity=Severity.LOW,
                    resource_id=name,
                    region="global",
                    detail=(
                        f"Bucket '{name}' has no lifecycle configuration, so data "
                        "is never transitioned to lower-impact storage classes or "
                        "expired automatically."
                    ),
                    recommendation=(
                        "Add lifecycle rules to transition cold data to "
                        "infrequent-access/Glacier tiers and expire data that is "
                        "no longer needed."
                    ),
                    wa_reference=f"{_SUS}/sus_sus_data_a4.html",
                )
            )
    return findings


@check(
    "SUS02-BP01",
    "Auto Scaling groups scale dynamically with demand",
    f"{_SUS}/sus_sus_user_a2.html",
)
def static_auto_scaling_groups(session, region) -> List[Finding]:
    """Flag Auto Scaling groups pinned to a fixed size (min == max)."""
    findings: List[Finding] = []
    asg = session.client("autoscaling", region_name=region)
    for page in asg.get_paginator("describe_auto_scaling_groups").paginate():
        for group in page.get("AutoScalingGroups", []):
            min_size = group.get("MinSize", 0)
            max_size = group.get("MaxSize", 0)
            if min_size == max_size and max_size > 0:
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="SUS02-BP01",
                        title="Auto Scaling group has a fixed size (no dynamic scaling)",
                        severity=Severity.LOW,
                        resource_id=group["AutoScalingGroupName"],
                        region=region,
                        detail=(
                            f"Auto Scaling group "
                            f"'{group['AutoScalingGroupName']}' has MinSize == "
                            f"MaxSize == {max_size}, so capacity cannot contract "
                            "when demand falls, wasting energy at low load."
                        ),
                        recommendation=(
                            "Set a lower minimum and use target-tracking or "
                            "scheduled scaling so infrastructure follows demand."
                        ),
                        wa_reference=f"{_SUS}/sus_sus_user_a2.html",
                    )
                )
    return findings


@check(
    "SUS05-BP02",
    "Compute uses instance types with the least impact",
    f"{_SUS}/sus_sus_hardware_a3.html",
)
def previous_generation_instances_sus(session, region) -> List[Finding]:
    """Flag running EC2 instances on previous-generation families (efficiency)."""
    findings: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    ):
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                itype = inst.get("InstanceType", "")
                if is_previous_generation(itype):
                    findings.append(
                        Finding(
                            pillar=PILLAR,
                            check_id="SUS05-BP02",
                            title="EC2 instance uses a higher-impact previous-generation type",
                            severity=Severity.INFO,
                            resource_id=inst["InstanceId"],
                            region=region,
                            detail=(
                                f"Instance '{inst['InstanceId']}' runs on "
                                f"'{itype}' (family '{instance_family(itype)}'). "
                                "Older families are less energy-efficient per unit "
                                "of work than current or Graviton-based types."
                            ),
                            recommendation=(
                                "Move to a current-generation or AWS Graviton "
                                "instance type to reduce the workload's energy "
                                "footprint."
                            ),
                            wa_reference=f"{_SUS}/sus_sus_hardware_a3.html",
                        )
                    )
    return findings


CHECKS = [
    idle_ebs_volumes,
    s3_lifecycle_policies,
    static_auto_scaling_groups,
    previous_generation_instances_sus,
]
