"""Cost Optimization pillar checks.

All checks are read-only (Describe/List/Get). Best-practice IDs are taken from
the AWS Well-Architected Cost Optimization Pillar documentation.
"""

from __future__ import annotations

from typing import List

from .common import Finding, Severity, check, instance_family, is_previous_generation

PILLAR = "Cost Optimization"

_COST = "https://docs.aws.amazon.com/wellarchitected/latest/cost-optimization-pillar"


@check(
    "COST04-BP03",
    "Unattached EBS volumes are decommissioned",
    f"{_COST}/cost_decomissioning_resources_decommission_automatically.html",
)
def unattached_ebs_volumes(session, region) -> List[Finding]:
    """Flag EBS volumes in the 'available' state (attached to nothing)."""
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
                    check_id="COST04-BP03",
                    title="Unattached EBS volume is still being billed",
                    severity=Severity.LOW,
                    resource_id=vol["VolumeId"],
                    region=region,
                    detail=(
                        f"Volume '{vol['VolumeId']}' ({vol.get('Size')} GiB, "
                        f"{vol.get('VolumeType')}) is 'available' - attached to "
                        "no instance - but continues to accrue storage charges."
                    ),
                    recommendation=(
                        "Snapshot the volume if the data may be needed, then "
                        "delete it to stop charges."
                    ),
                    wa_reference=f"{_COST}/cost_decomissioning_resources_decommission_automatically.html",
                )
            )
    return findings


@check(
    "COST04-BP03",
    "Unassociated Elastic IP addresses are released",
    f"{_COST}/cost_decomissioning_resources_decommission_automatically.html",
)
def unassociated_elastic_ips(session, region) -> List[Finding]:
    """Flag Elastic IPs not associated with an instance or network interface."""
    findings: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)
    addresses = ec2.describe_addresses().get("Addresses", [])
    for addr in addresses:
        if not addr.get("AssociationId") and not addr.get("InstanceId"):
            findings.append(
                Finding(
                    pillar=PILLAR,
                    check_id="COST04-BP03",
                    title="Unassociated Elastic IP is being billed",
                    severity=Severity.LOW,
                    resource_id=addr.get("AllocationId", addr.get("PublicIp", "eip")),
                    region=region,
                    detail=(
                        f"Elastic IP {addr.get('PublicIp')} is allocated but not "
                        "associated with any running resource. Idle EIPs incur an "
                        "hourly charge."
                    ),
                    recommendation=(
                        "Release the Elastic IP if it is no longer needed, or "
                        "associate it with an active resource."
                    ),
                    wa_reference=f"{_COST}/cost_decomissioning_resources_decommission_automatically.html",
                )
            )
    return findings


@check(
    "COST06-BP02",
    "Compute uses current-generation instance types",
    f"{_COST}/cost_type_size_number_resources_data.html",
)
def previous_generation_instances(session, region) -> List[Finding]:
    """Flag running EC2 instances on previous-generation families (cost angle)."""
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
                            check_id="COST06-BP02",
                            title="EC2 instance uses a previous-generation type",
                            severity=Severity.LOW,
                            resource_id=inst["InstanceId"],
                            region=region,
                            detail=(
                                f"Instance '{inst['InstanceId']}' runs on "
                                f"'{itype}' (family '{instance_family(itype)}'), a "
                                "previous-generation type that is typically more "
                                "expensive per unit of performance than current "
                                "families."
                            ),
                            recommendation=(
                                "Evaluate migrating to the current-generation "
                                "equivalent (e.g. m4 -> m7i / m7g) for better "
                                "price-performance."
                            ),
                            wa_reference=f"{_COST}/cost_type_size_number_resources_data.html",
                        )
                    )
    return findings


@check(
    "COST02-BP05",
    "Cost controls such as AWS Budgets are configured",
    f"{_COST}/cost_govern_usage_controls.html",
    global_check=True,
)
def budgets_configured(session, region) -> List[Finding]:
    """Flag an account with no AWS Budgets (a basic cost-control guardrail)."""
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    budgets = session.client("budgets")
    resp = budgets.describe_budgets(AccountId=account_id)
    if not resp.get("Budgets"):
        return [
            Finding(
                pillar=PILLAR,
                check_id="COST02-BP05",
                title="No AWS Budgets are configured",
                severity=Severity.MEDIUM,
                resource_id=f"account:{account_id}",
                region="global",
                detail=(
                    "The account has no AWS Budgets defined, so there is no "
                    "proactive alerting when spend approaches a threshold."
                ),
                recommendation=(
                    "Create at least one cost or usage budget with alert "
                    "thresholds to govern spend."
                ),
                wa_reference=f"{_COST}/cost_govern_usage_controls.html",
            )
        ]
    return []


CHECKS = [
    unattached_ebs_volumes,
    unassociated_elastic_ips,
    previous_generation_instances,
    budgets_configured,
]
