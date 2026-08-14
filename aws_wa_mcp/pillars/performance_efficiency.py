"""Performance Efficiency pillar checks.

All checks are read-only (Describe/List/Get). Best-practice IDs are taken from
the AWS Well-Architected Performance Efficiency Pillar documentation.
"""

from __future__ import annotations

from typing import List

from .common import Finding, Severity, check, instance_family, is_previous_generation

PILLAR = "Performance Efficiency"

_PERF = "https://docs.aws.amazon.com/wellarchitected/latest/performance-efficiency-pillar"


@check(
    "PERF03-BP02",
    "EBS volumes use gp3 rather than legacy gp2",
    f"{_PERF}/perf_data_evaluate_configuration_options_data_store.html",
)
def gp2_volumes(session, region) -> List[Finding]:
    """Flag gp2 EBS volumes (gp3 offers better, decoupled performance)."""
    findings: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(
        Filters=[{"Name": "volume-type", "Values": ["gp2"]}]
    ):
        for vol in page.get("Volumes", []):
            findings.append(
                Finding(
                    pillar=PILLAR,
                    check_id="PERF03-BP02",
                    title="EBS volume uses the older gp2 volume type",
                    severity=Severity.LOW,
                    resource_id=vol["VolumeId"],
                    region=region,
                    detail=(
                        f"Volume '{vol['VolumeId']}' ({vol.get('Size')} GiB) is "
                        "gp2. On gp2, IOPS are tied to size; gp3 lets you "
                        "provision IOPS/throughput independently, usually at "
                        "lower cost."
                    ),
                    recommendation=(
                        "Modify the volume type to gp3 and tune IOPS/throughput "
                        "to the workload's needs."
                    ),
                    wa_reference=f"{_PERF}/perf_data_evaluate_configuration_options_data_store.html",
                )
            )
    return findings


@check(
    "PERF03-BP02",
    "RDS instances use SSD storage rather than magnetic",
    f"{_PERF}/perf_data_evaluate_configuration_options_data_store.html",
)
def rds_magnetic_storage(session, region) -> List[Finding]:
    """Flag RDS instances still on legacy magnetic ('standard') storage."""
    findings: List[Finding] = []
    rds = session.client("rds", region_name=region)
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            if db.get("StorageType") == "standard":
                findings.append(
                    Finding(
                        pillar=PILLAR,
                        check_id="PERF03-BP02",
                        title="RDS instance uses legacy magnetic storage",
                        severity=Severity.MEDIUM,
                        resource_id=db["DBInstanceIdentifier"],
                        region=region,
                        detail=(
                            f"RDS instance '{db['DBInstanceIdentifier']}' uses "
                            "magnetic ('standard') storage, which offers lower "
                            "and less predictable performance than SSD (gp3/io2)."
                        ),
                        recommendation=(
                            "Modify the instance to use gp3 or io2 SSD storage "
                            "for better and more consistent performance."
                        ),
                        wa_reference=f"{_PERF}/perf_data_evaluate_configuration_options_data_store.html",
                    )
                )
    return findings


@check(
    "PERF02-BP03",
    "EC2 instances collect detailed (1-minute) compute metrics",
    f"{_PERF}/perf_compute_hardware_collect_compute_related_metrics.html",
)
def ec2_detailed_monitoring(session, region) -> List[Finding]:
    """Flag running EC2 instances with only basic (5-minute) monitoring."""
    findings: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    ):
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                state = inst.get("Monitoring", {}).get("State")
                if state in ("disabled", "disabling"):
                    findings.append(
                        Finding(
                            pillar=PILLAR,
                            check_id="PERF02-BP03",
                            title="EC2 instance has detailed monitoring disabled",
                            severity=Severity.INFO,
                            resource_id=inst["InstanceId"],
                            region=region,
                            detail=(
                                f"Instance '{inst['InstanceId']}' emits metrics "
                                "at 5-minute (basic) granularity, limiting "
                                "visibility for right-sizing and scaling "
                                "decisions."
                            ),
                            recommendation=(
                                "Enable detailed (1-minute) monitoring where "
                                "finer-grained compute metrics aid performance "
                                "tuning and autoscaling."
                            ),
                            wa_reference=f"{_PERF}/perf_compute_hardware_collect_compute_related_metrics.html",
                        )
                    )
    return findings


@check(
    "PERF02-BP01",
    "Compute uses current-generation instance types",
    f"{_PERF}/perf_compute_hardware_evaluate_options.html",
)
def previous_generation_instances_perf(session, region) -> List[Finding]:
    """Flag running EC2 instances on previous-generation families (perf angle)."""
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
                            check_id="PERF02-BP01",
                            title="EC2 instance uses a previous-generation type",
                            severity=Severity.LOW,
                            resource_id=inst["InstanceId"],
                            region=region,
                            detail=(
                                f"Instance '{inst['InstanceId']}' runs on "
                                f"'{itype}' (family '{instance_family(itype)}'). "
                                "Current-generation families offer faster CPUs, "
                                "more memory bandwidth and better networking."
                            ),
                            recommendation=(
                                "Benchmark and move to the current-generation "
                                "equivalent (Graviton where supported) for higher "
                                "performance efficiency."
                            ),
                            wa_reference=f"{_PERF}/perf_compute_hardware_evaluate_options.html",
                        )
                    )
    return findings


CHECKS = [
    gp2_volumes,
    rds_magnetic_storage,
    ec2_detailed_monitoring,
    previous_generation_instances_perf,
]
