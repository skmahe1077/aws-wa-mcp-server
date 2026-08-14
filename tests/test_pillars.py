"""Integration-style tests for each pillar's checks against mocked AWS (moto).

Each test provisions the minimal resources that should trigger (or not trigger)
a specific check, then runs that check function directly and asserts on the
returned findings. No real AWS calls are made.
"""

import boto3
import pytest
from moto import mock_aws

from aws_wa_mcp.pillars import (
    cost_optimization,
    operational_excellence,
    performance_efficiency,
    reliability,
    security,
    sustainability,
)
from aws_wa_mcp.pillars.common import Severity

REGION = "us-east-1"
AMI = "ami-12c6146b"  # moto's built-in example AMI


@pytest.fixture
def sess():
    return boto3.Session(region_name=REGION)


def _ids(findings):
    return {f.check_id for f in findings}


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


@mock_aws
def test_security_group_open_to_world(sess):
    ec2 = sess.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(
        GroupName="open", Description="open", VpcId=vpc
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    findings = security.security_groups_open_to_world(sess, REGION)
    assert any(f.resource_id == sg for f in findings)
    assert all(f.severity == Severity.CRITICAL for f in findings)


@mock_aws
def test_security_group_restricted_is_clean(sess):
    ec2 = sess.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(
        GroupName="restricted", Description="ok", VpcId=vpc
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )
    findings = security.security_groups_open_to_world(sess, REGION)
    assert findings == []


@mock_aws
def test_root_mfa_missing_flagged(sess):
    findings = security.root_mfa_enabled(sess, REGION)
    assert _ids(findings) == {"SEC02-BP01"}
    assert findings[0].severity == Severity.CRITICAL


@mock_aws
def test_guardduty_absent_flagged(sess):
    findings = security.guardduty_enabled(sess, REGION)
    assert _ids(findings) == {"SEC04-BP01"}


@mock_aws
def test_s3_public_access_block_gap_flagged(sess):
    s3 = sess.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="my-open-bucket")
    findings = security.s3_public_access_block(sess, REGION)
    # Account-level block is absent -> at least the account finding fires.
    assert "SEC03-BP07" in _ids(findings)
    assert any(f.resource_id.startswith("account:") for f in findings)


# ---------------------------------------------------------------------------
# Reliability
# ---------------------------------------------------------------------------


def _make_rds(sess, **overrides):
    rds = sess.client("rds", region_name=REGION)
    params = dict(
        DBInstanceIdentifier="db1",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=20,
        MultiAZ=False,
        BackupRetentionPeriod=0,
        StorageType="standard",
    )
    params.update(overrides)
    rds.create_db_instance(**params)


@mock_aws
def test_rds_single_az_flagged(sess):
    _make_rds(sess, MultiAZ=False)
    findings = reliability.rds_multi_az(sess, REGION)
    assert _ids(findings) == {"REL10-BP01"}
    assert findings[0].resource_id == "db1"


@mock_aws
def test_rds_multi_az_is_clean(sess):
    _make_rds(sess, MultiAZ=True)
    findings = reliability.rds_multi_az(sess, REGION)
    assert findings == []


@mock_aws
def test_rds_backups_disabled_flagged(sess):
    _make_rds(sess, BackupRetentionPeriod=0)
    findings = reliability.rds_backups_enabled(sess, REGION)
    assert _ids(findings) == {"REL09-BP01"}


@mock_aws
def test_asg_single_az_flagged(sess):
    autoscaling = sess.client("autoscaling", region_name=REGION)
    autoscaling.create_launch_configuration(
        LaunchConfigurationName="lc", ImageId=AMI, InstanceType="t3.micro"
    )
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName="asg1",
        LaunchConfigurationName="lc",
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=1,
        AvailabilityZones=[f"{REGION}a"],
    )
    findings = reliability.asg_multi_az(sess, REGION)
    assert _ids(findings) == {"REL10-BP01"}
    assert findings[0].resource_id == "asg1"


@mock_aws
def test_ebs_no_snapshot_flagged(sess):
    ec2 = sess.client("ec2", region_name=REGION)
    # Volume attached to a running instance, with no snapshots.
    run = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1)
    instance_id = run["Instances"][0]["InstanceId"]
    vol = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    ec2.attach_volume(VolumeId=vol, InstanceId=instance_id, Device="/dev/sdf")
    findings = reliability.ebs_recent_snapshot(sess, REGION)
    assert vol in {f.resource_id for f in findings}


# ---------------------------------------------------------------------------
# Cost Optimization
# ---------------------------------------------------------------------------


@mock_aws
def test_unattached_ebs_flagged(sess):
    ec2 = sess.client("ec2", region_name=REGION)
    vol = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    findings = cost_optimization.unattached_ebs_volumes(sess, REGION)
    assert vol in {f.resource_id for f in findings}


@mock_aws
def test_unassociated_eip_flagged(sess):
    ec2 = sess.client("ec2", region_name=REGION)
    ec2.allocate_address(Domain="vpc")
    findings = cost_optimization.unassociated_elastic_ips(sess, REGION)
    assert _ids(findings) == {"COST04-BP03"}


@mock_aws
def test_previous_gen_instance_flagged_cost(sess):
    ec2 = sess.client("ec2", region_name=REGION)
    ec2.run_instances(
        ImageId=AMI, MinCount=1, MaxCount=1, InstanceType="m4.large"
    )
    findings = cost_optimization.previous_generation_instances(sess, REGION)
    assert _ids(findings) == {"COST06-BP02"}


@mock_aws
def test_no_budgets_flagged(sess):
    findings = cost_optimization.budgets_configured(sess, REGION)
    assert _ids(findings) == {"COST02-BP05"}


# ---------------------------------------------------------------------------
# Performance Efficiency
# ---------------------------------------------------------------------------


@mock_aws
def test_gp2_volume_flagged(sess):
    ec2 = sess.client("ec2", region_name=REGION)
    vol = ec2.create_volume(
        AvailabilityZone=f"{REGION}a", Size=8, VolumeType="gp2"
    )["VolumeId"]
    findings = performance_efficiency.gp2_volumes(sess, REGION)
    assert vol in {f.resource_id for f in findings}
    assert _ids(findings) == {"PERF03-BP02"}


@mock_aws
def test_rds_magnetic_flagged(sess):
    _make_rds(sess, StorageType="standard")
    findings = performance_efficiency.rds_magnetic_storage(sess, REGION)
    assert _ids(findings) == {"PERF03-BP02"}


# ---------------------------------------------------------------------------
# Operational Excellence
# ---------------------------------------------------------------------------


@mock_aws
def test_no_cloudtrail_flagged(sess):
    findings = operational_excellence.cloudtrail_enabled(sess, REGION)
    assert _ids(findings) == {"OPS04-BP02"}


@mock_aws
def test_no_config_recorder_flagged(sess):
    findings = operational_excellence.config_recorder_enabled(sess, REGION)
    assert _ids(findings) == {"OPS05-BP03"}


@mock_aws
def test_no_alarms_flagged(sess):
    findings = operational_excellence.cloudwatch_alarms_exist(sess, REGION)
    assert _ids(findings) == {"OPS08-BP04"}


@mock_aws
def test_log_group_without_retention_flagged(sess):
    logs = sess.client("logs", region_name=REGION)
    logs.create_log_group(logGroupName="/aws/test")
    findings = operational_excellence.log_group_retention(sess, REGION)
    assert _ids(findings) == {"OPS08-BP02"}


# ---------------------------------------------------------------------------
# Sustainability
# ---------------------------------------------------------------------------


@mock_aws
def test_static_asg_flagged(sess):
    autoscaling = sess.client("autoscaling", region_name=REGION)
    autoscaling.create_launch_configuration(
        LaunchConfigurationName="lc", ImageId=AMI, InstanceType="t3.micro"
    )
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName="fixed",
        LaunchConfigurationName="lc",
        MinSize=2,
        MaxSize=2,
        DesiredCapacity=2,
        AvailabilityZones=[f"{REGION}a", f"{REGION}b"],
    )
    findings = sustainability.static_auto_scaling_groups(sess, REGION)
    assert _ids(findings) == {"SUS02-BP01"}


@mock_aws
def test_s3_no_lifecycle_flagged(sess):
    s3 = sess.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="nolifecycle-bucket")
    findings = sustainability.s3_lifecycle_policies(sess, REGION)
    assert "nolifecycle-bucket" in {f.resource_id for f in findings}


# ---------------------------------------------------------------------------
# End-to-end: run_checks harness over a real pillar with moto
# ---------------------------------------------------------------------------


@mock_aws
def test_run_checks_over_cost_pillar(sess):
    from aws_wa_mcp.pillars.common import run_checks

    ec2 = sess.client("ec2", region_name=REGION)
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)  # unattached

    result = run_checks(
        cost_optimization.CHECKS, sess, REGION, cost_optimization.PILLAR
    )
    assert result.checks_run == len(cost_optimization.CHECKS)
    assert result.checks_skipped == []
    assert result.findings  # at least the unattached volume + no-budgets
    # findings must come back severity-sorted (descending rank)
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)
