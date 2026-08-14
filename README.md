<div align="center">

# AWS Well-Architected MCP Server

**Live, read-only Well-Architected reviews of your AWS account, straight from your assistant.**

Scan an AWS account against all six pillars of the [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/) - Cost Optimization, Reliability, Performance Efficiency, Operational Excellence, Security, and Sustainability - and get back concrete findings mapped to real best-practice IDs, each with a severity, the offending resource, and a remediation recommendation.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-brightgreen.svg)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-29%20passed-brightgreen.svg)](#development)
[![Read-only](https://img.shields.io/badge/AWS-read--only-blueviolet.svg)](#design-principles)

<br/>

[Features](#features) | [Installation](#installation) | [Configuration](#configuration) | [Usage](#usage) | [Development](#development)

</div>

---

## Features

The server exposes **7 scanning tools** - one per Well-Architected pillar, plus an account-wide `scan_all_pillars` - all reachable through a single MCP interface. Point your assistant at the pillar you care about and ask.

Every tool accepts optional `region` and `profile` arguments and returns findings sorted by severity, a 0-100 pillar `health_score`, and a `checks_skipped` list for any check blocked by missing permissions or an API error.

<details>
<summary><strong>Security</strong> - <code>scan_security</code></summary>

| Check | Best-practice ID |
|---|---|
| S3 Block Public Access gaps, account- and bucket-level | `SEC03-BP07` |
| Security groups open to `0.0.0.0/0` on sensitive ports | `SEC05-BP02` |
| Root user access keys present | `SEC02-BP02` |
| Root user MFA missing | `SEC02-BP01` |
| GuardDuty not enabled | `SEC04-BP01` |

</details>

<details>
<summary><strong>Reliability</strong> - <code>scan_reliability</code></summary>

| Check | Best-practice ID |
|---|---|
| Single-AZ RDS instances | `REL10-BP01` |
| Load balancers spanning < 2 AZs | `REL10-BP01` |
| Single-AZ Auto Scaling groups | `REL10-BP01` |
| EBS volumes with no recent snapshot | `REL09-BP01` |
| RDS automated backups disabled | `REL09-BP01` |

</details>

<details>
<summary><strong>Cost Optimization</strong> - <code>scan_cost_optimization</code></summary>

| Check | Best-practice ID |
|---|---|
| Unattached EBS volumes | `COST04-BP03` |
| Unassociated Elastic IPs | `COST04-BP03` |
| Previous-generation EC2 instances | `COST06-BP02` |
| No AWS Budgets configured | `COST02-BP05` |

</details>

<details>
<summary><strong>Performance Efficiency</strong> - <code>scan_performance_efficiency</code></summary>

| Check | Best-practice ID |
|---|---|
| gp2 EBS volumes (should be gp3) | `PERF03-BP02` |
| RDS on magnetic storage | `PERF03-BP02` |
| EC2 detailed monitoring disabled | `PERF02-BP03` |
| Previous-generation EC2 instances | `PERF02-BP01` |

</details>

<details>
<summary><strong>Operational Excellence</strong> - <code>scan_operational_excellence</code></summary>

| Check | Best-practice ID |
|---|---|
| No active multi-region CloudTrail | `OPS04-BP02` |
| AWS Config recorder not recording | `OPS05-BP03` |
| No CloudWatch alarms | `OPS08-BP04` |
| Log groups with no retention policy | `OPS08-BP02` |

</details>

<details>
<summary><strong>Sustainability</strong> - <code>scan_sustainability</code></summary>

| Check | Best-practice ID |
|---|---|
| Idle unattached EBS volumes | `SUS05-BP01` |
| S3 buckets without lifecycle policies | `SUS04-BP03` |
| Fixed-size Auto Scaling groups | `SUS02-BP01` |
| Previous-generation EC2 instances | `SUS05-BP02` |

</details>

<details>
<summary><strong>All pillars</strong> - <code>scan_all_pillars</code></summary>

Runs every check above and returns an **overall weighted health score** (the mean of the six severity-weighted pillar scores), per-pillar `health_score` values, full per-pillar results, aggregate totals, and the top findings account-wide.

</details>

### Health score

Each pillar starts at 100 and subtracts a penalty per finding, by severity: `CRITICAL -20`, `HIGH -10`, `MEDIUM -4`, `LOW -1`, `INFO 0` (floored at 0). A pillar whose checks all passed - or were all skipped - scores 100. `scan_all_pillars.overall_health_score` is the mean of the six pillar scores.

---

## Design principles

- **Generate-never-mutate.** Every AWS API call is `Describe`/`List`/`Get` only. The server can never create, modify, or delete a resource. The minimal IAM policy in [`iam-policy-readonly.json`](iam-policy-readonly.json) grants nothing but read actions.
- **Per-check failure isolation.** Each check runs independently in a thread pool. A missing IAM permission, an unauthorized region, or a transient API error on one check is caught (`NoCredentialsError`, `ClientError`, `BotoCoreError`, or any unexpected exception) and reported in a `checks_skipped` list - it never aborts the rest of the scan.
- **Real best-practice IDs.** `check_id` values are taken from the published AWS Well-Architected pillar documentation, not invented.
- **Global vs. regional checks.** Checks against global services (IAM root settings, the S3 bucket namespace, account-level Block Public Access, AWS Budgets) are marked `global_check`. They evaluate account-wide state that does not vary by region and are designed to run exactly once - so a future multi-region loop never fans them out per region.

---

## Installation

### From PyPI (recommended)

```bash
pip install aws-wa-mcp-server
```

Or run it without installing anything, using [uv](https://docs.astral.sh/uv/):

```bash
uvx aws-wa-mcp-server
```

### From source

```bash
git clone https://github.com/skmahe1077/aws-wa-mcp-server.git
cd aws-wa-mcp-server
python -m pip install -e .
```

### With test dependencies

```bash
python -m pip install -e ".[test]"
```

This installs the console script `aws-wa-mcp-server` (equivalent to `python -m aws_wa_mcp.server`).

> **Requirements:** Python 3.10+, `mcp>=2.0`, and `boto3>=1.28`. Transport is **stdio**, for local use with Claude Desktop / Claude Code.

---

## Configuration

Set up AWS access **before** wiring the server into an MCP client - the client only launches the server; it does not create credentials. Do these three steps first, then move on to [Usage](#usage).

### Step 1 - Configure AWS credentials

Create a named profile with the AWS CLI (recommended), so the server can assume it later:

```bash
aws configure --profile wa-scan
# AWS Access Key ID     [None]: ...
# AWS Secret Access Key [None]: ...
# Default region name   [None]: eu-west-1
# Default output format [None]: json
```

Credentials are resolved the usual way by boto3, so any of these also work instead of a profile:

- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`)
- a named profile via `AWS_PROFILE` or the tool's `profile` argument
- an EC2/ECS instance role (when running on AWS compute)

**Region resolution order:** the tool's `region` argument → the session/profile default → `AWS_REGION` → `AWS_DEFAULT_REGION` → `us-east-1`.

### Step 2 - Attach the read-only IAM policy

Grant the principal exactly the read actions the checks need - nothing else. Attach [`iam-policy-readonly.json`](iam-policy-readonly.json):

```bash
aws iam put-user-policy \
  --user-name your-user \
  --policy-name AwsWaMcpReadOnlyScan \
  --policy-document file://iam-policy-readonly.json \
  --profile wa-scan
```

The policy lists only these read actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AwsWaMcpReadOnlyScan",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "iam:GetAccountSummary",
        "ec2:Describe*",
        "rds:DescribeDBInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        "autoscaling:DescribeAutoScalingGroups",
        "s3:ListAllMyBuckets",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetLifecycleConfiguration",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "budgets:ViewBudget",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "cloudwatch:DescribeAlarms",
        "logs:DescribeLogGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

> The canonical policy in the repo enumerates each `ec2:Describe*` action individually. Use it verbatim for a least-privilege setup.

### Step 3 - Verify access

Confirm the profile resolves before pointing an MCP client at it:

```bash
aws sts get-caller-identity --profile wa-scan
```

A response with your account ID and ARN means you're ready. Any check that is still denied at scan time is reported in `checks_skipped` rather than failing the whole scan, so you can tighten permissions iteratively.

---

## Usage

### 1. Configure your MCP client

<details>
<summary><strong>Claude Desktop</strong></summary>

Add this to your Claude Desktop config:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "aws-well-architected": {
      "command": "aws-wa-mcp-server",
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_REGION": "eu-west-2"
      }
    }
  }
}
```

If the console script is not on Claude's `PATH`, use the interpreter form:

```json
{
  "mcpServers": {
    "aws-well-architected": {
      "command": "python",
      "args": ["-m", "aws_wa_mcp.server"],
      "env": { "AWS_PROFILE": "your-profile", "AWS_REGION": "eu-west-2" }
    }
  }
}
```

</details>

<details>
<summary><strong>Claude Code (CLI)</strong></summary>

```bash
# Using the console script
claude mcp add aws-well-architected -- aws-wa-mcp-server

# Or with environment variables
claude mcp add aws-well-architected \
  -e AWS_PROFILE=your-profile \
  -e AWS_REGION=eu-west-2 \
  -- aws-wa-mcp-server
```

</details>

<details>
<summary><strong>VS Code</strong></summary>

Add this to `.vscode/settings.json` or your user settings:

```json
{
  "mcp": {
    "servers": {
      "aws-well-architected": {
        "command": "aws-wa-mcp-server",
        "env": {
          "AWS_PROFILE": "your-profile",
          "AWS_REGION": "eu-west-2"
        }
      }
    }
  }
}
```

</details>

<details>
<summary><strong>Kiro</strong></summary>

Kiro reads MCP servers from `.kiro/settings/mcp.json` (workspace-level) or `~/.kiro/settings/mcp.json` (user-level). Add:

```json
{
  "mcpServers": {
    "aws-well-architected": {
      "command": "uvx",
      "args": ["aws-wa-mcp-server"],
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_REGION": "eu-west-2"
      },
      "disabled": false,
      "autoApprove": ["scan_all_pillars"]
    }
  }
}
```

If you installed the package with pip instead of using `uvx`, set `"command": "aws-wa-mcp-server"` and drop the `args`. Kiro picks up changes to `mcp.json` automatically; every tool is read-only, so it's safe to add scans to `autoApprove` if you'd rather not confirm each run.

</details>

### 2. Start asking

Once it's wired up, just talk to your assistant in plain language:

```
"Scan my AWS account against the Well-Architected security pillar"
"Check my account for reliability risks like single-AZ RDS and load balancers"
"Where am I wasting money? Run the cost optimization scan"
"Audit performance efficiency - flag gp2 volumes and previous-gen instances"
"Run the operational excellence checks in eu-west-2"
"Scan sustainability using the 'audit' profile"
"Run all six Well-Architected pillars and give me the overall health score"
```

---

## Development

```bash
git clone https://github.com/skmahe1077/aws-wa-mcp-server.git
cd aws-wa-mcp-server
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]"

# Run the tests
pytest -q
```

The suite uses [`moto`](https://github.com/getmoto/moto) to mock boto3, so all **29 tests** run in CI with no live AWS calls or credentials. Coverage includes the harness's failure-isolation and scoring logic (with `unittest.mock`-style fake checks) plus each pillar's checks provisioned against mocked AWS backends.

Each pillar lives in its own module under `aws_wa_mcp/pillars/` and exposes a `CHECKS` list; `aws_wa_mcp/server.py` registers one `scan_<pillar>` tool per module plus `scan_all_pillars`, so adding a check is a change to a single pillar module.

---

## Limitations

- **stdio transport only.** No Lambda/API Gateway deployment.
- **Single region per invocation** (plus global-service checks). Pass different `region` values to cover more regions; the harness is already structured to run global checks only once when looped across regions.
- Findings are heuristics aligned to best practices, not a substitute for the full AWS Well-Architected Tool review or a formal audit.

---

## License

[MIT](LICENSE)
