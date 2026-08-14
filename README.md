# aws-wa-mcp-server

A local [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server
that performs **live, read-only** scans of an AWS account against all six pillars
of the [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/):
Cost Optimization, Reliability, Performance Efficiency, Operational Excellence,
Security, and Sustainability.

Point Claude Desktop or Claude Code at it and ask *"scan my AWS account against
the Well-Architected security pillar"* — you get back concrete findings mapped to
real best-practice IDs (e.g. `SEC05-BP02`, `REL10-BP01`), each with severity, the
offending resource, and a remediation recommendation.

## Design principles

- **Generate-never-mutate.** Every AWS API call is `Describe`/`List`/`Get` only.
  The server can never create, modify, or delete a resource. The minimal IAM
  policy in [`iam-policy-readonly.json`](iam-policy-readonly.json) grants nothing
  but read actions.
- **Per-check failure isolation.** Each check runs independently in a thread
  pool. A missing IAM permission, an unauthorized region, or a transient API
  error on one check is caught (`NoCredentialsError`, `ClientError`,
  `BotoCoreError`, or any unexpected exception) and reported in a
  `checks_skipped` list — it never aborts the rest of the scan.
- **Real best-practice IDs.** `check_id` values are taken from the published AWS
  Well-Architected pillar documentation, not invented.

## MCP SDK version / API

This server targets the latest **`mcp` 2.x** Python SDK, where the server class
is `MCPServer`, imported from `mcp.server.mcpserver`:

```python
from mcp.server.mcpserver import MCPServer
mcp = MCPServer("aws-wa-mcp-server", version="0.1.0")
```

> **Migrating from `mcp` 1.x.** On the 1.x SDK this class was `FastMCP` in
> `mcp.server.fastmcp`. The `add_tool` / `tool` / `run` APIs are
> signature-compatible, so the only change to run on 1.x is the import and the
> constructor call in [`aws_wa_mcp/server.py`](aws_wa_mcp/server.py) — the tool
> functions themselves are unchanged. This project is developed and verified
> against `mcp` 2.0.0; the `pyproject.toml` pin is `mcp>=2.0`.

Transport is **stdio** (for local use with Claude Desktop / Claude Code). There
is intentionally no Lambda/API Gateway variant yet.

## Setup

```bash
# from the repo root
python -m pip install -e .

# (optional) install test dependencies
python -m pip install -e ".[test]"
```

Configure AWS credentials the usual way (any of these work, resolved by boto3):

- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`)
- a named profile via `AWS_PROFILE` or the tool's `profile` argument
- an EC2/ECS instance role

Region resolution order: the tool's `region` argument → the session/profile
default → `AWS_REGION` → `AWS_DEFAULT_REGION` → `us-east-1`.

Attach [`iam-policy-readonly.json`](iam-policy-readonly.json) to the principal
you scan with. It lists exactly the read actions the checks issue and nothing
else.

## Claude Desktop configuration

Add this to your `claude_desktop_config.json`
(`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

For **Claude Code**:

```bash
claude mcp add aws-well-architected -- aws-wa-mcp-server
```

## Tools

Every tool accepts optional `region` and `profile` arguments and returns findings
sorted by severity, a 0–100 pillar `health_score`, and a `checks_skipped` list.

| Tool | Pillar | Checks (real WA best-practice IDs) |
|------|--------|------------------------------------|
| `scan_security` | Security | S3 Block Public Access gaps, account- and bucket-level (`SEC03-BP07`); security groups open to `0.0.0.0/0` on sensitive ports (`SEC05-BP02`); root user access keys present (`SEC02-BP02`); root user MFA missing (`SEC02-BP01`); GuardDuty not enabled (`SEC04-BP01`) |
| `scan_reliability` | Reliability | Single-AZ RDS (`REL10-BP01`); load balancers spanning < 2 AZs (`REL10-BP01`); single-AZ Auto Scaling groups (`REL10-BP01`); EBS volumes with no recent snapshot (`REL09-BP01`); RDS automated backups disabled (`REL09-BP01`) |
| `scan_cost_optimization` | Cost Optimization | Unattached EBS volumes (`COST04-BP03`); unassociated Elastic IPs (`COST04-BP03`); previous-generation EC2 instances (`COST06-BP02`); no AWS Budgets configured (`COST02-BP05`) |
| `scan_performance_efficiency` | Performance Efficiency | gp2 EBS volumes (should be gp3) (`PERF03-BP02`); RDS on magnetic storage (`PERF03-BP02`); EC2 detailed monitoring disabled (`PERF02-BP03`); previous-generation EC2 instances (`PERF02-BP01`) |
| `scan_operational_excellence` | Operational Excellence | No active multi-region CloudTrail (`OPS04-BP02`); AWS Config recorder not recording (`OPS05-BP03`); no CloudWatch alarms (`OPS08-BP04`); log groups with no retention policy (`OPS08-BP02`) |
| `scan_sustainability` | Sustainability | Idle unattached EBS volumes (`SUS05-BP01`); S3 buckets without lifecycle policies (`SUS04-BP03`); fixed-size Auto Scaling groups (`SUS02-BP01`); previous-generation EC2 instances (`SUS05-BP02`) |
| `scan_all_pillars` | All six | Runs every check above and returns an **overall weighted health score** (mean of the six severity-weighted pillar scores), per-pillar results, and the top findings account-wide. |

### Health score

Each pillar starts at 100 and subtracts a penalty per finding, by severity:
`CRITICAL −20`, `HIGH −10`, `MEDIUM −4`, `LOW −1`, `INFO 0` (floored at 0). A
pillar whose checks all passed — or were all skipped — scores 100.
`scan_all_pillars.overall_health_score` is the mean of the six pillar scores.

### Global vs. regional checks

Checks against global services (IAM root settings, the S3 bucket namespace,
account-level Block Public Access, AWS Budgets) are marked `global_check`. They
evaluate account-wide state that does not vary by region and are designed to run
**exactly once**. The S3 checks deliberately iterate the bucket list a single
time and never call `get_bucket_location` per bucket. The harness's
`include_global` flag lets a future multi-region loop run these once (first
region) and skip them for the rest, so IAM/S3/account checks never fan out per
region.

## Testing

The suite uses [`moto`](https://github.com/getmoto/moto) to mock boto3, so it
runs in CI with no live AWS calls or credentials:

```bash
python -m pip install -e ".[test]"
pytest -q
```

Coverage includes the harness's failure-isolation and scoring logic (with
`unittest.mock`-style fake checks) plus each pillar's checks provisioned against
mocked AWS backends.

## Limitations

- **stdio transport only.** No Lambda/API Gateway deployment.
- **Single region per invocation** (plus global-service checks). Pass different
  `region` values to cover more regions; the harness is already structured to
  run global checks only once when looped across regions.
- Findings are heuristics aligned to best practices, not a substitute for the
  full AWS Well-Architected Tool review or a formal audit.
