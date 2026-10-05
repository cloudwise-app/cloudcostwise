# cloudcostwise

<!-- mcp-name: io.github.cloudwise-app/cloudcostwise -->

Find AWS waste from your terminal or your AI assistant. `cloudcostwise` runs CloudWise's open waste
checks on your own machine, with your own read-only AWS credentials.

- **Nothing leaves your machine.** The only network calls are AWS API calls in
  your account. No signup, no IAM role for a third party, no telemetry.
- **It cannot change anything.** Every AWS call goes through a guard that
  refuses any operation that isn't a `Describe`, `List`, `Get`, `Search` or
  `Lookup`, whatever your credentials allow.
- **20 of CloudWise's 46 service checks**: EC2, Lambda, SageMaker, WorkSpaces,
  Lightsail, EBS, S3, EFS, ECR, RDS, DynamoDB, ElastiCache, Elastic IPs, NAT
  gateways and load balancers, VPC endpoints, dangling DNS records, CloudWatch
  logs and dashboards, security posture, RI/Savings Plans opportunities, and
  Compute Optimizer.

## Install and run

```bash
pipx install cloudcostwise          # or: uvx cloudcostwise scan
cloudcostwise scan                      # us-east-1 plus your profile's region
cloudcostwise scan --profile prod --regions all
cloudcostwise scan --format json > waste.json
```

Options:

| Option | Meaning |
|---|---|
| `--profile NAME` | AWS profile; otherwise the standard credential chain (env vars, SSO, instance role) |
| `--regions LIST` | Comma-separated regions, or `all` for every enabled region. Account-level checks (Cost Explorer, Route 53) run once, in us-east-1 |
| `--format table\|markdown\|json` | Output format |
| `--no-cost-explorer` | Make no Cost Explorer call. AWS bills those at $0.01 per request and a scan makes about 13. Skips the RI/Savings Plans checks; extended-support surcharges fall back to estimates |
| `--parallel N` | Regions scanned at once, each in its own process (default 4; `--regions all` takes ~2–3 min instead of ~10) |
| `--verbose` | Show data warnings (checks that could not read a metric report it as missing, never as zero) |

## Use it from Claude Code, Codex or any MCP client

`cloudcostwise mcp` runs the same scan as an MCP server (stdio). Then ask your
assistant: *"Where am I wasting money on AWS?"*

The plugin and registry entries start the server with `uvx`, so install
[uv](https://docs.astral.sh/uv/) first (`brew install uv` or `pipx install uv`).

Claude Code, as a plugin (asks for your AWS profile):

```text
/plugin marketplace add cloudwise-app/cloudcostwise
/plugin install cloudcostwise@cloudcostwise
```

Claude Code, as a plain MCP server:

```bash
claude mcp add cloudcostwise -- uvx cloudcostwise mcp
# a specific profile:
claude mcp add cloudcostwise -e AWS_PROFILE=prod -- uvx cloudcostwise mcp
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.cloudcostwise]
command = "uvx"
args = ["cloudcostwise", "mcp"]
env = { AWS_PROFILE = "prod" }
```

Tools, all read-only: `scan`, `list_findings`, `explain_finding`,
`fix_guidance`. `fix_guidance` returns the steps and AWS CLI command as text
for you to review; nothing is ever executed. The assistant is told about the
Cost Explorer cost before it scans, and `include_cost_explorer=false` skips it.

## Permissions

`ReadOnlyAccess` (AWS managed) is enough. The minimal policy the checks use is
in [`docs/iam-policy.json`](docs/iam-policy.json). It was derived from a scan of
an account with most supported resource types; if a check lacks a permission,
the scan says so in its data warnings instead of failing.

## How the numbers are counted

Each finding shows an estimated monthly saving. **Advisory** waste types, ones
CloudWise could not validate against a real AWS resource, are listed but never
added to the total.

## What the hosted product adds

The other 26 service checks (Glue, ECS, Step Functions, Backup, CloudFront,
commitments and more), history and trends, alerts, and safe automated fixes:
<https://cloudcostwise.io/connect?utm_source=cloudcostwise&utm_medium=cli>.

## License

FSL-1.1-ALv2. Each release becomes Apache-2.0 two years after it ships.

## How we know it's right

See [VALIDATION.md](VALIDATION.md): the validation level of every waste type this tool reports, from L0 (unit-tested) to L2 (fired on a real AWS resource and stayed silent on a healthy twin) and beyond.
