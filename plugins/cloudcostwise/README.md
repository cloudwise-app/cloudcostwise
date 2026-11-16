# cloudcostwise skill for Claude

This plugin holds one skill, `aws-waste-scan`. It contains no code and no MCP server: the skill is a
Markdown file that tells Claude how to run the free, open-source
[cloudcostwise](https://github.com/cloudwise-app/cloudcostwise) command line tool and how to read its
result.

Ask Claude: *"Scan my AWS account for waste."*

## What happens when the skill runs

- Claude runs one command in your terminal: `uvx cloudcostwise==0.1.26 scan --format json`. `uvx`
  downloads that exact release of cloudcostwise from PyPI the first time. You need
  [uv](https://docs.astral.sh/uv/) installed and a place where Claude can run commands, such as Claude Code.
- The scan calls AWS from your machine with your own credentials, through the standard AWS credential
  chain (a profile in `~/.aws`, SSO, or environment variables). It only makes read calls (Describe, List,
  Get, Search, Lookup). The minimal policy is in
  [docs/iam-policy.json](https://github.com/cloudwise-app/cloudcostwise/blob/main/docs/iam-policy.json).
- Some of the scan calls AWS Cost Explorer, which AWS bills to you at $0.01 per request (a few cents a
  scan): the Reserved Instance and Savings Plans checks, one request for the account's last 30 days of
  spend, and one KMS spend read when an S3 bucket-key finding appears. The skill tells Claude to say so
  before the first scan, and `--no-cost-explorer` skips all of them.
- The findings go to Claude, like any command output, so it can explain them.
- Nothing is sent to CloudWise unless you have turned sharing on yourself. Sharing a summary of a scan is
  a separate choice you make in your own terminal (`cloudcostwise share`), and the skill tells Claude never
  to run it. If you have already turned sharing on (`cloudcostwise share --on` or
  `CLOUDCOSTWISE_SHARE=yes`), a scan sends the summary as that setting says: the CLI version, whether the
  scan ran in the CLI or MCP, the number of findings, the estimated monthly savings and the number of
  checks run, to `https://api.cloudcostwise.io`. See
  [Sharing a summary](https://github.com/cloudwise-app/cloudcostwise#sharing-a-summary-optional).
- The skill never changes anything in AWS. Fix steps are text for you to review.

## Try it without AWS credentials

Ask Claude for a demo scan. It runs `uvx cloudcostwise==0.1.26 scan --demo --format json`, which
prints a recorded scan of a CloudWise test account: sample data, no AWS call and no network call beyond
the download of the tool.

## Prefer an MCP server?

The same scan is available as a local MCP server for Claude Code, Codex, Cursor, Kiro and Gemini CLI. See
the [main README](https://github.com/cloudwise-app/cloudcostwise#readme).

## License

Apache-2.0. See `LICENSE.md`.
