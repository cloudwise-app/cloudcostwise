---
name: aws-waste-scan
description: Scan the user's own AWS account for waste (idle, unattached, oversized or forgotten resources) with cloudcostwise, a free open-source scanner that runs on the user's machine with their own read-only credentials, then explain the findings. Use when the user asks for such a scan, or asks which resources in their AWS account cost money for nothing.
---

# Scan an AWS account for waste with cloudcostwise

cloudcostwise is a free, open-source (Apache-2.0) command line tool. It reads the user's own AWS account
with their own credentials, from their own machine, and reports resources that cost money without being
used. It only makes read calls (Describe, List, Get, Search, Lookup). It cannot change anything in AWS.

This skill needs a terminal on the user's machine, where their AWS credentials are, and
[uv](https://docs.astral.sh/uv/) installed. If you cannot run commands there, give the user the command
below to run themselves and read the output they paste back.

## Before the first scan

Tell the user two things, and wait for their answer:

1. The scan is read-only and runs on their machine with their own AWS credentials.
2. Some of the scan calls AWS Cost Explorer, which AWS bills to them at $0.01 per request (a few cents a
   scan): the Reserved Instance and Savings Plans checks, one request for the account's last 30 days of
   spend, and one KMS spend read when an S3 bucket-key finding appears. `--no-cost-explorer` skips all of
   them.

If the user has not said which AWS profile or regions to scan, ask. Without `--profile` the scan uses the
standard AWS credential chain. Without `--regions` it scans us-east-1 plus the profile's region.

## Run the scan

```bash
uvx cloudcostwise==0.1.26 scan --format json
```

Options, added only as the user asked:

- `--profile NAME`: the AWS profile to use.
- `--regions us-east-1,eu-west-1` or `--regions all`: the regions to scan.
- `--no-cost-explorer`: make no Cost Explorer call.
- `--anonymize`: replace the account ID and the resource IDs, names and ARNs it recognizes with
  placeholders. It is not complete, so the user should review a report before sending it to anyone.

A scan takes about 30 to 60 seconds per region. If `uvx` is not found, tell the user to install uv
(`brew install uv` or `pipx install uv`). Do not install it for them unless they ask.

To show what a result looks like without AWS credentials, run
`uvx cloudcostwise==0.1.26 scan --demo --format json`. It prints a recorded scan of a CloudWise test
account and makes no AWS call. Say clearly that it is sample data and not the user's account.

## Read the result

The JSON has these fields:

- `estimated_monthly_savings`: the total, in US dollars a month. `advisory_monthly_savings_excluded` is the
  part from advisory findings, which is left out of the total.
- `findings`: one entry per resource, with `waste_type`, `region`, `resource_id`, `title`,
  `monthly_savings`, `confidence`, `action` and `validation`. A `validation` of `advisory` marks a kind of
  finding that is listed but not counted in the total. Say which findings are advisory.
- `checks_run`: how many checks ran. `cost_explorer_skipped`: whether the Cost Explorer checks were skipped.
- `warnings`, `errors`, `permission_errors` and `coverage_notes`: what the scan could not read or check.
- `excluded_by_list_count`: findings left out because the user put those resources on their exclude list.

Then tell the user:

1. The total estimated monthly savings, the regions scanned and how many checks ran.
2. The findings, largest `monthly_savings` first, grouped by waste type when there are many. Give the
   region, the resource and the `action` for each.
3. Anything in `permission_errors`, `errors`, `warnings` or `coverage_notes`, so the user knows what was
   not checked. A missing permission is a gap in the result, not a clean result.

The savings are estimates. They are not figures from the user's bill. Say so when you give a total.

## Rules

- Never change anything in AWS as part of this skill. Do not run a command that modifies, stops or deletes
  a resource. If the user asks how to fix a finding, write the steps or the AWS CLI command for them to
  review and run themselves, and say what cannot be undone.
- Never run `cloudcostwise share`, and never set `CLOUDCOSTWISE_SHARE`. Sharing a summary with CloudWise
  is the user's own choice, made in their own terminal. A scan you run sends nothing to CloudWise unless
  the user has already turned sharing on themselves.
- Do not send the scan result anywhere, and do not write it to a file unless the user asks.
- Report what the scan found and what it could not check. Do not add product or plan suggestions.
- If the user wants a resource left out of future scans, the command is
  `uvx cloudcostwise==0.1.26 exclude add RESOURCE_ID_OR_ARN`. The list stays on their machine.

## When the scan fails

- No AWS credentials: say so, and that the scan needs a profile in `~/.aws`, SSO or environment variables
  with read-only access. The minimal IAM policy is at
  https://github.com/cloudwise-app/cloudcostwise/blob/main/docs/iam-policy.json.
- An access-denied message for one service: the other checks still ran. Report the gap.
- Anything else: show the user the error text. Bugs can be reported at
  https://github.com/cloudwise-app/cloudcostwise/issues.
