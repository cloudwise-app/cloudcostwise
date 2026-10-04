"""Local runtime for the open scan engine: adapters, credentials, regions, guard.

Everything a scan needs that the hosted product gets from Lambda, DynamoDB or
Parameter Store is replaced here by something local, so a scan makes AWS API
calls on the user's own credentials and nothing else.
"""

from __future__ import annotations

import os
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from typing import FrozenSet, Iterator, List, Optional

import boto3
import botocore.client
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

GLOBAL_REGION = "us-east-1"

# Every AWS operation a local scan may call starts with one of these. Anything
# else (Put/Create/Delete/Update/Modify/Start/Stop/Tag/...) is refused before
# it leaves the machine, whatever the credentials would allow.
READ_ONLY_PREFIXES = ("Describe", "List", "Get", "Search", "Lookup")

# Cost Explorer bills $0.01 per request; the user should know before and after.
COST_EXPLORER_SERVICE = "ce"
COST_EXPLORER_PRICE_PER_REQUEST = 0.01


class ReadOnlyViolation(RuntimeError):
    """A scan tried an AWS operation that is not a read."""


class CredentialsError(RuntimeError):
    """No usable AWS credentials for the requested profile."""


@dataclass(frozen=True)
class Credentials:
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str]
    account_id: str
    default_region: Optional[str]


def configure_local_runtime() -> None:
    """Wire scan-core's ports for a local, single-user, no-persistence run."""
    from cloudwise_scan_core import configure_providers
    from cloudwise_scan_core.metrics import NullMetricsEmitter
    from cloudwise_scan_core.savings_cache_service import use_in_memory_savings_cache

    # Null metrics explicitly: the EMF emitter writes to stdout, which carries
    # the protocol under `cloudcostwise mcp` and the JSON under --format json.
    null_metrics = NullMetricsEmitter()
    configure_providers(env_detector_provider=lambda: _LocalEnvironment(),
                        metrics_emitter_provider=lambda: null_metrics)
    use_in_memory_savings_cache()
    # No API Gateway 29 s budget here: give slow detectors room instead of
    # reporting their findings as MISSING. A value the user set wins.
    os.environ.setdefault("DETECTOR_TIMEOUT_DEFAULT_SECONDS", "120")
    os.environ.setdefault("DETECTOR_TIMEOUT_HEAVY_SECONDS", "300")


class _LocalEnvironment:
    environment_name = "local"


def resolve_credentials(profile: Optional[str]) -> Credentials:
    """Standard boto3 chain (env vars, profile, SSO, instance role), frozen."""
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        creds = session.get_credentials()
        if creds is None:
            raise CredentialsError(
                "No AWS credentials found. Set AWS_PROFILE, pass --profile, or run `aws sso login`."
            )
        frozen = creds.get_frozen_credentials()
        account = session.client("sts").get_caller_identity()["Account"]
    except (NoCredentialsError, BotoCoreError, ClientError) as e:
        raise CredentialsError(f"Could not use AWS credentials: {e}") from e
    return Credentials(
        access_key_id=frozen.access_key,
        secret_access_key=frozen.secret_key,
        session_token=frozen.token,
        account_id=account,
        default_region=session.region_name,
    )


def resolve_regions(spec: Optional[str], creds: Credentials) -> List[str]:
    """Regions to scan, us-east-1 first (account-level checks only run there).

    ``None`` scans us-east-1 plus the profile's region; ``all`` scans every
    region enabled for the account; otherwise a comma-separated list.
    """
    if spec is None:
        regions = [GLOBAL_REGION, creds.default_region or GLOBAL_REGION]
    elif spec.strip().lower() == "all":
        ec2 = boto3.client(
            "ec2",
            region_name=GLOBAL_REGION,
            aws_access_key_id=creds.access_key_id,
            aws_secret_access_key=creds.secret_access_key,
            aws_session_token=creds.session_token,
        )
        enabled = sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
        regions = [GLOBAL_REGION] + enabled
    else:
        regions = [r.strip() for r in spec.split(",") if r.strip()]
    seen: List[str] = []
    for region in regions:
        if region not in seen:
            seen.append(region)
    return seen


@dataclass
class GuardLog:
    calls: Counter
    violations: List[str]
    blocked: Counter


@contextmanager
def read_only_guard(blocked_services: FrozenSet[str] = frozenset()) -> Iterator[GuardLog]:
    """Refuse any non-read AWS operation for the duration; count calls per service.

    Detectors catch their own exceptions, so a refused call is also recorded in
    ``violations``: the caller must check it, or a refusal reads as a warning.

    ``blocked_services`` (e.g. ``{"ce"}`` for --no-cost-explorer) are answered
    locally with AccessDenied, never sent: the engine already reports a denied
    read as MISSING data and falls back, exactly as for a role without that
    permission. Those are counted in ``blocked``, not as violations.
    """
    log = GuardLog(calls=Counter(), violations=[], blocked=Counter())
    original = botocore.client.BaseClient._make_api_call

    def guarded(client, operation_name, api_params):
        service = client.meta.service_model.service_name
        if service in blocked_services:
            log.blocked[service] += 1
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException",
                           "Message": f"{service} skipped locally by cloudcostwise (--no-cost-explorer)"}},
                operation_name,
            )
        if not operation_name.startswith(READ_ONLY_PREFIXES):
            log.violations.append(f"{service}:{operation_name}")
            raise ReadOnlyViolation(f"refused non-read AWS call {service}:{operation_name}")
        log.calls[service] += 1
        return original(client, operation_name, api_params)

    botocore.client.BaseClient._make_api_call = guarded
    try:
        yield log
    finally:
        botocore.client.BaseClient._make_api_call = original
