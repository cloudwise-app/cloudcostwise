"""CLO-1116: ``scan --emulator``. A live scan of a fake AWS account running in AWS Emulator on this machine.

AWS Emulator (https://github.com/aws/aws-emulator) is AWS's free local emulator of the AWS APIs. This module
starts it in Docker (published on 127.0.0.1 only, telemetry off), seeds a small wasteful account into it and runs
the normal scan engine against it. Nothing here ever uses the person's AWS credentials:

* this process builds its own boto3 Session from the emulator's credentials file, config file and CA bundle, and
  passes the emulator endpoint to every client;
* the scan runs in a child process whose environment is a copy with every AWS variable removed and the emulator's
  own set, so the environment of this process (an MCP server's, say) is never changed;
* before anything is created or scanned, three guards must pass, in this process and again in the child: the
  effective endpoint is 127.0.0.1, the credentials come from the shared credentials file in the emulator's
  directory, and STS answers with the emulator's account 000000000000.

The report is flagged ``emulator=True``: every output says what it is, and it is never shared.
"""

from __future__ import annotations

import json
import os
import pickle
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import boto3
import botocore.session
from botocore.config import Config

from cloudcostwise.scan import ScanReport

DEFAULT_PORT = 9397
PORT_ENV = "CW_DEMO_EMULATOR_PORT"
IMAGE = "cw-aws-emulator"
EMULATOR_ACCOUNT = "000000000000"
REGION = "us-east-1"
RPM_URL = "https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/latest/aws-emulator-{arch}.rpm"
TAG = [{"Key": "cloudwise-demo", "Value": "aws-emulator"}]
# Encrypted root volumes, so the only findings are the seeded waste (an unencrypted volume is its own finding).
ENCRYPTED_ROOT = [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "Encrypted": True}}]

# What it is and is not. First and last line of the table and markdown, a note in the JSON and in every MCP result.
NOTE = ("Live scan of a fake AWS account running in AWS Emulator on your machine. The resources are fake, savings "
        "use AWS list prices, and checks that need billing or usage history can't fire here.")
CARD_MARK = "FAKE ACCOUNT (AWS Emulator on your machine, not your AWS account)"
# Text for the assistant behind the MCP server.
MCP_NOTE = (NOTE + " This is not the user's AWS account: tell the user so, and say so whenever you quote or "
            "summarize it. The emulator container keeps running; stop it with `cloudcostwise scan --emulator-down`.")
IGNORED_IN_MCP = ("profile, regions and include_cost_explorer are ignored with emulator=true: the scan always "
                  "uses the fake account's us-east-1, with Cost Explorer off, and never your AWS credentials.")
DOCKER_NEEDED = ("cloudcostwise: --emulator needs Docker installed and running ({why}). Nothing was started and no "
                 "AWS call was made. Try `cloudcostwise scan --demo` for a recorded sample instead.")
MCP_DOCKER_NEEDED = ("Could not run the emulator scan: it needs Docker installed and running ({why}). Nothing was "
                     "started and no AWS call was made. Try scan with demo=true for a recorded sample instead.")


class EmulatorError(RuntimeError):
    """The emulator could not be started, was not safe to use, or the scan failed."""


class DockerMissing(EmulatorError):
    """Docker is not installed or not running."""


class DockerTimeout(EmulatorError):
    """A docker command did not finish in time."""


class Unsafe(EmulatorError):
    """A guard refused: what we would talk to is not the local emulator."""


def default_port() -> int:
    raw = os.environ.get(PORT_ENV)
    try:
        return int(raw) if raw else DEFAULT_PORT
    except ValueError:
        return DEFAULT_PORT


def emulator_dir(port: int) -> Path:
    return Path.home() / ".aws" / "emulator" / str(port)


def container_name(port: int) -> str:
    return f"cw-aws-emulator-{port}"


def endpoint(port: int) -> str:
    return f"https://127.0.0.1:{port}"


# --------------------------------------------------------------------------- Docker

def _docker(args: List[str], timeout: float = 120, **kw) -> subprocess.CompletedProcess:
    """Run docker with all output captured: nothing it prints can reach stdout (MCP, --format json)."""
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        raise DockerTimeout(f"docker {args[0]} did not finish in {int(timeout)} s; check that Docker is responding "
                            "and try again") from None
    except OSError as e:
        raise DockerMissing(f"docker could not be run: {e}") from None


def require_docker() -> None:
    if shutil.which("docker") is None:
        raise DockerMissing("docker not found on PATH")
    try:
        r = _docker(["info", "--format", "{{.ServerVersion}}"], timeout=20)
    except DockerTimeout:
        raise DockerMissing("the docker daemon did not answer")
    if r.returncode != 0:
        raise DockerMissing("the docker daemon is not running")


def dockerfile() -> str:
    arch = "aarch64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    return (
        "FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal\n"
        f"ADD {RPM_URL.format(arch=arch)} /tmp/aws-emulator.rpm\n"
        "RUN rpm -i /tmp/aws-emulator.rpm && rm /tmp/aws-emulator.rpm \\\n"
        "    && mkdir -p /home/emulator && chown 1000 /home/emulator\n"
        "USER 1000\n"
        "ENV HOME=/home/emulator EMULATOR_BIND_ADDRESS=0.0.0.0 EMULATOR_TELEMETRY=off\n"
        'ENTRYPOINT ["aws-emulator"]\n')


def ensure_image(say: Callable[[str], None]) -> None:
    """Reuse an image tagged cw-aws-emulator; otherwise build it from AWS's own RPM (about 1.4 GB, once)."""
    if _docker(["image", "inspect", IMAGE]).returncode == 0:
        return
    say("Building the AWS Emulator image from AWS's own package (about 1.4 GB, first run only) ...")
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "Dockerfile").write_text(dockerfile())
        r = _docker(["build", "-q", "-t", IMAGE, tmp], timeout=1800)
    if r.returncode != 0:
        raise EmulatorError("could not build the AWS Emulator image: " + (r.stderr.strip().splitlines() or ["docker build failed"])[-1])


def _healthy(port: int) -> bool:
    """Ready when the emulator answers an STS call through the guarded, 127.0.0.1-only session.

    Deliberately boto3 and not urllib: the CLI's only network code outside share.py is the AWS SDK, which
    the Privacy Policy and Terms pin (legal-facts-pins.test.tsx, NETWORK_IMPORT)."""
    d = emulator_dir(port)
    if not ((d / "ca.pem").exists() and (d / "emulator_credentials").exists()):
        return False
    try:
        client(make_session(port), "sts", port).get_caller_identity()
        return True
    except Exception:
        return False


def _running(port: int) -> bool:
    r = _docker(["ps", "--format", "{{.Names}}"])
    return r.returncode == 0 and container_name(port) in r.stdout.split()


def start(port: int, say: Callable[[str], None]) -> bool:
    """Start the emulator on 127.0.0.1:port, or reuse a running one. Returns True when it was reused."""
    require_docker()
    ensure_image(say)
    name = container_name(port)
    reused = _running(port)
    if not reused:
        home = str(Path.home())
        d = str(Path.home() / ".aws" / "emulator")
        # The emulator keeps its credentials and CA here: private to the user (existing directories are left as they are).
        os.makedirs(os.path.dirname(d), mode=0o700, exist_ok=True)
        os.makedirs(d, mode=0o700, exist_ok=True)
        _docker(["rm", "-f", name])
        r = _docker(["run", "-d", "--name", name, "--memory=2g", "--memory-swap=2g",
                     "-p", f"127.0.0.1:{port}:{port}", "-e", f"HOME={home}", "-e", "EMULATOR_TELEMETRY=off",
                     "-v", f"{d}:{d}", IMAGE, "-p", str(port)])
        if r.returncode != 0:
            raise EmulatorError("could not start the emulator: " + (r.stderr.strip().splitlines() or ["docker run failed"])[-1]
                                + f" (is port {port} in use? try --emulator-port)")
    for _ in range(60):
        if _healthy(port):
            return reused
        time.sleep(1)
    tail = _docker(["logs", "--tail", "5", name]).stderr.strip()
    raise EmulatorError(f"the emulator on port {port} did not become healthy. {tail}".strip())


def stop(port: int) -> None:
    require_docker()
    _docker(["rm", "-f", container_name(port)])


# --------------------------------------------------------------------------- the safe session and guards

def _only_local(request, **kwargs) -> None:
    host = urlparse(request.url).hostname
    if host != "127.0.0.1":
        raise Unsafe(f"refused a request to {host!r}: this session only talks to the local emulator at 127.0.0.1")


def make_session(port: int) -> boto3.Session:
    """A boto3 Session that reads only the emulator's own files. It ignores AWS_PROFILE and every AWS key
    variable: an explicit profile in a botocore session drops the environment credential provider."""
    d = emulator_dir(port)
    bs = botocore.session.Session()
    # Defense in depth: whatever a client was built with, no request from this session leaves 127.0.0.1.
    bs.register("before-send.*.*", _only_local)
    bs.set_config_variable("profile", "default")
    bs.set_config_variable("credentials_file", str(d / "emulator_credentials"))
    bs.set_config_variable("config_file", str(d / "config"))
    bs.set_config_variable("ca_bundle", str(d / "ca.pem"))
    return boto3.Session(botocore_session=bs, region_name=REGION)


def client(session: boto3.Session, service: str, port: int):
    d = emulator_dir(port)
    return session.client(service, region_name=REGION, endpoint_url=endpoint(port), verify=str(d / "ca.pem"),
                          config=Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=60))


def verify(session: boto3.Session, port: int, expect_endpoint: bool = True) -> None:
    """The three guards. Raises Unsafe, naming what failed, before anything is created or scanned.

    ``expect_endpoint=False`` checks the endpoint the environment gives (the child's engine builds its
    clients from it) instead of passing one."""
    try:
        sts = client(session, "sts", port) if expect_endpoint else session.client("sts", region_name=REGION)
        host = urlparse(sts.meta.endpoint_url).hostname
        if host != "127.0.0.1":
            raise Unsafe(f"the STS endpoint is {host!r}, not the local emulator at 127.0.0.1")
        creds = session.get_credentials()
        if creds is None or getattr(creds, "method", None) != "shared-credentials-file":
            raise Unsafe("the credentials do not come from a shared credentials file")
        expected = str(emulator_dir(port) / "emulator_credentials")
        used = session._session.get_config_variable("credentials_file")
        if os.path.realpath(os.path.expanduser(str(used))) != os.path.realpath(expected):
            raise Unsafe("the credentials file is not the emulator's own")
        account = sts.get_caller_identity()["Account"]
    except Unsafe:
        raise
    except Exception as e:
        raise Unsafe(f"could not confirm that this is the local emulator ({type(e).__name__}: {e})") from e
    if account != EMULATOR_ACCOUNT:
        raise Unsafe(f"the account is {account}, not the emulator's {EMULATOR_ACCOUNT}")


# --------------------------------------------------------------------------- seeding

def _tags(kind: str, name: str) -> list:
    return [{"ResourceType": kind, "Tags": TAG + [{"Key": "Name", "Value": name}]}]


def already_seeded(session: boto3.Session, port: int) -> bool:
    ec2 = client(session, "ec2", port)
    found = ec2.describe_instances(Filters=[{"Name": "tag:cloudwise-demo", "Values": ["aws-emulator"]}])
    return any(r["Instances"] for r in found["Reservations"])


def seed(session: boto3.Session, port: int) -> Dict[str, dict]:
    """Create the fake wasteful account, each wasteful resource beside a healthy twin. Guards must have passed.

    Four of the seeded resources are expected to fire; the log group and the unfinished multipart upload are
    created too but cannot fire on a fake account (they need retention history and resource age)."""
    ec2 = client(session, "ec2", port)
    out: dict = {"waste": {}, "not_waste": {}, "skipped": {}}
    wait = {"Delay": 1, "MaxAttempts": 30}
    image = sorted(ec2.describe_images(Owners=["amazon"])["Images"], key=lambda i: i.get("CreationDate", ""),
                   reverse=True)[0]["ImageId"]
    subnets = ec2.describe_subnets()["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets]
    vpc_id = subnets[0]["VpcId"]

    running = ec2.run_instances(
        ImageId=image, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet_ids[0],
        BlockDeviceMappings=ENCRYPTED_ROOT, TagSpecifications=_tags("instance", "demo-web-server"),
    )["Instances"][0]["InstanceId"]
    ec2.get_waiter("instance_running").wait(InstanceIds=[running], WaiterConfig=wait)
    attached = ec2.create_volume(AvailabilityZone=subnets[0]["AvailabilityZone"], Size=20, VolumeType="gp3",
                                 Encrypted=True, TagSpecifications=_tags("volume", "demo-web-data"))["VolumeId"]
    ec2.get_waiter("volume_available").wait(VolumeIds=[attached], WaiterConfig=wait)
    ec2.attach_volume(VolumeId=attached, InstanceId=running, Device="/dev/sdf")
    used_eip = ec2.allocate_address(Domain="vpc", TagSpecifications=_tags("elastic-ip", "demo-web-ip"))["AllocationId"]
    ec2.associate_address(AllocationId=used_eip, InstanceId=running)
    out["not_waste"].update(running_instance=running, attached_volume=attached, associated_eip=used_eip)

    loose = ec2.create_volume(AvailabilityZone=subnets[0]["AvailabilityZone"], Size=100, VolumeType="gp2",
                              Encrypted=True, TagSpecifications=_tags("volume", "demo-old-migration-disk"))["VolumeId"]
    idle_eip = ec2.allocate_address(Domain="vpc", TagSpecifications=_tags("elastic-ip", "demo-forgotten-ip"))["AllocationId"]
    stopped = ec2.run_instances(
        ImageId=image, InstanceType="m5.large", MinCount=1, MaxCount=1, SubnetId=subnet_ids[0],
        BlockDeviceMappings=ENCRYPTED_ROOT, TagSpecifications=_tags("instance", "demo-old-batch-box"),
    )["Instances"][0]["InstanceId"]
    ec2.get_waiter("instance_running").wait(InstanceIds=[stopped], WaiterConfig=wait)
    ec2.stop_instances(InstanceIds=[stopped])
    out["waste"].update(unattached_volume=loose, unassociated_eip=idle_eip, stopped_instance=stopped)

    try:
        elb = client(session, "elbv2", port)
        two_azs: list = []
        for s in subnets:
            if s["AvailabilityZone"] not in [x["AvailabilityZone"] for x in two_azs]:
                two_azs.append(s)
        lb = elb.create_load_balancer(Name="demo-empty-alb", Subnets=[s["SubnetId"] for s in two_azs[:2]],
                                      Type="application", Tags=TAG)["LoadBalancers"][0]["LoadBalancerArn"]
        tg = elb.create_target_group(Name="demo-empty-tg", Protocol="HTTP", Port=80, VpcId=vpc_id)
        elb.create_listener(LoadBalancerArn=lb, Protocol="HTTP", Port=80,
                            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroups"][0]["TargetGroupArn"]}])
        out["waste"]["empty_load_balancer"] = lb
    except Exception as exc:  # an emulator gap must not stop the demo
        out["skipped"]["empty_load_balancer"] = str(exc)[:200]

    try:
        logs = client(session, "logs", port)
        logs.create_log_group(logGroupName="/demo/app/no-retention")
        logs.create_log_group(logGroupName="/demo/app/30-day-retention")
        logs.put_retention_policy(logGroupName="/demo/app/30-day-retention", retentionInDays=30)
        out["waste"]["log_group_no_retention"] = "/demo/app/no-retention"
        out["not_waste"]["log_group_with_retention"] = "/demo/app/30-day-retention"
    except Exception as exc:
        out["skipped"]["log_groups"] = str(exc)[:200]

    try:
        s3 = client(session, "s3", port)
        s3.create_bucket(Bucket="demo-uploads-with-leftovers")
        s3.create_multipart_upload(Bucket="demo-uploads-with-leftovers", Key="backups/huge-file.tar")
        s3.create_bucket(Bucket="demo-clean-bucket")
        s3.put_object(Bucket="demo-clean-bucket", Key="readme.txt", Body=b"hello")
        out["waste"]["incomplete_multipart_upload_bucket"] = "demo-uploads-with-leftovers"
        out["not_waste"]["clean_bucket"] = "demo-clean-bucket"
    except Exception as exc:
        out["skipped"]["s3"] = str(exc)[:200]
    return out


# --------------------------------------------------------------------------- the scan, in a child process

def scan_env(port: int, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """A COPY of the environment for the scan child: every AWS variable removed, the emulator's own set.
    The environment of this process is never touched."""
    env = {k: v for k, v in (os.environ if base is None else base).items() if not k.startswith("AWS_")}
    d = emulator_dir(port)
    env.update({
        "AWS_ENDPOINT_URL": endpoint(port),
        "AWS_SHARED_CREDENTIALS_FILE": str(d / "emulator_credentials"),
        "AWS_CONFIG_FILE": str(d / "config"),
        "AWS_CA_BUNDLE": str(d / "ca.pem"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_DISABLE_HOST_PREFIX_INJECTION": "true",
        "AWS_REGION": REGION,
        "AWS_DEFAULT_REGION": REGION,
        "CW_AWS_EMULATOR_PORT": str(port),
        "EMULATOR_TELEMETRY": "off",
    })
    return env


def _worker(port: int, out_path: str) -> int:
    """Runs in the child: guards again on what the engine will really use, then the normal scan."""
    from cloudcostwise.runtime import configure_local_runtime, resolve_credentials, resolve_regions
    from cloudcostwise.scan import run_scan

    verify(make_session(port), port)
    verify(boto3.Session(), port, expect_endpoint=False)  # what the engine builds its clients from
    configure_local_runtime()
    creds = resolve_credentials(None)
    report = run_scan(creds, resolve_regions(REGION, creds), include_cost_explorer=False, parallel=1, with_spend=False)
    report.emulator = True
    with open(out_path, "wb") as f:
        pickle.dump(report, f)  # our own child's output, read back by the process that started it
    return 0


def run_scan_child(port: int) -> ScanReport:
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "report.pickle")
        # -P and an empty cwd: nothing in the caller's directory (a boto3.py in a project, say) can be imported.
        r = subprocess.run([sys.executable, "-P", "-m", "cloudcostwise.emulator_demo", "--worker", str(port), out],
                           env=scan_env(port), capture_output=True, text=True, timeout=900, cwd=tmp)
        if r.returncode != 0 or not os.path.exists(out):
            tail = (r.stderr.strip().splitlines() or ["no output"])[-1]
            raise EmulatorError(f"the scan of the emulator failed: {tail}")
        with open(out, "rb") as f:
            return pickle.load(f)


def prepare(port: int, say: Callable[[str], None] = lambda s: None) -> None:
    """Docker, emulator, guards, seed. Raises DockerMissing, Unsafe or EmulatorError."""
    require_docker()  # before a word is printed: no Docker means one line and nothing else
    say(f"1/3  Starting AWS Emulator on 127.0.0.1:{port} (Docker, telemetry off) ...")
    reused = start(port, say)
    session = make_session(port)
    verify(session, port)
    if reused and already_seeded(session, port):
        say("2/3  The fake account is already there; reusing it ...")
    else:
        say("2/3  Creating a fake account with wasteful resources next to healthy twins ...")
        seed(session, port)


def run(port: int, say: Callable[[str], None] = lambda s: None) -> ScanReport:
    """The whole thing: start or reuse, guard, seed, scan. Returns the report, flagged ``emulator=True``."""
    prepare(port, say)
    say(f"3/3  Running the scan against the emulator (us-east-1, Cost Explorer off) ...")
    return run_scan_child(port)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        sys.exit(_worker(int(sys.argv[2]), sys.argv[3]))
    sys.exit("internal module: run `cloudcostwise scan --emulator`")
