"""Which files make up the open core (CLO-562).

``OPEN_CORE_FILES`` is the static import closure of ``open_service.py`` (every
``cloudwise_scan_core`` import, including ones nested in functions), as paths
relative to the package. The export script (CLO-565) copies exactly these
files. ``tests/test_open_core_boundary.py`` recomputes the closure and fails
if this list drifts, so a new import from open code must be added here on
purpose.

The one edge that is deliberately cut: ``waste_detection_service`` resolves
``WasteDetectionService`` lazily from ``hosted_service`` (closed). In the
open core that name is not available; use ``OpenWasteDetectionService``.
"""

import ast
from pathlib import Path
from typing import Iterable, Set

PACKAGE = "cloudwise_scan_core"
ROOT_MODULE = "open_service"
LAZY_CLOSED_EDGES = frozenset({"hosted_service"})

OPEN_CORE_FILES = (
    "__init__.py",
    "advisory_types.py",
    "aws_ip_ranges.py",
    "aws_ip_ranges_snapshot.py",
    "aws_pricing_service.py",
    "billed_cost.py",
    "cache.py",
    "circuit_breaker.py",
    "cloudwatch_metrics_service.py",
    "config.py",
    "cpu_sizing.py",
    "credential_cache.py",
    "data_providers/__init__.py",
    "data_providers/base.py",
    "data_providers/missing_data.py",
    "data_providers/models.py",
    "data_providers/offline.py",
    "data_providers/online.py",
    "detectors/__init__.py",
    "detectors/extended_support.py",
    "detectors/open/__init__.py",
    "detectors/open/commitment_cache.py",
    "detectors/open/compute.py",
    "detectors/open/database.py",
    "detectors/open/management.py",
    "detectors/open/network.py",
    "detectors/open/optimizer.py",
    "detectors/open/savings.py",
    "detectors/open/security.py",
    "detectors/open/storage.py",
    "metric_window.py",
    "metrics.py",
    "models.py",
    "open_core_manifest.py",
    "open_service.py",
    "ports.py",
    "py.typed",
    "savings_cache_service.py",
    "tier_routing.py",
    "waste_detection_service.py",
)


def _module_file(pkg_dir: Path, dotted: str) -> Path:
    rel = Path(*dotted.split("."))
    as_pkg = pkg_dir / rel / "__init__.py"
    return as_pkg if as_pkg.exists() else pkg_dir / rel.with_suffix(".py")


def _imports(path: Path, pkg_dir: Path) -> Iterable[str]:
    here = path.relative_to(pkg_dir).with_suffix("").parts
    if here[-1] == "__init__":
        here = here[:-1]
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(PACKAGE + "."):
                    yield alias.name[len(PACKAGE) + 1:]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = list(here if path.name == "__init__.py" else here[:-1])
                base = base[: len(base) - (node.level - 1)] if node.level > 1 else base
                mod = ".".join(base + ([node.module] if node.module else []))
            elif node.module == PACKAGE:
                mod = ""
            elif node.module and node.module.startswith(PACKAGE + "."):
                mod = node.module[len(PACKAGE) + 1:]
            else:
                continue
            if mod:
                yield mod
            for alias in node.names:  # ``from pkg import submodule``
                candidate = f"{mod}.{alias.name}" if mod else alias.name
                if _module_file(pkg_dir, candidate).exists():
                    yield candidate


def compute_closure(pkg_dir: Path) -> Set[str]:
    """Package-relative files reachable from ``open_service`` by import."""
    seen: Set[str] = set()
    stack = [ROOT_MODULE]
    while stack:
        dotted = stack.pop()
        if dotted in LAZY_CLOSED_EDGES:
            continue
        parts = dotted.split(".")
        for i in range(1, len(parts)):  # parent packages' __init__.py run first
            stack.append(".".join(parts[:i]))
        path = _module_file(pkg_dir, dotted)
        rel = path.relative_to(pkg_dir).as_posix()
        if rel in seen or not path.exists():
            continue
        seen.add(rel)
        stack.extend(_imports(path, pkg_dir))
    stack = list(_imports(pkg_dir / "__init__.py", pkg_dir))  # the package root runs too
    seen.add("__init__.py")
    while stack:
        dotted = stack.pop()
        if dotted in LAZY_CLOSED_EDGES:
            continue
        path = _module_file(pkg_dir, dotted)
        rel = path.relative_to(pkg_dir).as_posix()
        if rel in seen or not path.exists():
            continue
        seen.add(rel)
        stack.extend(_imports(path, pkg_dir))
    return seen | {"py.typed", "open_core_manifest.py"}
