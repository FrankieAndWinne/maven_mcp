"""Version parsing, comparison, and breaking-change filtering for Maven versions."""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

# Maven qualifier suffix (e.g. -RELEASE, -SNAPSHOT, -RC1). We exclude SNAPSHOT by default.
SNAPSHOT_SUFFIX = "-SNAPSHOT"
SNAPSHOT_SUFFIX_CI = re.compile(r"[-.]SNAPSHOT$", re.IGNORECASE)


def is_snapshot(version: str) -> bool:
    """Return True if the version string looks like a snapshot (e.g. 1.0-SNAPSHOT, 1.0.0-SNAPSHOT)."""
    v = version.strip()
    if not v:
        return False
    return bool(SNAPSHOT_SUFFIX_CI.search(v)) or v.upper().endswith("SNAPSHOT")


def _parse_major(version: str) -> int | None:
    """
    Extract major version number for breaking-change filtering.
    Handles formats like 1, 1.8, 1.8.5, 1.8.5-RELEASE, 2.0.0-RC1.
    Returns None if unparseable.
    """
    v = version.strip()
    # Strip common qualifiers for parsing
    for suffix in ("-RELEASE", "-RC1", "-RC2", "-M1", "-M2", "-SNAPSHOT", "-alpha", "-beta"):
        if v.upper().endswith(suffix.upper()):
            v = v[: -len(suffix)].strip().rstrip("-.")
            break
    # Match leading digits
    match = re.match(r"^(\d+)", v)
    if match:
        return int(match.group(1))
    return None


def _version_key(version: str) -> tuple:
    """
    Build a sort key from a version string for ordering.
    Returns (0, Version) for parseable versions, (1, raw_string) for others.
    """
    v = version.strip()
    try:
        ver = Version(v)
        return (0, ver)
    except InvalidVersion:
        return (1, v)


def filter_non_breaking_versions(
    current_version: str,
    available_versions: list[str],
    exclude_snapshots: bool = True,
) -> list[str]:
    """
    From a list of available versions, return only those that are:
    - Same major version as current_version (no breaking change),
    - Greater than current_version,
    - Optionally exclude SNAPSHOT versions.

    Result is sorted ascending by version.
    """
    current = current_version.strip()
    current_major = _parse_major(current)
    if current_major is None:
        # Cannot determine major; return all newer-looking versions (conservative)
        current_major = -1

    candidates: list[str] = []
    for v in available_versions:
        v = v.strip()
        if not v:
            continue
        if exclude_snapshots and is_snapshot(v):
            continue
        major = _parse_major(v)
        if major is None:
            continue
        if major != current_major:
            continue
        if _version_key(v) <= _version_key(current):
            continue
        candidates.append(v)

    return sorted(candidates, key=_version_key)
