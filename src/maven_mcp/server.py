"""MCP server definition and tool registration for maven_mcp."""

from __future__ import annotations

import logging
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import Config
from .nexus_client import NexusClient, NexusClientError
from .version_utils import filter_non_breaking_versions
from .vuln_checker import check_vulnerabilities

logger = logging.getLogger(__name__)

_mcp_port = 8000
try:
    _mcp_port = int(os.environ.get("MCP_PORT", "8000"))
except ValueError:
    pass
_mcp_host = os.environ.get("MCP_HOST", "0.0.0.0")
mcp = FastMCP("maven_mcp", json_response=True, host=_mcp_host, port=_mcp_port)


def _get_config() -> Config:
    """Load configuration from environment (used by tools)."""
    return Config.from_env()


@mcp.tool()
async def check_maven_versions(
    group_id: str,
    artifact_id: str,
    current_version: str,
) -> list[dict[str, Any]]:
    """
    Fetch all non-breaking newer versions of a Maven artifact from Nexus and check each for known vulnerabilities.

    Returns only versions with the same major version as current_version (e.g. for 1.8.5 only 1.x.x), sorted ascending.
    Each version includes its vulnerability details from OSV.dev (or Sonatype IQ when configured).
    """
    group_id = (group_id or "").strip()
    artifact_id = (artifact_id or "").strip()
    current_version = (current_version or "").strip()
    if not group_id or not artifact_id or not current_version:
        return [
            {
                "error": "group_id, artifact_id, and current_version are required",
                "version": "",
                "vulnerabilities": [],
                "vulnerability_count": 0,
            }
        ]

    try:
        config = _get_config()
    except ValueError as e:
        return [
            {
                "error": str(e),
                "version": "",
                "vulnerabilities": [],
                "vulnerability_count": 0,
            }
        ]

    try:
        nexus = NexusClient(config.nexus)
        all_versions = await nexus.get_versions(group_id, artifact_id)
    except NexusClientError as e:
        return [
            {
                "error": str(e),
                "version": "",
                "vulnerabilities": [],
                "vulnerability_count": 0,
            }
        ]

    candidates = filter_non_breaking_versions(current_version, all_versions, exclude_snapshots=True)
    if not candidates:
        return []

    try:
        vuln_by_version = await check_vulnerabilities(config, group_id, artifact_id, candidates)
    except Exception as e:
        logger.exception("Vulnerability check failed")
        return [
            {
                "error": f"Vulnerability check failed: {e!s}",
                "version": "",
                "vulnerabilities": [],
                "vulnerability_count": 0,
            }
        ]

    result: list[dict[str, Any]] = []
    for version in candidates:
        vulns = vuln_by_version.get(version, [])
        result.append(
            {
                "version": version,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "summary": v.summary,
                        "severity": v.severity,
                        "references": v.references,
                    }
                    for v in vulns
                ],
                "vulnerability_count": len(vulns),
            }
        )
    return result


def main() -> None:
    """Entry point: load config and run MCP server with configured transport."""
    config = Config.from_env()
    if config.mcp_transport == "streamable-http":
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
