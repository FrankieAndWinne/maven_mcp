"""Vulnerability checking via OSV.dev (primary) and Sonatype IQ (fallback)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from .config import Config, SonatypeIQConfig

logger = logging.getLogger(__name__)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL_TEMPLATE = "https://api.osv.dev/v1/vulns/{id}"


@dataclass
class VulnerabilityDetail:
    """Single vulnerability record for tool output."""

    id: str
    summary: str
    severity: str
    references: list[str]


def _purl_maven(group_id: str, artifact_id: str, version: str) -> str:
    """Build a Maven package URL (purl) for OSV."""
    # PURL format: pkg:maven/groupId/artifactId@version (slash and @ need encoding in path)
    # OSV expects format pkg:maven/org.group/artifact-id@1.0.0
    namespace = quote(group_id, safe="")
    name = quote(artifact_id, safe="")
    ver = quote(version, safe="")
    return f"pkg:maven/{namespace}/{name}@{ver}"


def _normalize_severity(osv_vuln: dict) -> str:
    """Extract a single severity string from an OSV vulnerability object."""
    # Top-level severity array: [{"type": "CVSS_V3", "score": "7.5"}]
    sev = osv_vuln.get("severity") or []
    if isinstance(sev, list) and sev:
        first = sev[0]
        if isinstance(first, dict):
            score = first.get("score", "")
            stype = first.get("type", "")
            if score:
                return f"{stype} {score}".strip() if stype else score
    # Affected[].ecosystem_specific.severity
    for aff in osv_vuln.get("affected") or []:
        if isinstance(aff, dict):
            es = aff.get("ecosystem_specific") or {}
            if isinstance(es, dict) and es.get("severity"):
                return str(es["severity"])
    return "UNKNOWN"


def _detail_from_osv(osv_vuln: dict) -> VulnerabilityDetail:
    """Build VulnerabilityDetail from OSV GET /v1/vulns/{id} response."""
    vuln_id = osv_vuln.get("id", "UNKNOWN")
    summary = osv_vuln.get("summary") or osv_vuln.get("details", "")[:500] or ""
    severity = _normalize_severity(osv_vuln)
    refs = []
    for r in osv_vuln.get("references") or []:
        if isinstance(r, dict) and r.get("url"):
            refs.append(r["url"])
        elif isinstance(r, str):
            refs.append(r)
    return VulnerabilityDetail(
        id=vuln_id,
        summary=summary,
        severity=severity,
        references=refs,
    )


async def _fetch_osv_vuln_details(
    vuln_ids: list[str],
    proxy: str | None = None,
) -> dict[str, VulnerabilityDetail]:
    """Fetch full vulnerability details from OSV for each id. Returns map id -> detail."""
    details: dict[str, VulnerabilityDetail] = {}
    proxies = {"http://": proxy, "https://": proxy} if proxy else None
    async with httpx.AsyncClient(timeout=30.0, proxies=proxies) as client:
        for vid in vuln_ids:
            try:
                url = OSV_VULN_URL_TEMPLATE.format(id=quote(vid, safe="-"))
                resp = await client.get(url)
                if resp.status_code != 200:
                    details[vid] = VulnerabilityDetail(
                        id=vid,
                        summary="(failed to fetch details)",
                        severity="UNKNOWN",
                        references=[],
                    )
                    continue
                data = resp.json()
                details[vid] = _detail_from_osv(data)
            except Exception as e:
                logger.warning("OSV vuln fetch failed for %s: %s", vid, e)
                details[vid] = VulnerabilityDetail(
                    id=vid,
                    summary=f"(error: {e!s})",
                    severity="UNKNOWN",
                    references=[],
                )
    return details


async def check_versions_osv(
    group_id: str,
    artifact_id: str,
    versions: list[str],
    proxy: str | None = None,
) -> dict[str, list[VulnerabilityDetail]]:
    """
    For each version, query OSV and return version -> list of vulnerability details.
    Uses querybatch then fetches details for each unique vuln id.
    An optional proxy URL (e.g. http://proxy.corp.com:8080) is forwarded to all requests.
    """
    if not versions:
        return {}

    queries = [
        {"package": {"purl": _purl_maven(group_id, artifact_id, v)}}
        for v in versions
    ]
    proxies = {"http://": proxy, "https://": proxy} if proxy else None
    async with httpx.AsyncClient(timeout=60.0, proxies=proxies) as client:
        try:
            resp = await client.post(OSV_QUERYBATCH_URL, json={"queries": queries})
            resp.raise_for_status()
        except httpx.RequestError as e:
            logger.exception("OSV querybatch request failed")
            raise RuntimeError(f"OSV API unreachable: {e!s}") from e
        except httpx.HTTPStatusError as e:
            raise RuntimeError(f"OSV API error: {e.response.status_code}") from e

        data = resp.json()
    results = data.get("results") or []

    all_vuln_ids: set[str] = set()
    version_vuln_ids: list[list[str]] = []
    for res in results:
        vulns = res.get("vulns") or []
        ids = [v.get("id") for v in vulns if isinstance(v, dict) and v.get("id")]
        ids = [x for x in ids if isinstance(x, str)]
        version_vuln_ids.append(ids)
        all_vuln_ids.update(ids)

    detail_map = await _fetch_osv_vuln_details(list(all_vuln_ids), proxy=proxy)

    out: dict[str, list[VulnerabilityDetail]] = {}
    for v, ids in zip(versions, version_vuln_ids, strict=True):
        out[v] = [detail_map[vid] for vid in ids if vid in detail_map]
    return out


async def check_versions_sonatype_iq(
    iq_config: SonatypeIQConfig,
    group_id: str,
    artifact_id: str,
    versions: list[str],
) -> dict[str, list[VulnerabilityDetail]]:
    """
    Evaluate each version with Sonatype IQ and return version -> list of vulnerability details.
    Uses IQ Server Component Evaluation API (v2).
    """
    # IQ Server component evaluation: POST with component coordinates
    # Typical endpoint: POST {iq_url}/api/v2/evaluate or similar
    # Reference: https://help.sonatype.com/en/component-evaluation-rest-api.html
    out: dict[str, list[VulnerabilityDetail]] = {v: [] for v in versions}
    headers = {"Authorization": f"Bearer {iq_config.token}"}
    # IQ often uses application ID in the path or body
    eval_url = f"{iq_config.url.rstrip('/')}/api/v2/evaluate/applications/{iq_config.application_id}/components"

    async with httpx.AsyncClient(timeout=60.0) as client:
        for version in versions:
            try:
                body = {
                    "coordinates": [
                        {
                            "format": "maven",
                            "groupId": group_id,
                            "artifactId": artifact_id,
                            "version": version,
                        }
                    ]
                }
                resp = await client.post(eval_url, json=body, headers=headers)
                if resp.status_code != 200:
                    logger.warning(
                        "IQ evaluate failed for %s:%s:%s: %s",
                        group_id,
                        artifact_id,
                        version,
                        resp.status_code,
                    )
                    continue
                data = resp.json()
                # Map IQ response to VulnerabilityDetail; structure varies by IQ version
                components = data.get("components") or data.get("componentDetails") or []
                for comp in components:
                    for vuln in comp.get("vulnerabilities") or comp.get("securityData", {}).get("vulnerabilities") or []:
                        if isinstance(vuln, dict):
                            out[version].append(
                                VulnerabilityDetail(
                                    id=vuln.get("id") or vuln.get("identifier") or "unknown",
                                    summary=vuln.get("description") or vuln.get("title") or "",
                                    severity=vuln.get("severity") or vuln.get("cvssScore") or "UNKNOWN",
                                    references=[vuln.get("reference")] if vuln.get("reference") else [],
                                )
                            )
            except Exception as e:
                logger.warning("IQ check failed for %s: %s", version, e)
    return out


async def check_vulnerabilities(
    config: Config,
    group_id: str,
    artifact_id: str,
    versions: list[str],
) -> dict[str, list[VulnerabilityDetail]]:
    """
    Check vulnerabilities for the given versions using configured source (OSV or Sonatype IQ).
    If config is OSV and OSV fails, optionally fall back to IQ when configured.
    """
    if config.vuln_source == "sonatype_iq" and config.sonatype_iq:
        return await check_versions_sonatype_iq(
            config.sonatype_iq,
            group_id,
            artifact_id,
            versions,
        )

    try:
        return await check_versions_osv(group_id, artifact_id, versions, proxy=config.osv_proxy)
    except Exception as e:
        if config.sonatype_iq:
            logger.warning("OSV failed (%s), falling back to Sonatype IQ", e)
            return await check_versions_sonatype_iq(
                config.sonatype_iq,
                group_id,
                artifact_id,
                versions,
            )
        raise
