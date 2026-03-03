"""Nexus 3 REST API client for fetching Maven artifact versions."""

from __future__ import annotations

import logging
from urllib.parse import urlencode

import httpx

from .config import NexusConfig

logger = logging.getLogger(__name__)

NEXUS_SEARCH_PATH = "/service/rest/v1/search"


class NexusClientError(Exception):
    """Raised when Nexus API requests fail."""

    pass


class NexusClient:
    """Async client for Nexus 3 component search API."""

    def __init__(self, config: NexusConfig) -> None:
        self._config = config
        self._base = config.url.rstrip("/")

    def _auth(self) -> httpx.Auth | None:
        if self._config.username and self._config.password:
            return httpx.BasicAuth(self._config.username, self._config.password)
        return None

    async def get_versions(self, group_id: str, artifact_id: str) -> list[str]:
        """
        Fetch all distinct versions of a Maven artifact from the configured repository.

        Uses pagination via continuationToken to collect every version.
        """
        seen: set[str] = set()
        continuation_token: str | None = None

        async with httpx.AsyncClient(auth=self._auth(), timeout=60.0) as client:
            while True:
                params: dict[str, str] = {
                    "repository": self._config.repository,
                    "maven.groupId": group_id,
                    "maven.artifactId": artifact_id,
                }
                if continuation_token:
                    params["continuationToken"] = continuation_token

                url = f"{self._base}{NEXUS_SEARCH_PATH}?{urlencode(params)}"
                try:
                    resp = await client.get(url)
                    resp.raise_for_status()
                except httpx.HTTPStatusError as e:
                    raise NexusClientError(
                        f"Nexus search failed: {e.response.status_code} {e.response.text}"
                    ) from e
                except httpx.RequestError as e:
                    raise NexusClientError(f"Nexus request failed: {e!s}") from e

                data = resp.json()
                items = data.get("items") or []
                for item in items:
                    ver = item.get("version")
                    if isinstance(ver, str) and ver.strip():
                        seen.add(ver.strip())

                continuation_token = data.get("continuationToken")
                if not continuation_token:
                    break

        return sorted(seen)
