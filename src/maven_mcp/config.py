"""Configuration via environment variables and constructor args."""

import os
from dataclasses import dataclass
from typing import Literal


VulnSource = Literal["osv", "sonatype_iq"]
Transport = Literal["stdio", "streamable-http"]


@dataclass
class NexusConfig:
    """Nexus 3 connection settings."""

    url: str
    username: str | None = None
    password: str | None = None
    repository: str = "maven-releases"


@dataclass
class SonatypeIQConfig:
    """Sonatype IQ Server settings (fallback vulnerability source)."""

    url: str
    token: str
    application_id: str


@dataclass
class Config:
    """Maven MCP server configuration."""

    nexus: NexusConfig
    vuln_source: VulnSource = "osv"
    sonatype_iq: SonatypeIQConfig | None = None
    mcp_transport: Transport = "stdio"
    mcp_port: int = 8000
    osv_proxy: str | None = None
    """HTTP/HTTPS proxy URL for OSV.dev API calls (e.g. http://proxy.corp.com:8080)."""

    @classmethod
    def from_env(cls) -> "Config":
        """Build configuration from environment variables."""
        nexus_url = os.environ.get("NEXUS_URL", "").rstrip("/")
        if not nexus_url:
            raise ValueError("NEXUS_URL is required")

        nexus = NexusConfig(
            url=nexus_url,
            username=os.environ.get("NEXUS_USERNAME") or None,
            password=os.environ.get("NEXUS_PASSWORD") or None,
            repository=os.environ.get("NEXUS_REPOSITORY", "maven-releases"),
        )

        vuln_source_raw = (os.environ.get("VULN_SOURCE") or "osv").strip().lower()
        vuln_source: VulnSource = "osv"
        if vuln_source_raw == "sonatype_iq":
            vuln_source = "sonatype_iq"

        sonatype_iq: SonatypeIQConfig | None = None
        if vuln_source == "sonatype_iq":
            iq_url = os.environ.get("SONATYPE_IQ_URL", "").rstrip("/")
            iq_token = os.environ.get("SONATYPE_IQ_TOKEN")
            iq_app_id = os.environ.get("SONATYPE_IQ_APP_ID")
            if not iq_url or not iq_token or not iq_app_id:
                raise ValueError(
                    "SONATYPE_IQ_URL, SONATYPE_IQ_TOKEN, and SONATYPE_IQ_APP_ID are required when VULN_SOURCE=sonatype_iq"
                )
            sonatype_iq = SonatypeIQConfig(url=iq_url, token=iq_token, application_id=iq_app_id)
        else:
            # Optional IQ config for fallback when VULN_SOURCE=osv
            iq_url = os.environ.get("SONATYPE_IQ_URL", "").rstrip("/")
            iq_token = os.environ.get("SONATYPE_IQ_TOKEN")
            iq_app_id = os.environ.get("SONATYPE_IQ_APP_ID")
            if iq_url and iq_token and iq_app_id:
                sonatype_iq = SonatypeIQConfig(url=iq_url, token=iq_token, application_id=iq_app_id)

        transport_raw = (os.environ.get("MCP_TRANSPORT") or "stdio").strip().lower()
        mcp_transport: Transport = "stdio"
        if transport_raw == "streamable-http":
            mcp_transport = "streamable-http"

        try:
            mcp_port = int(os.environ.get("MCP_PORT", "8000"))
        except ValueError:
            mcp_port = 8000

        osv_proxy = os.environ.get("OSV_PROXY") or None

        return cls(
            nexus=nexus,
            vuln_source=vuln_source,
            sonatype_iq=sonatype_iq,
            mcp_transport=mcp_transport,
            mcp_port=mcp_port,
            osv_proxy=osv_proxy,
        )
