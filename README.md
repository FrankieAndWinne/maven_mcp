# maven_mcp

MCP server that fetches Maven artifact versions from a **Nexus 3** repository and checks each for known vulnerabilities via **OSV.dev** (or **Sonatype IQ** as fallback). Returns only **non-breaking** newer versions (same major version).

**Requires Python 3.10+** (MCP SDK requirement).

## Features

- **Nexus 3**: Fetches all versions for a given `groupId` and `artifactId` from a private Nexus Repository Manager 3.x (with pagination).
- **Version filtering**: Returns only versions with the **same major version** as the current version (e.g. for `1.8.5` only `1.9.x`, not `2.x`), and excludes SNAPSHOTs by default.
- **Vulnerability checks**: Uses [OSV.dev](https://osv.dev) API by default (no API key). Optional fallback to **Sonatype IQ Server** when OSV is unreachable (e.g. in air-gapped K8s).
- **MCP**: Exposes one tool, `check_maven_versions`, and supports **stdio** (local) and **streamable-http** (e.g. K8s) transports.

## Installation

```bash
cd maven_mcp
pip install -e .
# or
uv pip install -e .
```

## Configuration

All configuration is via **environment variables**.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEXUS_URL` | Yes | — | Base URL of Nexus 3 (e.g. `https://nexus.company.com`) |
| `NEXUS_USERNAME` | No | — | Username for Nexus (if repo requires auth) |
| `NEXUS_PASSWORD` | No | — | Password for Nexus |
| `NEXUS_REPOSITORY` | No | `maven-releases` | Repository name to search |
| `VULN_SOURCE` | No | `osv` | `osv` or `sonatype_iq` |
| `OSV_PROXY` | No | — | HTTP/HTTPS proxy for OSV.dev API calls (e.g. `http://proxy.corp.com:8080`) |
| `SONATYPE_IQ_URL` | If IQ | — | Sonatype IQ Server base URL |
| `SONATYPE_IQ_TOKEN` | If IQ | — | IQ API token |
| `SONATYPE_IQ_APP_ID` | If IQ | — | IQ application ID for evaluation |
| `MCP_TRANSPORT` | No | `stdio` | `stdio` or `streamable-http` |
| `MCP_PORT` | No | `8000` | Port for HTTP transport (set before process start) |
| `MCP_HOST` | No | `0.0.0.0` | Bind address for HTTP transport (set before process start) |

When `VULN_SOURCE=osv`, you can still set `SONATYPE_IQ_*`; the server will use IQ as fallback if OSV is unreachable.

## Running the server

**Stdio (local):**

```bash
export NEXUS_URL=https://nexus.example.com
maven-mcp
# or
python -m maven_mcp.server
```

**Streamable HTTP (e.g. K8s):**

```bash
export NEXUS_URL=https://nexus.example.com
export MCP_TRANSPORT=streamable-http
export MCP_PORT=8000
maven-mcp
```

Then connect clients to `http://localhost:8000/mcp` (or your deployed URL).

## Tool: `check_maven_versions`

**Parameters:**

- `group_id` (string): Maven groupId (e.g. `org.springframework`)
- `artifact_id` (string): Maven artifactId (e.g. `spring-web`)
- `current_version` (string): Current version (e.g. `1.8.5`) used to filter same-major and newer versions

**Returns:** A list of objects, one per candidate version, each with:

- `version`: Version string
- `vulnerabilities`: List of `{ id, summary, severity, references }`
- `vulnerability_count`: Number of vulnerabilities

Only versions **newer than** `current_version` and with the **same major version** are returned (e.g. for `1.8.5` you get `1.9.5`, `1.9.8`, but not `2.0.1`). SNAPSHOT versions are excluded.

**Example (conceptual):**

Request: `group_id=com.example`, `artifact_id=my-lib`, `current_version=1.8.5`  
Response: `[{ "version": "1.9.5", "vulnerabilities": [...], "vulnerability_count": 0 }, { "version": "1.9.8", ... }]`

## License

MIT
