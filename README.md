# vulncheck-mcp

The VulnCheck MCP Server connects AI assistants to [VulnCheck](https://vulncheck.com) vulnerability intelligence. Ask your AI tools about CVEs, exploits, advisories, and vulnerable packages — directly in your editor or terminal, using natural language.

### Use Cases

- **CVE research**: Look up vulnerability details, severity, exploitability, and affected versions while reviewing code or triaging issues
- **Dependency analysis**: Check packages by CPE or PURL to identify known vulnerabilities before shipping
- **Exploit intelligence**: Determine whether a CVE has known exploit code, active exploitation, or C2 indicators
- **Advisory lookup**: Search vendor and ecosystem advisories by package, product, or keyword
- **Index queries**: Query VulnCheck's breach, botnet, and threat intelligence indices for real-time context

---

## Requirements

- A VulnCheck API token — create one [here](https://console.vulncheck.com/settings/tokens)

## Installation

Download the latest release from the [Releases page](https://github.com/vulncheck-oss/mcp/releases/latest), or use the Docker image (`ghcr.io/vulncheck-oss/mcp`).

| Platform | Archive |
|----------|---------|
| macOS (Apple Silicon) | `vulncheck-mcp_1.2.3_darwin_arm64.tar.gz` |
| macOS (Intel) | `vulncheck-mcp_1.2.3_darwin_amd64.tar.gz` |
| Linux | `vulncheck-mcp_1.2.3_linux_amd64.tar.gz` |
| Windows | `vulncheck-mcp_1.2.3_windows_amd64.zip` |

### Install in Your AI Client

- **[Claude Code & Claude Desktop](docs/installation-guides/install-claude.md)**
- **[Cursor](docs/installation-guides/install-cursor.md)**
- **[VS Code](docs/installation-guides/install-vscode.md)**
- **[Windsurf](docs/installation-guides/install-windsurf.md)**
- **[Cline](docs/installation-guides/install-cline.md)**
- **[Roo Code](docs/installation-guides/install-roo-code.md)**
- **[Gemini CLI](docs/installation-guides/install-gemini-cli.md)**
- **[Codex CLI](docs/installation-guides/install-codex.md)**

## Available Tools

See [docs/tools.md](docs/tools.md) for the full list of available tools.

## Development

```bash
make build      # build for current platform → bin/vulncheck-mcp
make snapshot   # cross-compile all platforms via GoReleaser → dist/
make test       # run tests
make lint       # run golangci-lint
```
