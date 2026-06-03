# vulncheck-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes [VulnCheck](https://vulncheck.com) vulnerability intelligence to AI assistants.

## Requirements

- A VulnCheck API token — create one [here](https://console.vulncheck.com/settings/tokens)

## Installation

Download the latest release from the [Releases page](https://github.com/vulncheck-oss/mcp/releases/latest), or use the Docker image (`ghcr.io/vulncheck-oss/mcp`).

| Platform | Archive |
|----------|---------|
| macOS (Apple Silicon) | `vulncheck-mcp_VERSION_darwin_arm64.tar.gz` |
| macOS (Intel) | `vulncheck-mcp_VERSION_darwin_amd64.tar.gz` |
| Linux | `vulncheck-mcp_VERSION_linux_amd64.tar.gz` |
| Windows | `vulncheck-mcp_VERSION_windows_amd64.zip` |

### Install in Your AI Client

- **[Claude Code & Claude Desktop](docs/installation-guides/install-claude.md)** — Installation guide for Claude Code CLI and Claude Desktop

## Available Tools

See [docs/tools.md](docs/tools.md) for the full list of available tools.

## Development

```bash
make build      # build for current platform → bin/vulncheck-mcp
make build-all  # cross-compile all platforms → dist/
make test       # run tests
make lint       # run golangci-lint
```
