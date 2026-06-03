# Install VulnCheck MCP in Codex CLI

[Codex CLI](https://github.com/openai/codex) is OpenAI's terminal-based coding agent.

## Prerequisites

- Codex CLI installed
- [VulnCheck API token](https://console.vulncheck.com/settings/tokens)
- For Docker setup: [Docker](https://www.docker.com/) installed and running

## Configuration

MCP servers are configured in `~/.codex/config.toml`.

### With Docker

```toml
[mcp_servers.vulncheck]
command = "docker"
args = ["run", "--rm", "-i", "-e", "VULNCHECK_API_TOKEN", "ghcr.io/vulncheck-oss/mcp"]
env = { VULNCHECK_API_TOKEN = "YOUR_TOKEN" }
```

### With a Binary (no Docker)

1. Download the [latest release](https://github.com/vulncheck-oss/mcp/releases/latest) and add it to your `PATH`
2. Add to `~/.codex/config.toml`:

   ```toml
   [mcp_servers.vulncheck]
   command = "vulncheck-mcp"
   args = ["-transport", "stdio"]
   env = { VULNCHECK_API_TOKEN = "YOUR_TOKEN" }
   ```

### Via CLI

```bash
codex mcp add vulncheck --env VULNCHECK_API_TOKEN=YOUR_TOKEN -- vulncheck-mcp -transport stdio
```

## Verification

Start Codex and run `/mcp` to confirm `vulncheck` is listed with its available tools.

## Troubleshooting

**Server not listed:**
- Validate TOML syntax in `~/.codex/config.toml`
- Restart Codex after saving the config

**Authentication failed:**
- Verify your token at [console.vulncheck.com](https://console.vulncheck.com/settings/tokens)
- Ensure `VULNCHECK_API_TOKEN` is spelled correctly

**Docker issues:**
- Ensure Docker Desktop is running
- Try pulling the image manually: `docker pull ghcr.io/vulncheck-oss/mcp`
