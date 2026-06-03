# Install VulnCheck MCP in Claude Applications

## Claude Code CLI

### Prerequisites
- Claude Code CLI installed
- [VulnCheck API token](https://console.vulncheck.com/settings/tokens)
- For Docker setup: [Docker](https://www.docker.com/) installed and running

### With Docker

```bash
claude mcp add vulncheck -e VULNCHECK_API_TOKEN=YOUR_TOKEN -- \
  docker run -i --rm -e VULNCHECK_API_TOKEN ghcr.io/vulncheck-oss/mcp
```

With an environment variable:
```bash
claude mcp add vulncheck -e VULNCHECK_API_TOKEN=$(grep VULNCHECK_API_TOKEN .env | cut -d '=' -f2) -- \
  docker run -i --rm -e VULNCHECK_API_TOKEN ghcr.io/vulncheck-oss/mcp
```

### With a Binary (no Docker)

1. Download the [latest release](https://github.com/vulncheck-oss/mcp/releases/latest) and add it to your `PATH`
2. Run:

   ```bash
   claude mcp add-json vulncheck '{"command":"vulncheck-mcp","args":["-transport","stdio"],"env":{"VULNCHECK_API_TOKEN":"YOUR_TOKEN"}}'
   ```

### Verification

```bash
claude mcp list
claude mcp get vulncheck
```

> **About the `--scope` flag** (optional): Use `--scope user` to make the server available across all projects instead of only the current one.

---

## Claude Desktop

### Prerequisites
- Claude Desktop installed (latest version)
- [VulnCheck API token](https://console.vulncheck.com/settings/tokens)
- For Docker setup: [Docker](https://www.docker.com/) installed and running

### Configuration File Location
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### With Docker

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vulncheck": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e",
        "VULNCHECK_API_TOKEN",
        "ghcr.io/vulncheck-oss/mcp"
      ],
      "env": {
        "VULNCHECK_API_TOKEN": "YOUR_TOKEN"
      }
    }
  }
}
```

### With a Binary (no Docker)

1. Download the [latest release](https://github.com/vulncheck-oss/mcp/releases/latest) and add it to your `PATH`
2. Add the following to your `claude_desktop_config.json`:

   ```json
   {
     "mcpServers": {
       "vulncheck": {
         "command": "vulncheck-mcp",
         "args": ["-transport", "stdio"],
         "env": {
           "VULNCHECK_API_TOKEN": "YOUR_TOKEN"
         }
       }
     }
   }
   ```

3. Restart Claude Desktop after saving the configuration file.

---

## Troubleshooting

**Authentication failed / no results:**
- Verify your token is valid at [console.vulncheck.com](https://console.vulncheck.com/settings/tokens)
- Ensure `VULNCHECK_API_TOKEN` is spelled correctly — no quotes around the value in JSON

**Docker issues:**
- Ensure Docker Desktop is running
- Try pulling the image manually: `docker pull ghcr.io/vulncheck-oss/mcp`

**Server not starting / tools not showing:**
- Validate JSON syntax in your config file
- Claude Code: run `claude mcp list` and check `/mcp` command output
- Claude Desktop logs:
  - macOS: `~/Library/Logs/Claude/mcp-server-vulncheck.log`
  - Windows: `%APPDATA%\Claude\logs\`
- Remove and re-add: `claude mcp remove vulncheck` then repeat setup