# Install VulnCheck MCP in Windsurf

## Prerequisites

- Windsurf IDE installed (latest version)
- [VulnCheck API token](https://console.vulncheck.com/settings/tokens)
- For Docker setup: [Docker](https://www.docker.com/) installed and running

## With Docker

1. Click the hammer icon (🔨) in Cascade
2. Click **Configure** to open `~/.codeium/windsurf/mcp_config.json`
3. Add the following:

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

4. Save the file and click **Refresh** (🔄) in the MCP toolbar

## With a Binary (no Docker)

1. Download the [latest release](https://github.com/vulncheck-oss/mcp/releases/latest) and add it to your `PATH`
2. Click the hammer icon (🔨) in Cascade and click **Configure**
3. Add the following to `~/.codeium/windsurf/mcp_config.json`:

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

4. Save the file and click **Refresh** (🔄) in the MCP toolbar

## Configuration Details

- **File path**: `~/.codeium/windsurf/mcp_config.json`
- **Scope**: Global only — Windsurf does not support per-project MCP configuration

## Verification

After saving and refreshing:
1. Look for "1 available MCP server" in the MCP toolbar
2. Click the hammer icon to confirm VulnCheck tools are listed

## Troubleshooting

**Tools not appearing:**
- Click **Refresh** (🔄) in the MCP toolbar after any config change
- Validate JSON syntax — use a linter if unsure
- Restart Windsurf completely if refresh doesn't help

**Authentication failed:**
- Verify your token at [console.vulncheck.com](https://console.vulncheck.com/settings/tokens)
- Ensure `VULNCHECK_API_TOKEN` is spelled correctly

**Docker issues:**
- Ensure Docker Desktop is running
- Try pulling the image manually: `docker pull ghcr.io/vulncheck-oss/mcp`
- Check logs at `~/.codeium/windsurf/logs/`
