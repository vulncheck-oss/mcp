# Install VulnCheck MCP in Cursor

## Prerequisites

- Cursor IDE installed (latest version)
- [VulnCheck API token](https://console.vulncheck.com/settings/tokens)
- For Docker setup: [Docker](https://www.docker.com/) installed and running

## With Docker

Open `~/.cursor/mcp.json` and add:

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

## With a Binary (no Docker)

1. Download the [latest release](https://github.com/vulncheck-oss/mcp/releases/latest) and add it to your `PATH`
2. Open `~/.cursor/mcp.json` and add:

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

## Configuration Files

- **Global (all projects)**: `~/.cursor/mcp.json`
- **Project-specific**: `.cursor/mcp.json` in project root

## Verification

1. Restart Cursor completely
2. Go to Settings → Tools & Integrations → MCP Tools
3. Look for a green dot next to `vulncheck`

## Troubleshooting

**Tools not appearing / server not starting:**
- Restart Cursor completely after saving the config file
- Validate JSON syntax in `mcp.json`
- Check for a red dot in Settings → Tools & Integrations → MCP Tools for error details

**Authentication failed:**
- Verify your token at [console.vulncheck.com](https://console.vulncheck.com/settings/tokens)
- Ensure `VULNCHECK_API_TOKEN` is spelled correctly

**Docker issues:**
- Ensure Docker Desktop is running
- Try pulling the image manually: `docker pull ghcr.io/vulncheck-oss/mcp`
