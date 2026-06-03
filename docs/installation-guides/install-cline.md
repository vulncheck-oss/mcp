# Install VulnCheck MCP in Cline

[Cline](https://github.com/cline/cline) is an AI coding assistant that runs inside VS Code-compatible editors (VS Code, Cursor, Windsurf, etc.).

## Prerequisites

- Cline extension installed in your editor
- [VulnCheck API token](https://console.vulncheck.com/settings/tokens)
- For Docker setup: [Docker](https://www.docker.com/) installed and running

## Configuration

1. Click the Cline icon in your editor's sidebar
2. Open the menu in the top right of the Cline panel and select **MCP Servers**
3. Click **Configure MCP Servers** to open `cline_mcp_settings.json`
4. Add your chosen configuration below, then save

### With Docker

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
2. Add to `cline_mcp_settings.json`:

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

## Verification

After saving, the server should connect automatically. Look for a green indicator next to `vulncheck` in the MCP Servers list.

## Troubleshooting

**Server not connecting:**
- Verify JSON syntax in `cline_mcp_settings.json`
- Restart your editor after saving

**Authentication failed:**
- Verify your token at [console.vulncheck.com](https://console.vulncheck.com/settings/tokens)
- Ensure `VULNCHECK_API_TOKEN` is spelled correctly

**Docker issues:**
- Ensure Docker Desktop is running
- Try pulling the image manually: `docker pull ghcr.io/vulncheck-oss/mcp`
