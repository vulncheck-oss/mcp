# Install VulnCheck MCP in Gemini CLI

## Prerequisites

- [Gemini CLI](https://github.com/google-gemini/gemini-cli) installed
- [VulnCheck API token](https://console.vulncheck.com/settings/tokens)
- For Docker setup: [Docker](https://www.docker.com/) installed and running

## Configuration

MCP servers are configured in Gemini CLI's settings JSON under an `mcpServers` key.

- **Global**: `~/.gemini/settings.json`
- **Project-specific**: `.gemini/settings.json` in your project root

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
2. Add to `~/.gemini/settings.json`:

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

Restart Gemini CLI after saving.

## Verification

Start Gemini CLI and run:

```
/mcp list
```

You should see `vulncheck` listed with a green status and its available tools.

## Troubleshooting

**Server not listed:**
- Validate JSON syntax: `cat ~/.gemini/settings.json | jq .`
- Restart Gemini CLI after any config change

**Authentication failed:**
- Verify your token at [console.vulncheck.com](https://console.vulncheck.com/settings/tokens)
- Ensure `VULNCHECK_API_TOKEN` is spelled correctly

**Docker issues:**
- Ensure Docker Desktop is running
- Try pulling the image manually: `docker pull ghcr.io/vulncheck-oss/mcp`
