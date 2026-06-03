# Install VulnCheck MCP in VS Code

## Prerequisites

- VS Code or VS Code Insiders installed (latest version)
- [GitHub Copilot](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot) extension installed and active
- [VulnCheck API token](https://console.vulncheck.com/settings/tokens)
- For Docker setup: [Docker](https://www.docker.com/) installed and running

## With Docker

Add the following to your VS Code `settings.json`:

```json
{
  "mcp": {
    "servers": {
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
}
```

## With a Binary (no Docker)

1. Download the [latest release](https://github.com/vulncheck-oss/mcp/releases/latest) and add it to your `PATH`
2. Add the following to your VS Code `settings.json`:

   ```json
   {
     "mcp": {
       "servers": {
         "vulncheck": {
           "command": "vulncheck-mcp",
           "args": ["-transport", "stdio"],
           "env": {
             "VULNCHECK_API_TOKEN": "YOUR_TOKEN"
           }
         }
       }
     }
   }
   ```

## Configuration Files

Open `settings.json` via **Command Palette** (`Cmd/Ctrl+Shift+P`) → `Preferences: Open User Settings (JSON)` for global configuration, or add a `.vscode/mcp.json` file in your project root for project-scoped configuration:

```json
{
  "servers": {
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

> Note: `.vscode/mcp.json` does not use the `mcp.servers` wrapper — just `servers` directly.

## Verification

1. Open the Copilot Chat panel
2. Switch to **Agent** mode
3. Click the **Tools** button and confirm VulnCheck tools are listed

## Troubleshooting

**Tools not appearing:**
- Ensure you are in **Agent** mode in Copilot Chat (not Ask or Edit)
- Reload VS Code after saving `settings.json`
- Check the Output panel → **GitHub Copilot** for MCP errors

**Authentication failed:**
- Verify your token at [console.vulncheck.com](https://console.vulncheck.com/settings/tokens)
- Ensure `VULNCHECK_API_TOKEN` is spelled correctly

**Docker issues:**
- Ensure Docker Desktop is running
- Try pulling the image manually: `docker pull ghcr.io/vulncheck-oss/mcp`
