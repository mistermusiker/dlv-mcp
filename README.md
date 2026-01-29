# DLV MCP - Wordpress Debug Log Viewer and MCP Server

## Let your vibe coding AI talk to your debug log.

A WordPress plugin that provides a modern debug log viewer with an integrated MCP (Model Context Protocol) Server for AI-assisted Wordpress debugging with Claude Code and Cursor.

DLV-MCP lets you ask Cursor and Claude Code connect to your wordpress log, read it, aks questions about it and find errors. 

## Description

DLV-MCP makes WordPress debugging easier by providing:

- **Admin Log Viewer** - View, search, and filter debug logs directly in WordPress admin
- **Log Management** - Enable/disable logging, clear logs, download log files
- **Log Rotation** - Automatic rotation when logs exceed 1 MB
- **MCP Server** - REST API for AI-assisted debugging with Claude Code, Cursor or other MCP-compatible tools
- **Secure Access** - API key authentication for remote access

## Requirements

- WordPress 5.8 or higher
- PHP 7.4 or higher

## Installation

### Manual Installation

1. Download the plugin files
2. Upload the `dlv-mcp` folder to `/wp-content/plugins/`
3. Activate the plugin through the 'Plugins' menu in WordPress

### From WordPress Admin

1. Go to Plugins > Add New
2. Search for "DLV-MCP"
3. Click "Install Now" and then "Activate"

## Configuration

### Enable Debug Logging

1. Go to **Tools > DLV-MCP** in your WordPress admin
2. Click **"Enable logging"** to create a new log file
3. The plugin will automatically configure PHP error logging

### View Debug Logs

1. Go to **Tools > DLV-MCP**
2. The log viewer shows the most recent entries
3. Use the search field to filter log entries
4. Toggle "Wrap lines" and "Highlight" for better readability
5. Enable "Auto-refresh" to monitor logs in real-time

### MCP Server Setup

The MCP Server allows AI assistants like Claude Code to read and analyze your debug logs.

1. Go to **Tools > DLV-MCP Settings**
2. Ensure the MCP Server status shows **"Enabled"**
3. Click **"Generate New API Key"** and give it a name
4. **Important:** Copy the API key immediately - it will only be shown once!

After generating a key, you'll see a **Quick Integration** panel with ready-to-use configurations for Claude Code and Cursor IDE.

## Using DLV MCP with Claude Code

### What is MCP?

The Model Context Protocol (MCP) is an open standard that allows AI assistants like Claude to securely connect to external tools and data sources. DLV-MCP implements an MCP Server that gives Claude Code direct access to your WordPress debug logs.

This means you can ask Claude natural language questions like:
- "Show me the recent PHP errors"
- "Search the debug log for database errors"
- "What errors occurred in the last 30 minutes?"

And Claude will automatically use the DLV-MCP tools to fetch and analyze the data.

### Step 1: Generate an API Key

1. In WordPress admin, go to **Tools > DLV-MCP Settings**
2. Enter a name for your key (e.g., "Claude Code Local")
3. Click **"Generate New API Key"**
4. **Copy the key immediately** - it will only be shown once!

### Step 2: Add the MCP Server to Claude Code

#### Option A: Quick Integration (Recommended)

After generating an API key, you'll see a **Claude Code** section in the Quick Integration panel. Simply copy the pre-configured command and run it in your terminal:

```bash
claude mcp add --transport http 'your-site-debug-log' 'https://your-site.com/wp-json/dlv-mcp/v1/mcp' --header "Authorization: Bearer YOUR_API_KEY"
```

The plugin generates this command with your actual site URL and API key - just click **"Copy Command"** and paste it into your terminal.

#### Option B: Manual Configuration

If you prefer to configure manually, run this command in your terminal:

```bash
claude mcp add --transport http 'my-wordpress-debug' 'https://your-site.com/wp-json/dlv-mcp/v1/mcp' --header "Authorization: Bearer YOUR_API_KEY"
```

Replace:
- `my-wordpress-debug` with a name of your choice
- `your-site.com` with your WordPress site URL
- `YOUR_API_KEY` with the key you generated

Verify the connection:

```bash
claude mcp list
```

You should see your server listed as "Connected".

### Step 3: Start Debugging with Claude

Once connected, you can ask Claude Code questions about your WordPress debug log:

**Example prompts:**

```
Check the debug log for errors
```

```
Show me the last 50 lines of the WordPress debug log
```

```
Search the debug log for "Fatal error"
```

```
Are there any PHP warnings in the last hour?
```

```
What's the current size of the debug log?
```

```
Find all database-related errors in the log
```

Claude will automatically use the appropriate DLV MCP tool to answer your question.

### Step 4: Integrate into Your Workflow

For seamless integration, add the MCP server info to your Claude Code memory file:

**File:** `~/.claude/CLAUDE.md`

```markdown
## WordPress Debug Log Access

MCP Server for WordPress debugging is available.
Endpoint: https://your-site.com/wp-json/dlv-mcp/v1/mcp

When debugging WordPress issues, use the debug log tools to check for errors.
```

This way, Claude will remember the connection across all your projects.

## Using DLV-MCP with Cursor IDE

Cursor IDE natively supports MCP (Model Context Protocol), allowing you to integrate DLV MCP directly into your development workflow.

### Step 1: Generate an API Key

1. In WordPress admin, go to **Tools > DLV-MCP Settings**
2. Enter a name for your key (e.g., "Cursor IDE")
3. Click **"Generate New API Key"**
4. **Copy the key immediately** - it will only be shown once!

### Step 2: Configure MCP Server in Cursor

#### Option A: One-Click Installation (Recommended)

After generating an API key, you'll see a **Cursor IDE** section in the Quick Integration panel:

1. Click **"Add to Cursor IDE"** - this opens Cursor and installs the MCP server automatically
2. Alternatively, click **"Copy Link"** to copy the installation URL

This is the fastest way to get started with Cursor.

#### Option B: Manual Configuration (mcp.json)

Create a `.cursor/mcp.json` file in your project root. After generating an API key, you'll see the ready-to-use JSON configuration in the **Manual Configuration** section - just click **"Copy Configuration"**:

```json
{
  "mcpServers": {
    "your-site-debug-log": {
      "url": "https://your-site.com/wp-json/dlv-mcp/v1/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

The plugin provides the complete JSON with your actual site URL and API key pre-filled.

**Important:** Add `.cursor/mcp.json` to your `.gitignore` file to prevent committing sensitive API keys.

#### Option C: Global Configuration

For global access across all projects, create `~/.cursor/mcp.json` in your home directory with the same configuration.

#### Option D: Using Environment Variables

You can use environment variable interpolation in the config:

```json
{
  "mcpServers": {
    "your-site-debug-log": {
      "url": "https://your-site.com/wp-json/dlv-mcp/v1/mcp",
      "headers": {
        "Authorization": "Bearer ${env:DLV_MCP_API_KEY}"
      }
    }
  }
}
```

Then set the environment variable:
```bash
export DLV_MCP_API_KEY="your-api-key-here"
```

### Step 3: Verify Installation

1. Restart Cursor IDE to load the MCP configuration
2. Open Settings (`Cmd+Shift+J` on Mac, `Ctrl+Shift+J` on Windows/Linux)
3. Navigate to **Features → Model Context Protocol**
4. Verify that your MCP server appears in the list and is enabled

### Step 4: Use MCP Tools in Cursor

Once configured, you can ask Cursor's AI assistant questions about your WordPress debug logs:

**Example prompts:**

```
Check the debug log for errors
```

```
Show me the last 50 lines of the WordPress debug log
```

```
Search the debug log for "Fatal error"
```

```
What errors occurred in the last hour?
```

```
Get information about the debug log file
```

Cursor will automatically use the appropriate DLV MCP tool to fetch and analyze the data. You can see available tools listed under "Available Tools" in the chat interface.

### Troubleshooting

**"MCP Server not connected"**
- Check that the API key is correct in your `mcp.json` file
- Verify the endpoint URL is accessible (test with curl)
- Ensure the MCP Server is enabled in WordPress (Tools > DLV MCP Settings)
- Restart Cursor IDE after configuration changes

**"401 Unauthorized"**
- The API key is invalid or expired
- Generate a new key in WordPress admin and update your `mcp.json`

**"Server not appearing in Cursor"**
- Check the MCP logs: Open Output Panel (`Cmd+Shift+U`), select "MCP Logs"
- Verify JSON syntax in `mcp.json` is valid
- Ensure the file is in the correct location (`.cursor/mcp.json` for project, `~/.cursor/mcp.json` for global)

### Available MCP Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `get_debug_log` | Get last N lines from the log | `lines` (default: 100, max: 1000) |
| `search_debug_log` | Search the log for a pattern | `pattern` (required), `max_results` (default: 100) |
| `get_errors_since` | Get errors from the last N minutes | `minutes_ago` (default: 60), `timestamp` |
| `get_log_info` | Get log file information | - |
| `tail_debug_log` | Get most recent log entries | `bytes` (default: 10000) |
| `clear_debug_log` | Clear the debug log | `confirm` (must be true) |

### Direct API Access (curl)

For advanced use cases or when MCP is not available, you can use curl to directly access the API.

Add this to your `~/.claude/CLAUDE.md`:

```bash
# Get log file info
curl -s -X POST "https://your-site.com/wp-json/dlv-mcp/v1/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_log_info","arguments":{}},"id":1}'

# Get last 50 lines
curl -s -X POST "https://your-site.com/wp-json/dlv-mcp/v1/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_debug_log","arguments":{"lines":50}},"id":1}'

# Search for errors
curl -s -X POST "https://your-site.com/wp-json/dlv-mcp/v1/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_debug_log","arguments":{"pattern":"Fatal error","max_results":10}},"id":1}'
```

### Claude Code CLAUDE.md Template

Add this to your `~/.claude/CLAUDE.md` for global access:

```markdown
## DLV MCP Server (WordPress Debug Log)

The DLV MCP WordPress plugin provides an MCP Server for AI-assisted debugging.

**Endpoint:** `https://your-site.com/wp-json/dlv-mcp/v1/mcp`
**Auth:** `Bearer YOUR_API_KEY`

### Available Tools

1. **get_debug_log** - Get last N lines from the log (default: 100, max: 1000)
2. **search_debug_log** - Search the log for a pattern (pattern, max_results)
3. **get_errors_since** - Get errors from the last N minutes (minutes_ago)
4. **get_log_info** - Get log file information (size, lines, last modified)
5. **tail_debug_log** - Get most recent log entries by bytes (bytes)
6. **clear_debug_log** - Clear the debug log (confirm: true required)
```

## Security

- Log files are stored in `wp-content/uploads/dlv-mcp-logs/` with `.htaccess` protection
- API access requires a valid API key
- Only users with `manage_options` capability can access the admin interface
- API keys can be revoked at any time from the MCP settings page

## Frequently Asked Questions

### Where are log files stored?

Log files are stored in `wp-content/uploads/dlv-mcp-logs/` with automatic protection against direct web access.

### How do I enable WordPress debug mode?

Add this to your `wp-config.php`:

```php
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
```

Note: DLV-MCP will override the log file location when logging is enabled.

### Can I use multiple API keys?

Yes! You can generate multiple API keys for different team members or applications. Each key can be revoked independently.

### Is the MCP Server compatible with other AI tools?

The MCP Server follows the Model Context Protocol specification (version 2025-11-25) and should work with any MCP-compatible client.

## Changelog

### 0.0.7
- Initial release

## License

GPL v2 or later - https://www.gnu.org/licenses/gpl-2.0.html

## Author

Roger Kirchhoff

## Support

For bug reports and feature requests, please use the GitHub issue tracker.
