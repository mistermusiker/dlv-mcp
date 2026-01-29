=== DLV-MCP - Debug Log Viewer with MCP Server ===
Contributors: mistermusiker
Author: Roger Kirchhoff
Tags: debug, log, mcp, ai, debugging, claude, cursor, developer, error-log
Requires at least: 5.8
Tested up to: 6.7
Stable tag: 0.0.7
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Debug Log Viewer with MCP Server for Claude Code and Cursor integration. View, filter, and manage WordPress debug logs with AI assistance.

== Description ==

DLV-MCP is a modern WordPress debug log viewer with an integrated MCP (Model Context Protocol) Server that enables AI-assisted debugging with Claude Code, Cursor IDE, and other MCP-compatible tools.

**Key Features:**

* **Admin Log Viewer** - View, search, and filter debug logs directly in WordPress admin
* **Log Management** - Enable/disable logging, clear logs, download log files
* **Log Rotation** - Automatic rotation when logs exceed 1 MB
* **MCP Server** - REST API for AI-assisted debugging with Claude Code, Cursor or other MCP-compatible tools
* **Secure Access** - API key authentication for remote access
* **Real-time Monitoring** - Auto-refresh to monitor logs in real-time
* **Syntax Highlighting** - Color-coded error types (Fatal, Warning, Notice, Deprecated)

**AI Integration:**

With MCP (Model Context Protocol) support, you can ask AI assistants natural language questions like:

* "Show me the recent PHP errors"
* "Search the debug log for database errors"
* "What errors occurred in the last 30 minutes?"
* "Find all fatal errors in the log"

The AI will automatically use the DLV-MCP tools to fetch and analyze the data.

**MCP Tools Available:**

* `get_debug_log` - Get last N lines from the log
* `search_debug_log` - Search the log for a pattern
* `get_errors_since` - Get errors from the last N minutes
* `get_log_info` - Get log file information
* `tail_debug_log` - Get most recent log entries
* `clear_debug_log` - Clear the debug log

== Installation ==

1. Upload the `dlv-mcp` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to **Tools > DLV-MCP** to view your debug logs
4. Go to **Tools > DLV-MCP Settings** to configure the MCP Server

**Enable Debug Logging:**

1. Go to **Tools > DLV-MCP** in your WordPress admin
2. Click **"Enable logging"** to create a new log file
3. The plugin will automatically configure PHP error logging

**MCP Server Setup:**

1. Go to **Tools > DLV-MCP Settings**
2. Ensure the MCP Server status shows **"Enabled"**
3. Click **"Generate New API Key"** and give it a name
4. Copy the API key immediately - it will only be shown once!
5. Use the Quick Integration panel to configure Claude Code or Cursor IDE

== Frequently Asked Questions ==

= Where are log files stored? =

Log files are stored in `wp-content/uploads/dlv-mcp-logs/` with automatic protection against direct web access via .htaccess.

= How do I connect Claude Code? =

After generating an API key, use the Quick Integration panel to copy the pre-configured command:

`claude mcp add --transport http 'your-site-debug-log' 'https://your-site.com/wp-json/dlv-mcp/v1/mcp' --header "Authorization: Bearer YOUR_API_KEY"`

= How do I connect Cursor IDE? =

After generating an API key, either:
* Click "Add to Cursor IDE" for one-click installation
* Or copy the JSON configuration to `.cursor/mcp.json` in your project

= Can I use multiple API keys? =

Yes! You can generate multiple API keys for different team members or applications. Each key can be revoked independently.

= Is the MCP Server compatible with other AI tools? =

The MCP Server follows the Model Context Protocol specification (version 2025-11-25) and should work with any MCP-compatible client.

= Do I need to modify wp-config.php? =

No. DLV-MCP manages its own log file. However, if you want WordPress to also use debug mode, add this to your `wp-config.php`:

`define( 'WP_DEBUG', true );`
`define( 'WP_DEBUG_LOG', true );`
`define( 'WP_DEBUG_DISPLAY', false );`

== Screenshots ==

1. Debug Log Viewer - Main interface showing log entries with syntax highlighting
2. MCP Settings - API key management and Quick Integration panel
3. Quick Integration - Pre-configured commands for Claude Code and Cursor IDE

== Changelog ==

= 0.0.7 =
* Fixed settings persistence for toggle options
* Improved Hide Deprecated toggle functionality
* Updated to MCP Protocol version 2025-11-25

= 0.0.6 =
* Added Quick Integration panel for easy setup
* Added one-click Cursor IDE installation
* Improved API key generation workflow

= 0.0.5 =
* Added syntax highlighting for log entries
* Added Hide Deprecated toggle
* Improved search functionality

= 0.0.4 =
* Added auto-refresh functionality
* Added log rotation support
* Security improvements

= 0.0.3 =
* Added MCP Server for Claude Code integration
* Added API key authentication
* Added real-time log viewing

= 0.0.2 =
* Added search and filter functionality
* Improved admin interface

= 0.0.1 =
* Initial release
* Basic debug log viewer

== Upgrade Notice ==

= 0.0.7 =
This version includes important fixes for settings persistence. Upgrade recommended.

== Privacy Policy ==

DLV-MCP does not collect, store, or transmit any personal data to external servers. All log data remains on your WordPress installation. API keys are stored locally in your WordPress database and are only used to authenticate requests to your own site's MCP endpoint.
