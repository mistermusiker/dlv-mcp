<?php
/**
 * DLV-MCP - Debug Log Viewer and MCP Server for Claude Code and Cursor integration.
 *
 * @package           DLV_MCP
 * @author            Roger Kirchhoff
 * @copyright         2025 Roger Kirchhoff
 * @license           GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name:       DLV-MCP
 * Plugin URI:        https://github.com/mistermusiker/dlv-mcp
 * Description:       Debug Log Viewer with MCP Server for Claude Code and Cursor integration. View, filter, and manage WordPress debug logs with a modern admin interface. Includes REST API for AI-assisted debugging.
 * Version:           0.0.7
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Roger Kirchhoff
 * Author URI:        https://grp.solutions
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       dlv-mcp
 * Domain Path:       /languages
 * Update URI:        https://github.com/mistermusiker/dlv-mcp
 */

namespace DLV_MCP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const OPTION_KEY = 'dlv_mcp_settings';
const API_KEYS_OPTION = 'dlv_mcp_api_keys';
const MAX_LOG_SIZE = 1048576; // 1 MB
const MAX_ROTATED_FILES = 3;
const MCP_PROTOCOL_VERSION = '2025-11-25';

/**
 * Get plugin settings with defaults.
 *
 * @return array
 */
function get_settings(): array {
	$defaults = array(
		'enabled'               => false,
		'log_file'              => '',
		'wrap_lines'            => true,
		'auto_refresh'          => false,
		'auto_refresh_interval' => 5, // seconds
		'mcp_enabled'           => true,
		'hide_deprecated'       => false,
		'highlight'             => false,
		'max_log_size'          => 1048576, // 1 MB in bytes
	);

	$settings = get_option( OPTION_KEY, array() );

	if ( ! is_array( $settings ) ) {
		$settings = array();
	}

	return array_merge( $defaults, $settings );
}

/**
 * Update plugin settings.
 *
 * @param array $settings
 */
function update_settings( array $settings ): void {
	$current = get_settings();
	$new     = array_merge( $current, $settings );

	update_option( OPTION_KEY, $new );
}

/**
 * Get all API keys.
 *
 * @return array
 */
function get_api_keys(): array {
	$keys = get_option( API_KEYS_OPTION, array() );
	return is_array( $keys ) ? $keys : array();
}

/**
 * Save API keys.
 *
 * @param array $keys
 */
function save_api_keys( array $keys ): void {
	update_option( API_KEYS_OPTION, $keys );
}

/**
 * Generate a new API key.
 *
 * @param string $name
 * @return array Key data with 'key', 'name', 'created', 'last_used'
 */
function generate_api_key( string $name ): array {
	$key = 'dlv_mcp_' . bin2hex( random_bytes( 24 ) );
	
	$key_data = array(
		'key'       => $key,
		'key_hash'  => wp_hash( $key ),
		'name'      => sanitize_text_field( $name ),
		'created'   => time(),
		'last_used' => null,
	);
	
	$keys = get_api_keys();
	$keys[ $key_data['key_hash'] ] = $key_data;
	save_api_keys( $keys );
	
	return $key_data;
}

/**
 * Validate an API key.
 *
 * @param string $key
 * @return bool
 */
function validate_api_key( string $key ): bool {
	if ( empty( $key ) ) {
		return false;
	}
	
	$key_hash = wp_hash( $key );
	$keys = get_api_keys();
	
	if ( isset( $keys[ $key_hash ] ) ) {
		// Update last used timestamp
		$keys[ $key_hash ]['last_used'] = time();
		save_api_keys( $keys );
		return true;
	}
	
	return false;
}

/**
 * Delete an API key by hash.
 *
 * @param string $key_hash
 * @return bool
 */
function delete_api_key( string $key_hash ): bool {
	$keys = get_api_keys();
	
	if ( isset( $keys[ $key_hash ] ) ) {
		unset( $keys[ $key_hash ] );
		save_api_keys( $keys );
		return true;
	}
	
	return false;
}

/**
 * Generate a new log file path in uploads.
 *
 * @return string|false Absolute path to the log file or false on failure.
 */
function generate_log_file_path() {
	$uploads = wp_get_upload_dir();

	if ( empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) ) {
		return false;
	}

	$log_dir = trailingslashit( $uploads['basedir'] ) . 'dlv-mcp-logs';

	if ( ! wp_mkdir_p( $log_dir ) && ! is_dir( $log_dir ) ) {
		return false;
	}

	// Create .htaccess to protect directory (Apache)
	$htaccess = $log_dir . '/.htaccess';
	if ( ! file_exists( $htaccess ) ) {
		file_put_contents( $htaccess, "# Deny access to all files in this directory\nOrder deny,allow\nDeny from all\n\n# Also works with Apache 2.4+\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>" );
	}

	// Create index.php to prevent listing and direct access
	$index = $log_dir . '/index.php';
	if ( ! file_exists( $index ) ) {
		file_put_contents( $index, '<?php // Silence is golden.' );
	}

	// Create index.html as additional protection (Nginx fallback)
	$index_html = $log_dir . '/index.html';
	if ( ! file_exists( $index_html ) ) {
		file_put_contents( $index_html, '<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/" /></head><body></body></html>' );
	}

	// Build filename: sanitized host + timestamp + random suffix.
	$host     = parse_url( home_url(), PHP_URL_HOST );
	$host     = $host ? $host : 'site';
	$host     = preg_replace( '/\W+/', '', strtolower( $host ) );
	$host     = $host ? $host : 'site';
	$stamp    = gmdate( 'YmdHis' ) . sprintf( '%05d', mt_rand( 0, 99999 ) );
	$filename = sprintf( '%s_%s_debug.log', $host, $stamp );

	return trailingslashit( $log_dir ) . $filename;
}

/**
 * Rotate logs if they exceed max size.
 *
 * @param string $log_file
 */
function maybe_rotate_log( string $log_file ): void {
	if ( ! file_exists( $log_file ) ) {
		return;
	}

	$settings     = get_settings();
	$max_log_size = ! empty( $settings['max_log_size'] ) ? (int) $settings['max_log_size'] : MAX_LOG_SIZE;

	$size = filesize( $log_file );
	if ( $size === false || $size < $max_log_size ) {
		return;
	}

	// Rotate existing backups
	for ( $i = MAX_ROTATED_FILES - 1; $i >= 1; $i-- ) {
		$current = $log_file . '.' . $i;
		$next    = $log_file . '.' . ( $i + 1 );
		if ( file_exists( $current ) ) {
			rename( $current, $next );
		}
	}

	// Rotate current file
	rename( $log_file, $log_file . '.1' );
	
	// Create new empty file
	touch( $log_file );
	clearstatcache( true, $log_file );
}

/**
 * Apply PHP error_log settings when enabled.
 */
function maybe_apply_logging(): void {
	$settings = get_settings();

	if ( empty( $settings['enabled'] ) || empty( $settings['log_file'] ) ) {
		return;
	}

	$log_file = $settings['log_file'];

	// Ensure directory exists.
	$dir = dirname( $log_file );
	if ( ! is_dir( $dir ) ) {
		if ( ! wp_mkdir_p( $dir ) ) {
			return;
		}
	}

	// Ensure file exists.
	if ( ! file_exists( $log_file ) ) {
		touch( $log_file );
		clearstatcache( true, $log_file );
	}

	// Check rotation
	maybe_rotate_log( $log_file );

	// Redirect PHP error log.
	ini_set( 'log_errors', '1' );
	ini_set( 'error_log', $log_file );
}
add_action( 'plugins_loaded', __NAMESPACE__ . '\\maybe_apply_logging', 1 );

/**
 * Enable logging: create a new log file and apply settings.
 *
 * @return string|false Log file path or false on failure.
 */
function enable_logging() {
	$log_file = generate_log_file_path();

	if ( ! $log_file ) {
		return false;
	}

	if ( ! file_exists( $log_file ) ) {
		if ( ! touch( $log_file ) ) {
			return false;
		}
		clearstatcache( true, $log_file );
	}

	update_settings(
		array(
			'enabled'  => true,
			'log_file' => $log_file,
		)
	);

	maybe_apply_logging();

	return $log_file;
}

/**
 * Disable logging.
 */
function disable_logging(): void {
	update_settings(
		array(
			'enabled' => false,
		)
	);

	// We do not reset global PHP error_log here; we just stop forcing our own file.
}

/**
 * Filter log content to remove deprecated warnings if setting is enabled.
 *
 * @param string $content
 * @return string
 */
function filter_log_content( string $content ): string {
	$settings = get_settings();
	
	if ( ! isset( $settings['hide_deprecated'] ) || ! $settings['hide_deprecated'] ) {
		return $content;
	}
	
	$lines = explode( "\n", $content );
	$filtered = array();
	
	foreach ( $lines as $line ) {
		// Skip lines containing "Deprecated" (case-insensitive)
		if ( stripos( $line, 'Deprecated' ) === false ) {
			$filtered[] = $line;
		}
	}
	
	return implode( "\n", $filtered );
}

/**
 * Read the last portion of a file (simple tail).
 *
 * @param string $file
 * @param int|null $max_bytes
 *
 * @return string
 */
function tail_file( string $file, ?int $max_bytes = null ): string {
	if ( null === $max_bytes ) {
		$settings  = get_settings();
		$max_bytes = ! empty( $settings['max_log_size'] ) ? (int) $settings['max_log_size'] : MAX_LOG_SIZE;
	}

	if ( ! is_readable( $file ) ) {
		return '';
	}

	$size = filesize( $file );

	if ( false === $size || $size <= $max_bytes ) {
		$content = file_get_contents( $file );
		$content = is_string( $content ) ? $content : '';
		// Don't filter here - JavaScript handles filtering for display
		return $content;
	}

	$fp = fopen( $file, 'rb' );
	if ( ! $fp ) {
		return '';
	}

	fseek( $fp, -1 * $max_bytes, SEEK_END );
	$data = fread( $fp, $max_bytes );
	fclose( $fp );

	if ( ! is_string( $data ) ) {
		return '';
	}

	// Ensure we start at a line boundary.
	$pos = strpos( $data, "\n" );
	if ( false !== $pos ) {
		$data = substr( $data, $pos + 1 );
	}

	// Don't filter here - JavaScript handles filtering for display
	return $data;
}

/**
 * Get the last N lines from a file.
 *
 * @param string $file
 * @param int $lines
 * @return string
 */
function tail_lines( string $file, int $lines = 100 ): string {
	if ( ! is_readable( $file ) ) {
		return '';
	}
	
	$content = file_get_contents( $file );
	if ( ! is_string( $content ) ) {
		return '';
	}

	// Don't filter here - return raw content for MCP tools
	$all_lines = explode( "\n", $content );
	$total = count( $all_lines );
	
	if ( $total <= $lines ) {
		return $content;
	}
	
	return implode( "\n", array_slice( $all_lines, -$lines ) );
}

/**
 * Search log file for pattern.
 *
 * @param string $file
 * @param string $pattern
 * @param int $max_results
 * @return array
 */
function search_log( string $file, string $pattern, int $max_results = 100 ): array {
	if ( ! is_readable( $file ) ) {
		return array();
	}
	
	$content = file_get_contents( $file );
	if ( ! is_string( $content ) ) {
		return array();
	}
	
	$lines = explode( "\n", $content );
	$results = array();
	$pattern_lower = strtolower( $pattern );
	
	foreach ( $lines as $line_num => $line ) {
		if ( stripos( $line, $pattern ) !== false ) {
			$results[] = array(
				'line_number' => $line_num + 1,
				'content'     => $line,
			);
			
			if ( count( $results ) >= $max_results ) {
				break;
			}
		}
	}
	
	return $results;
}

/**
 * Get errors from log since timestamp.
 *
 * @param string $file
 * @param int $since Unix timestamp
 * @return array
 */
function get_errors_since( string $file, int $since ): array {
	if ( ! is_readable( $file ) ) {
		return array();
	}
	
	$content = file_get_contents( $file );
	if ( ! is_string( $content ) ) {
		return array();
	}
	
	$lines = explode( "\n", $content );
	$results = array();
	
	// PHP error log format: [DD-Mon-YYYY HH:MM:SS TZ] ...
	$date_pattern = '/^\[(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2})\s+\w+\]/';
	
	foreach ( $lines as $line ) {
		if ( preg_match( $date_pattern, $line, $matches ) ) {
			$timestamp = strtotime( $matches[1] );
			if ( $timestamp && $timestamp >= $since ) {
				// Check if it's an error type
				if ( preg_match( '/(Fatal error|Parse error|Warning|Notice|Deprecated|Error)/i', $line ) ) {
					$results[] = array(
						'timestamp' => $timestamp,
						'datetime'  => $matches[1],
						'content'   => $line,
					);
				}
			}
		}
	}
	
	return $results;
}

/**
 * Get log file info.
 *
 * @param string $file
 * @return array
 */
function get_log_info( string $file ): array {
	if ( ! file_exists( $file ) ) {
		return array(
			'exists'     => false,
			'size'       => 0,
			'size_human' => '0 B',
			'lines'      => 0,
			'modified'   => null,
		);
	}

	clearstatcache( true, $file );
	$size = filesize( $file );

	// Count lines
	$lines = 0;
	if ( is_readable( $file ) && $size > 0 ) {
		$fp = fopen( $file, 'r' );
		if ( $fp ) {
			while ( ! feof( $fp ) ) {
				$buffer = fread( $fp, 8192 );
				if ( $buffer ) {
					$lines += substr_count( $buffer, "\n" );
				}
			}
			fclose( $fp );
		}
	}

	return array(
		'exists'     => true,
		'size'       => $size,
		'size_human' => size_format( $size, 2 ),
		'lines'      => $lines,
		'modified'   => filemtime( $file ),
	);
}

/**
 * Clear the log file.
 *
 * @param string $file
 * @return bool
 */
function clear_log_file( string $file ): bool {
	if ( ! file_exists( $file ) || ! is_writable( $file ) ) {
		return false;
	}

	return file_put_contents( $file, '' ) !== false;
}

/**
 * Get all log files in the logs directory.
 *
 * @return array
 */
function get_all_log_files(): array {
	$uploads = wp_get_upload_dir();
	$log_dir = trailingslashit( $uploads['basedir'] ) . 'dlv-mcp-logs';

	if ( ! is_dir( $log_dir ) ) {
		return array();
	}

	$settings    = get_settings();
	$current_log = ! empty( $settings['log_file'] ) ? $settings['log_file'] : '';
	$files       = glob( $log_dir . '/*.log*' );
	$result      = array();

	if ( ! $files ) {
		return array();
	}

	foreach ( $files as $file ) {
		$result[] = array(
			'name'     => basename( $file ),
			'path'     => $file,
			'size'     => filesize( $file ),
			'modified' => filemtime( $file ),
			'current'  => $file === $current_log,
		);
	}

	// Sort by modified time, newest first
	usort(
		$result,
		function ( $a, $b ) {
			return $b['modified'] - $a['modified'];
		}
	);

	return $result;
}

/**
 * Sanitize log filename - allows .log.1, .log.2 etc but prevents path traversal.
 *
 * @param string $filename
 * @return string
 */
function sanitize_log_filename( string $filename ): string {
	// Remove any path components - only keep the basename
	$filename = basename( $filename );
	// Remove null bytes and other dangerous characters
	$filename = preg_replace( '/[\x00-\x1f]/', '', $filename );
	// Only allow alphanumeric, dots, underscores, hyphens
	$filename = preg_replace( '/[^a-zA-Z0-9._-]/', '', $filename );
	return $filename;
}

/**
 * Get secure URL for viewing a log file.
 *
 * @param string $filename
 * @return string
 */
function get_view_log_url( string $filename ): string {
	$safe_filename = sanitize_log_filename( $filename );
	return add_query_arg(
		array(
			'action'   => 'dlv_mcp_view_log',
			'file'     => $safe_filename,
			'_wpnonce' => wp_create_nonce( 'dlv_mcp_view_log_' . $safe_filename ),
		),
		admin_url( 'admin-ajax.php' )
	);
}

// ============================================================================
// MCP SERVER IMPLEMENTATION
// ============================================================================

/**
 * Register MCP REST API routes.
 */
function register_mcp_routes(): void {
	register_rest_route(
		'dlv-mcp/v1',
		'/mcp',
		array(
			'methods'             => array( 'POST', 'OPTIONS' ),
			'callback'            => __NAMESPACE__ . '\\handle_mcp_request',
			'permission_callback' => __NAMESPACE__ . '\\mcp_permission_check',
		)
	);
	
	// Add CORS headers for MCP requests
	add_filter( 'rest_pre_serve_request', __NAMESPACE__ . '\\add_mcp_cors_headers', 0, 4 );
	
	// SSE endpoint for streaming (optional)
	register_rest_route(
		'dlv-mcp/v1',
		'/sse',
		array(
			'methods'             => 'GET',
			'callback'            => __NAMESPACE__ . '\\handle_mcp_sse',
			'permission_callback' => __NAMESPACE__ . '\\mcp_permission_check',
		)
	);
}
add_action( 'rest_api_init', __NAMESPACE__ . '\\register_mcp_routes' );

/**
 * Add CORS headers for MCP requests.
 *
 * @param bool $served Whether the request has already been served.
 * @param \WP_REST_Response $result Result to send to the client.
 * @param \WP_REST_Request $request Request used to generate the response.
 * @param \WP_REST_Server $server Server instance.
 * @return bool
 */
function add_mcp_cors_headers( bool $served, \WP_REST_Response $result, \WP_REST_Request $request, \WP_REST_Server $server ): bool {
	// Only add CORS headers for MCP endpoints
	if ( strpos( $request->get_route(), '/dlv-mcp/v1/' ) === false ) {
		return $served;
	}
	
	// Handle OPTIONS preflight request
	if ( $request->get_method() === 'OPTIONS' ) {
		header( 'Access-Control-Allow-Origin: *' );
		header( 'Access-Control-Allow-Methods: POST, OPTIONS' );
		header( 'Access-Control-Allow-Headers: Content-Type, Authorization' );
		header( 'Access-Control-Max-Age: 86400' );
		return true;
	}
	
	// Add CORS headers to response
	header( 'Access-Control-Allow-Origin: *' );
	header( 'Access-Control-Allow-Methods: POST, OPTIONS' );
	header( 'Access-Control-Allow-Headers: Content-Type, Authorization' );
	
	return $served;
}

/**
 * Check MCP API permission.
 *
 * @param \WP_REST_Request $request
 * @return bool|\WP_Error
 */
function mcp_permission_check( \WP_REST_Request $request ) {
	$settings = get_settings();
	
	if ( empty( $settings['mcp_enabled'] ) ) {
		return new \WP_Error(
			'mcp_disabled',
			__( 'MCP Server is disabled.', 'dlv-mcp' ),
			array( 'status' => 403 )
		);
	}
	
	// Check for API key in Authorization header
	$auth_header = $request->get_header( 'Authorization' );
	
	if ( empty( $auth_header ) ) {
		return new \WP_Error(
			'missing_api_key',
			__( 'API key required. Use Authorization: Bearer YOUR_API_KEY', 'dlv-mcp' ),
			array( 'status' => 401 )
		);
	}
	
	// Extract Bearer token
	if ( preg_match( '/^Bearer\s+(.+)$/i', $auth_header, $matches ) ) {
		$api_key = $matches[1];
	} else {
		$api_key = $auth_header;
	}
	
	if ( ! validate_api_key( $api_key ) ) {
		return new \WP_Error(
			'invalid_api_key',
			__( 'Invalid API key.', 'dlv-mcp' ),
			array( 'status' => 401 )
		);
	}
	
	return true;
}

/**
 * Handle MCP JSON-RPC request.
 *
 * @param \WP_REST_Request $request
 * @return \WP_REST_Response
 */
function handle_mcp_request( \WP_REST_Request $request ): \WP_REST_Response {
	// Handle OPTIONS preflight request
	if ( $request->get_method() === 'OPTIONS' ) {
		$response = new \WP_REST_Response( null, 204 );
		$response->header( 'Access-Control-Allow-Origin', '*' );
		$response->header( 'Access-Control-Allow-Methods', 'POST, OPTIONS' );
		$response->header( 'Access-Control-Allow-Headers', 'Content-Type, Authorization' );
		return $response;
	}
	
	$body = $request->get_json_params();
	
	if ( empty( $body ) ) {
		return mcp_error_response( -32700, 'Parse error', null );
	}
	
	$jsonrpc = $body['jsonrpc'] ?? '';
	$method  = $body['method'] ?? '';
	$params  = $body['params'] ?? array();
	$id      = $body['id'] ?? null;
	
	// Debug logging (only if WP_DEBUG is enabled)
	if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
		error_log( sprintf( '[DLV MCP] Request: method=%s, id=%s', $method, $id ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
	}
	
	if ( $jsonrpc !== '2.0' ) {
		return mcp_error_response( -32600, 'Invalid Request: jsonrpc must be "2.0"', $id );
	}
	
	if ( empty( $method ) ) {
		return mcp_error_response( -32600, 'Invalid Request: method required', $id );
	}
	
	// Route to appropriate handler
	switch ( $method ) {
		case 'initialize':
			return mcp_handle_initialize( $params, $id );
		
		case 'initialized':
			return mcp_success_response( array(), $id );
		
		case 'tools/list':
			return mcp_handle_tools_list( $params, $id );
		
		case 'tools/call':
			return mcp_handle_tools_call( $params, $id );
		
		case 'ping':
			return mcp_success_response( array(), $id );
		
		default:
			return mcp_error_response( -32601, 'Method not found: ' . $method, $id );
	}
}

/**
 * Handle MCP initialize request.
 *
 * @param array $params
 * @param mixed $id
 * @return \WP_REST_Response
 */
function mcp_handle_initialize( array $params, $id ): \WP_REST_Response {
	$result = array(
		'protocolVersion' => MCP_PROTOCOL_VERSION,
		'capabilities'    => array(
			'tools' => array(
				'listChanged' => false,
			),
		),
		'serverInfo'      => array(
			'name'    => 'DLV MCP Debug Log Server',
			'version' => '3.0.0',
		),
	);
	
	return mcp_success_response( $result, $id );
}

/**
 * Handle MCP tools/list request.
 *
 * @param array $params
 * @param mixed $id
 * @return \WP_REST_Response
 */
function mcp_handle_tools_list( array $params, $id ): \WP_REST_Response {
	$tools = array(
		array(
			'name'        => 'get_debug_log',
			'description' => 'Get the last N lines of the WordPress debug log',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array(
					'lines' => array(
						'type'        => 'integer',
						'description' => 'Number of lines to retrieve (default: 100, max: 1000)',
						'default'     => 100,
					),
				),
			),
		),
		array(
			'name'        => 'search_debug_log',
			'description' => 'Search the debug log for a specific pattern or text',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array(
					'pattern' => array(
						'type'        => 'string',
						'description' => 'Search pattern (case-insensitive)',
					),
					'max_results' => array(
						'type'        => 'integer',
						'description' => 'Maximum number of results (default: 100)',
						'default'     => 100,
					),
				),
				'required'   => array( 'pattern' ),
			),
		),
		array(
			'name'        => 'get_errors_since',
			'description' => 'Get all errors from the debug log since a specific time',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array(
					'minutes_ago' => array(
						'type'        => 'integer',
						'description' => 'Get errors from the last N minutes (default: 60)',
						'default'     => 60,
					),
					'timestamp' => array(
						'type'        => 'integer',
						'description' => 'Unix timestamp to get errors since (overrides minutes_ago)',
					),
				),
			),
		),
		array(
			'name'        => 'get_log_info',
			'description' => 'Get information about the current debug log file (size, lines, last modified)',
			'inputSchema' => array(
				'type' => 'object',
			),
		),
		array(
			'name'        => 'clear_debug_log',
			'description' => 'Clear the debug log file (use with caution)',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array(
					'confirm' => array(
						'type'        => 'boolean',
						'description' => 'Must be true to confirm clearing the log',
					),
				),
				'required'   => array( 'confirm' ),
			),
		),
		array(
			'name'        => 'tail_debug_log',
			'description' => 'Get the most recent entries from the debug log (real-time view)',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array(
					'bytes' => array(
						'type'        => 'integer',
						'description' => 'Maximum bytes to retrieve (default: 10000)',
						'default'     => 10000,
					),
				),
			),
		),
	);
	
	return mcp_success_response( array( 'tools' => $tools ), $id );
}

/**
 * Handle MCP tools/call request.
 *
 * @param array $params
 * @param mixed $id
 * @return \WP_REST_Response
 */
function mcp_handle_tools_call( array $params, $id ): \WP_REST_Response {
	$tool_name = $params['name'] ?? '';
	$arguments = $params['arguments'] ?? array();
	
	$settings = get_settings();
	$log_file = $settings['log_file'] ?? '';
	
	if ( empty( $log_file ) || ! file_exists( $log_file ) ) {
		return mcp_tool_response(
			array(
				array(
					'type' => 'text',
					'text' => 'Error: No debug log file configured or file does not exist. Please enable logging in the WordPress admin.',
				),
			),
			true,
			$id
		);
	}
	
	switch ( $tool_name ) {
		case 'get_debug_log':
			$lines = min( absint( $arguments['lines'] ?? 100 ), 1000 );
			$content = tail_lines( $log_file, $lines );
			
			if ( empty( $content ) ) {
				$content = '(Log file is empty)';
			}
			
			return mcp_tool_response(
				array(
					array(
						'type' => 'text',
						'text' => $content,
					),
				),
				false,
				$id
			);
		
		case 'search_debug_log':
			$pattern = $arguments['pattern'] ?? '';
			$max_results = min( absint( $arguments['max_results'] ?? 100 ), 500 );
			
			if ( empty( $pattern ) ) {
				return mcp_tool_response(
					array(
						array(
							'type' => 'text',
							'text' => 'Error: Search pattern is required.',
						),
					),
					true,
					$id
				);
			}
			
			$results = search_log( $log_file, $pattern, $max_results );
			
			if ( empty( $results ) ) {
				$text = "No results found for pattern: {$pattern}";
			} else {
				$text = "Found " . count( $results ) . " matches for '{$pattern}':\n\n";
				foreach ( $results as $result ) {
					$text .= "Line {$result['line_number']}: {$result['content']}\n";
				}
			}
			
			return mcp_tool_response(
				array(
					array(
						'type' => 'text',
						'text' => $text,
					),
				),
				false,
				$id
			);
		
		case 'get_errors_since':
			$timestamp = $arguments['timestamp'] ?? null;
			
			if ( ! $timestamp ) {
				$minutes = absint( $arguments['minutes_ago'] ?? 60 );
				$timestamp = time() - ( $minutes * 60 );
			}
			
			$errors = get_errors_since( $log_file, $timestamp );
			
			if ( empty( $errors ) ) {
				$text = "No errors found since " . gmdate( 'Y-m-d H:i:s', $timestamp ) . " UTC";
			} else {
				$text = "Found " . count( $errors ) . " errors since " . gmdate( 'Y-m-d H:i:s', $timestamp ) . " UTC:\n\n";
				foreach ( $errors as $error ) {
					$text .= "[{$error['datetime']}] {$error['content']}\n\n";
				}
			}
			
			return mcp_tool_response(
				array(
					array(
						'type' => 'text',
						'text' => $text,
					),
				),
				false,
				$id
			);
		
		case 'get_log_info':
			$info = get_log_info( $log_file );
			
			$text = "Debug Log Information:\n";
			$text .= "- File: " . basename( $log_file ) . "\n";
			$text .= "- Size: {$info['size_human']} ({$info['size']} bytes)\n";
			$text .= "- Lines: {$info['lines']}\n";
			$text .= "- Last Modified: " . ( $info['modified'] ? gmdate( 'Y-m-d H:i:s', $info['modified'] ) . ' UTC' : 'N/A' );
			
			return mcp_tool_response(
				array(
					array(
						'type' => 'text',
						'text' => $text,
					),
				),
				false,
				$id
			);
		
		case 'clear_debug_log':
			$confirm = $arguments['confirm'] ?? false;
			
			if ( ! $confirm ) {
				return mcp_tool_response(
					array(
						array(
							'type' => 'text',
							'text' => 'Error: You must set confirm=true to clear the debug log.',
						),
					),
					true,
					$id
				);
			}
			
			$success = clear_log_file( $log_file );
			
			return mcp_tool_response(
				array(
					array(
						'type' => 'text',
						'text' => $success ? 'Debug log cleared successfully.' : 'Failed to clear debug log.',
					),
				),
				! $success,
				$id
			);
		
		case 'tail_debug_log':
			$bytes = min( absint( $arguments['bytes'] ?? 10000 ), 100000 );
			$content = tail_file( $log_file, $bytes );
			
			if ( empty( $content ) ) {
				$content = '(Log file is empty)';
			}
			
			return mcp_tool_response(
				array(
					array(
						'type' => 'text',
						'text' => $content,
					),
				),
				false,
				$id
			);
		
		default:
			return mcp_error_response( -32601, 'Unknown tool: ' . $tool_name, $id );
	}
}

/**
 * Handle MCP SSE (Server-Sent Events) endpoint.
 *
 * @param \WP_REST_Request $request
 * @return \WP_REST_Response
 */
function handle_mcp_sse( \WP_REST_Request $request ): \WP_REST_Response {
	// SSE is more complex to implement in WordPress context
	// For now, return info about how to use HTTP transport
	return new \WP_REST_Response(
		array(
			'message' => 'SSE endpoint available. For full SSE support, use HTTP transport instead.',
			'http_endpoint' => rest_url( 'dlv-mcp/v1/mcp' ),
		),
		200
	);
}

/**
 * Create MCP success response.
 *
 * @param mixed $result
 * @param mixed $id
 * @return \WP_REST_Response
 */
function mcp_success_response( $result, $id ): \WP_REST_Response {
	$response = new \WP_REST_Response(
		array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'result'  => $result,
		),
		200
	);
	
	// Ensure Content-Type is set correctly
	$response->header( 'Content-Type', 'application/json' );
	
	return $response;
}

/**
 * Create MCP error response.
 *
 * @param int $code
 * @param string $message
 * @param mixed $id
 * @return \WP_REST_Response
 */
function mcp_error_response( int $code, string $message, $id ): \WP_REST_Response {
	$response = new \WP_REST_Response(
		array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'error'   => array(
				'code'    => $code,
				'message' => $message,
			),
		),
		200
	);
	
	// Ensure Content-Type is set correctly
	$response->header( 'Content-Type', 'application/json' );
	
	return $response;
}

/**
 * Create MCP tool response.
 *
 * @param array $content
 * @param bool $is_error
 * @param mixed $id
 * @return \WP_REST_Response
 */
function mcp_tool_response( array $content, bool $is_error, $id ): \WP_REST_Response {
	$response = new \WP_REST_Response(
		array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'result'  => array(
				'content' => $content,
				'isError' => $is_error,
			),
		),
		200
	);
	
	// Ensure Content-Type is set correctly
	$response->header( 'Content-Type', 'application/json' );
	
	return $response;
}

// ============================================================================
// ADMIN INTERFACE
// ============================================================================

/**
 * Handle AJAX refresh log.
 */
function ajax_refresh_log(): void {
	check_ajax_referer( 'dlv_mcp_nonce', 'nonce' );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => __( 'Permission denied.', 'dlv-mcp' ) ) );
	}

	$settings = get_settings();
	$log_file = $settings['log_file'] ?? '';

	if ( empty( $log_file ) || ! file_exists( $log_file ) || ! is_readable( $log_file ) ) {
		wp_send_json_error( array( 'message' => __( 'Log file not available.', 'dlv-mcp' ) ) );
	}

	$content = tail_file( $log_file );
	$info    = get_log_info( $log_file );

	wp_send_json_success(
		array(
			'content' => $content,
			'info'    => $info,
		)
	);
}
add_action( 'wp_ajax_dlv_mcp_refresh_log', __NAMESPACE__ . '\\ajax_refresh_log' );

/**
 * AJAX handler to save settings without page reload.
 */
function ajax_save_settings(): void {
	check_ajax_referer( 'dlv_mcp_nonce', 'nonce' );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => __( 'Permission denied.', 'dlv-mcp' ) ) );
	}

	$settings_to_update = array();

	// Only update settings that are explicitly passed
	// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Values are sanitized below
	if ( isset( $_POST['wrap_lines'] ) ) {
		$settings_to_update['wrap_lines'] = filter_var( wp_unslash( $_POST['wrap_lines'] ), FILTER_VALIDATE_BOOLEAN );
	}
	if ( isset( $_POST['auto_refresh'] ) ) {
		$settings_to_update['auto_refresh'] = filter_var( wp_unslash( $_POST['auto_refresh'] ), FILTER_VALIDATE_BOOLEAN );
	}
	if ( isset( $_POST['auto_refresh_interval'] ) ) {
		$settings_to_update['auto_refresh_interval'] = absint( wp_unslash( $_POST['auto_refresh_interval'] ) );
	}
	if ( isset( $_POST['hide_deprecated'] ) ) {
		$settings_to_update['hide_deprecated'] = filter_var( wp_unslash( $_POST['hide_deprecated'] ), FILTER_VALIDATE_BOOLEAN );
	}
	if ( isset( $_POST['highlight'] ) ) {
		$settings_to_update['highlight'] = filter_var( wp_unslash( $_POST['highlight'] ), FILTER_VALIDATE_BOOLEAN );
	}
	// phpcs:enable

	if ( ! empty( $settings_to_update ) ) {
		update_settings( $settings_to_update );
		wp_send_json_success( array( 'message' => __( 'Settings saved.', 'dlv-mcp' ) ) );
	} else {
		wp_send_json_error( array( 'message' => __( 'No settings to save.', 'dlv-mcp' ) ) );
	}
}
add_action( 'wp_ajax_dlv_mcp_save_settings', __NAMESPACE__ . '\\ajax_save_settings' );

/**
 * Handle admin post actions.
 */
function handle_admin_action(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Permission denied.', 'dlv-mcp' ) );
	}

	check_admin_referer( 'dlv_mcp_tools_action', 'dlv_mcp_nonce' );

	$action   = isset( $_POST['dlv_mcp_action'] ) ? sanitize_text_field( wp_unslash( $_POST['dlv_mcp_action'] ) ) : '';
	$redirect = admin_url( 'tools.php?page=dlv-mcp' );

	switch ( $action ) {
		case 'enable':
			$result = enable_logging();
			if ( $result ) {
				$redirect = add_query_arg( 'dlv_mcp_message', 'enabled', $redirect );
			} else {
				$redirect = add_query_arg( 'dlv_mcp_error', 'enable_failed', $redirect );
			}
			break;

		case 'disable':
			disable_logging();
			$redirect = add_query_arg( 'dlv_mcp_message', 'disabled', $redirect );
			break;

		case 'clear':
			$settings = get_settings();
			$log_file = $settings['log_file'] ?? '';

			if ( ! empty( $log_file ) && file_exists( $log_file ) && is_writable( $log_file ) ) {
				if ( clear_log_file( $log_file ) ) {
					$redirect = add_query_arg( 'dlv_mcp_message', 'cleared', $redirect );
				} else {
					$redirect = add_query_arg( 'dlv_mcp_error', 'clear_failed', $redirect );
				}
			} else {
				$redirect = add_query_arg( 'dlv_mcp_error', 'clear_not_writable', $redirect );
			}
			break;

		case 'download':
			$settings = get_settings();
			$log_file = $settings['log_file'] ?? '';

			if ( ! empty( $log_file ) && file_exists( $log_file ) && is_readable( $log_file ) ) {
				$filename = basename( $log_file );
				header( 'Content-Type: text/plain' );
				header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
				header( 'Content-Length: ' . filesize( $log_file ) );
				readfile( $log_file );
				exit;
			}
			break;

		case 'delete_log':
			$log_name = isset( $_POST['dlv_mcp_log_name'] ) ? sanitize_log_filename( wp_unslash( $_POST['dlv_mcp_log_name'] ) ) : '';

			if ( empty( $log_name ) ) {
				$redirect = add_query_arg( 'dlv_mcp_error', 'delete_invalid', $redirect );
				break;
			}

			$uploads  = wp_get_upload_dir();
			$log_dir  = trailingslashit( $uploads['basedir'] ) . 'dlv-mcp-logs';
			$log_path = $log_dir . '/' . $log_name;

			// Prevent deletion of current log file
			$settings    = get_settings();
			$current_log = ! empty( $settings['log_file'] ) ? $settings['log_file'] : '';

			if ( $log_path === $current_log ) {
				$redirect = add_query_arg( 'dlv_mcp_error', 'delete_current', $redirect );
				break;
			}

			if ( file_exists( $log_path ) && is_writable( $log_path ) ) {
				if ( wp_delete_file( $log_path ) || ! file_exists( $log_path ) ) {
					$redirect = add_query_arg( 'dlv_mcp_message', 'deleted', $redirect );
				} else {
					$redirect = add_query_arg( 'dlv_mcp_error', 'delete_failed', $redirect );
				}
			} else {
				$redirect = add_query_arg( 'dlv_mcp_error', 'delete_not_found', $redirect );
			}
			break;

		case 'save_max_size':
			$max_size = isset( $_POST['dlv_mcp_max_log_size'] ) ? absint( wp_unslash( $_POST['dlv_mcp_max_log_size'] ) ) : 1048576;

			// Validate: minimum 512 KB, maximum 50 MB
			$max_size = max( 524288, min( 52428800, $max_size ) );

			update_settings( array( 'max_log_size' => $max_size ) );
			$redirect = add_query_arg( 'dlv_mcp_message', 'max_size_saved', $redirect );
			break;

		case 'save_settings':
			// Save wrap_lines, auto_refresh, hide_deprecated, and highlight settings
			// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Values are sanitized with filter_var/absint
			$wrap_lines            = isset( $_POST['dlv_mcp_wrap_lines'] ) && filter_var( wp_unslash( $_POST['dlv_mcp_wrap_lines'] ), FILTER_VALIDATE_BOOLEAN );
			$auto_refresh          = isset( $_POST['dlv_mcp_auto_refresh'] ) && filter_var( wp_unslash( $_POST['dlv_mcp_auto_refresh'] ), FILTER_VALIDATE_BOOLEAN );
			$auto_refresh_interval = isset( $_POST['dlv_mcp_auto_refresh_interval'] ) ? absint( wp_unslash( $_POST['dlv_mcp_auto_refresh_interval'] ) ) : 5;
			$hide_deprecated       = isset( $_POST['dlv_mcp_hide_deprecated'] ) && filter_var( wp_unslash( $_POST['dlv_mcp_hide_deprecated'] ), FILTER_VALIDATE_BOOLEAN );
			$highlight             = isset( $_POST['dlv_mcp_highlight'] ) && filter_var( wp_unslash( $_POST['dlv_mcp_highlight'] ), FILTER_VALIDATE_BOOLEAN );
			// phpcs:enable
			
			// Explicitly save false values to ensure they are stored correctly
			update_settings( array(
				'wrap_lines'            => $wrap_lines,
				'auto_refresh'          => $auto_refresh,
				'auto_refresh_interval' => $auto_refresh_interval,
				'hide_deprecated'       => $hide_deprecated,
				'highlight'             => $highlight,
			) );
			
			// Redirect back to the page to show updated settings
			wp_safe_redirect( $redirect );
			exit;
	}

	wp_safe_redirect( $redirect );
	exit;
}
add_action( 'admin_post_dlv_mcp_action', __NAMESPACE__ . '\\handle_admin_action' );

/**
 * Handle MCP settings actions.
 */
function handle_mcp_settings_action(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Permission denied.', 'dlv-mcp' ) );
	}

	check_admin_referer( 'dlv_mcp_mcp_action', 'dlv_mcp_mcp_nonce' );

	$action   = isset( $_POST['dlv_mcp_mcp_action'] ) ? sanitize_text_field( wp_unslash( $_POST['dlv_mcp_mcp_action'] ) ) : '';
	$redirect = admin_url( 'tools.php?page=dlv-mcp-settings' );

	switch ( $action ) {
		case 'generate_key':
			$name = isset( $_POST['key_name'] ) ? sanitize_text_field( wp_unslash( $_POST['key_name'] ) ) : '';
			if ( empty( $name ) ) {
				$name = 'API Key ' . gmdate( 'Y-m-d H:i' );
			}
			$key_data = generate_api_key( $name );
			// Store the new key temporarily to show it once
			set_transient( 'dlv_mcp_new_key_' . get_current_user_id(), $key_data['key'], 60 );
			$redirect = add_query_arg( 'dlv_mcp_message', 'key_generated', $redirect );
			break;

		case 'delete_key':
			$key_hash = isset( $_POST['key_hash'] ) ? sanitize_text_field( wp_unslash( $_POST['key_hash'] ) ) : '';
			if ( delete_api_key( $key_hash ) ) {
				$redirect = add_query_arg( 'dlv_mcp_message', 'key_deleted', $redirect );
			} else {
				$redirect = add_query_arg( 'dlv_mcp_error', 'key_not_found', $redirect );
			}
			break;

		case 'toggle_mcp':
			$settings = get_settings();
			update_settings( array( 'mcp_enabled' => ! $settings['mcp_enabled'] ) );
			$redirect = add_query_arg( 'dlv_mcp_message', 'mcp_toggled', $redirect );
			break;
	}

	wp_safe_redirect( $redirect );
	exit;
}
add_action( 'admin_post_dlv_mcp_mcp_action', __NAMESPACE__ . '\\handle_mcp_settings_action' );

/**
 * Handle AJAX view log.
 */
function ajax_view_log(): void {
	$filename = isset( $_GET['file'] ) ? sanitize_log_filename( wp_unslash( $_GET['file'] ) ) : '';
	$nonce    = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';

	if ( ! wp_verify_nonce( $nonce, 'dlv_mcp_view_log_' . $filename ) ) {
		wp_die( esc_html__( 'Security check failed.', 'dlv-mcp' ) );
	}

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Permission denied.', 'dlv-mcp' ) );
	}

	$uploads  = wp_get_upload_dir();
	$log_dir  = trailingslashit( $uploads['basedir'] ) . 'dlv-mcp-logs';
	$log_file = trailingslashit( $log_dir ) . $filename;

	// Security: ensure file is within log directory
	$real_log_dir  = realpath( $log_dir );
	$real_log_file = realpath( $log_file );

	if ( ! $real_log_dir || ! $real_log_file || strpos( $real_log_file, $real_log_dir ) !== 0 ) {
		wp_die( esc_html__( 'Invalid file path.', 'dlv-mcp' ) );
	}

	if ( ! is_readable( $log_file ) ) {
		wp_die( esc_html__( 'Log file not readable.', 'dlv-mcp' ) );
	}

	header( 'Content-Type: text/plain; charset=utf-8' );
	readfile( $log_file );
	exit;
}
add_action( 'wp_ajax_dlv_mcp_view_log', __NAMESPACE__ . '\\ajax_view_log' );

/**
 * Enqueue admin assets.
 *
 * @param string $hook
 */
function enqueue_assets( string $hook ): void {
	if ( 'tools_page_dlv-mcp' !== $hook && 'tools_page_dlv-mcp-settings' !== $hook ) {
		return;
	}

	$settings = get_settings();

	wp_enqueue_style(
		'dlv-mcp-admin',
		plugins_url( 'assets/admin.css', __FILE__ ),
		array(),
		'3.0.0'
	);

	wp_enqueue_script(
		'dlv-mcp-admin',
		plugins_url( 'assets/admin.js', __FILE__ ),
		array(),
		'3.0.0',
		true
	);

	wp_localize_script( 'dlv-mcp-admin', 'dlvMcpSettings', array(
		'ajaxurl'             => admin_url( 'admin-ajax.php' ),
		'nonce'               => wp_create_nonce( 'dlv_mcp_nonce' ),
		'autoRefreshEnabled'  => ! empty( $settings['auto_refresh'] ),
		'autoRefreshInterval' => absint( $settings['auto_refresh_interval'] ),
		'highlightEnabled'    => ! empty( $settings['highlight'] ),
		'strings'             => array(
			'copied'        => __( 'Copied!', 'dlv-mcp' ),
			'copyFailed'    => __( 'Copy failed.', 'dlv-mcp' ),
			'refreshing'    => __( 'Refreshing...', 'dlv-mcp' ),
			'refreshError'  => __( 'Could not load log file.', 'dlv-mcp' ),
			'refreshFailed' => __( 'Refresh failed.', 'dlv-mcp' ),
			'size'          => __( 'Size:', 'dlv-mcp' ),
			'lines'         => __( 'Lines:', 'dlv-mcp' ),
		),
	) );
}
add_action( 'admin_enqueue_scripts', __NAMESPACE__ . '\\enqueue_assets' );

/**
 * Add Tools menu entries.
 */
function admin_menu(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	add_management_page(
		__( 'DLV MCP Debug Log Viewer', 'dlv-mcp' ),
		'DLV View Log',
		'manage_options',
		'dlv-mcp',
		__NAMESPACE__ . '\\render_tools_page'
	);

	add_management_page(
		__( 'DLV MCP Server Settings', 'dlv-mcp' ),
		'DLV MCP Settings',
		'manage_options',
		'dlv-mcp-settings',
		__NAMESPACE__ . '\\render_mcp_settings_page'
	);
}
add_action( 'admin_menu', __NAMESPACE__ . '\\admin_menu' );

/**
 * Generate Cursor IDE installation link.
 *
 * @param string $api_key API key to use in the configuration
 * @return string|false Cursor deeplink URL or false on failure
 */
function generate_cursor_install_link( string $api_key ) {
	if ( empty( $api_key ) ) {
		return false;
	}

		$mcp_endpoint = rest_url( 'dlv-mcp/v1/mcp' );
	$site_url     = parse_url( home_url(), PHP_URL_HOST );
	$server_name  = sanitize_title( $site_url ) . '-debug-log';

	// Ensure URL is absolute and uses proper protocol
	if ( ! preg_match( '/^https?:\/\//', $mcp_endpoint ) ) {
		$mcp_endpoint = home_url( '/wp-json/dlv-mcp/v1/mcp' );
	}

	// Create MCP configuration for deeplink
	// Since the name is passed as a URL parameter, the config should only contain
	// the server object (matching the Extension API format)
	$config = array(
		'url'     => $mcp_endpoint,
		'headers' => array(
			'Authorization' => 'Bearer ' . $api_key,
		),
	);
	
	// Verify URL is properly formatted
	if ( empty( $config['url'] ) ) {
		return false;
	}

	// Serialize and encode
	$json_config = wp_json_encode( $config, JSON_UNESCAPED_SLASHES );
	if ( false === $json_config ) {
		return false;
	}

	$base64_config = base64_encode( $json_config ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

	// Build Cursor deeplink
	$cursor_link = sprintf(
		'cursor://anysphere.cursor-deeplink/mcp/install?name=%s&config=%s',
		rawurlencode( $server_name ),
		rawurlencode( $base64_config )
	);

	return $cursor_link;
}

/**
 * Render the MCP Settings page.
 */
function render_mcp_settings_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'dlv-mcp' ) );
	}

	$settings    = get_settings();
	$mcp_enabled = ! empty( $settings['mcp_enabled'] );
	$api_keys    = get_api_keys();
	$message     = '';
	$error       = '';
	$new_key     = get_transient( 'dlv_mcp_new_key_' . get_current_user_id() );

	if ( $new_key ) {
		delete_transient( 'dlv_mcp_new_key_' . get_current_user_id() );
	}

	// Handle messages from redirects.
	if ( isset( $_GET['dlv_mcp_message'] ) ) {
		$msg_type = sanitize_text_field( wp_unslash( $_GET['dlv_mcp_message'] ) );
		switch ( $msg_type ) {
			case 'key_generated':
				$message = __( 'API key generated successfully. Copy it now - it will not be shown again!', 'dlv-mcp' );
				break;
			case 'key_deleted':
				$message = __( 'API key deleted.', 'dlv-mcp' );
				break;
			case 'mcp_toggled':
				$message = $mcp_enabled ? __( 'MCP Server enabled.', 'dlv-mcp' ) : __( 'MCP Server disabled.', 'dlv-mcp' );
				break;
		}
	}

	if ( isset( $_GET['dlv_mcp_error'] ) ) {
		$err_type = sanitize_text_field( wp_unslash( $_GET['dlv_mcp_error'] ) );
		switch ( $err_type ) {
			case 'key_not_found':
				$error = __( 'API key not found.', 'dlv-mcp' );
				break;
		}
	}

		$mcp_endpoint = rest_url( 'dlv-mcp/v1/mcp' );
	$site_url     = parse_url( home_url(), PHP_URL_HOST );
	$server_name  = sanitize_title( $site_url ) . '-debug-log';
	
	// Ensure endpoint URL is absolute
	if ( ! preg_match( '/^https?:\/\//', $mcp_endpoint ) ) {
		$mcp_endpoint = home_url( '/wp-json/dlv-mcp/v1/mcp' );
	}
	
	// Prepare Claude Code command
	$claude_command = sprintf(
		'claude mcp add --transport http %s %s --header "Authorization: Bearer %s"',
		escapeshellarg( $server_name ),
		escapeshellarg( $mcp_endpoint ),
		$new_key ? $new_key : 'YOUR_API_KEY'
	);
	
	// Prepare manual config JSON
	$manual_config = array(
		'mcpServers' => array(
			$server_name => array(
				'url'     => $mcp_endpoint,
				'headers' => array(
					'Authorization' => 'Bearer ' . ( $new_key ? $new_key : 'YOUR_API_KEY' ),
				),
			),
		),
	);
	$manual_config_json = wp_json_encode( $manual_config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );

	?>
	<div class="dlv-mcp-wrap">
		<!-- Header -->
		<div class="dlv-mcp-header">
			<h1>🔧 <?php esc_html_e( 'DLV MCP Server', 'dlv-mcp' ); ?></h1>
			<p><?php esc_html_e( 'WordPress Debug Log Viewer for AI-Assisted Development', 'dlv-mcp' ); ?></p>
		</div>

		<?php if ( $message ) : ?>
			<div class="notice notice-success is-dismissible">
				<p><?php echo esc_html( $message ); ?></p>
			</div>
		<?php endif; ?>

		<?php if ( $error ) : ?>
			<div class="notice notice-error is-dismissible">
				<p><?php echo esc_html( $error ); ?></p>
			</div>
		<?php endif; ?>

		<?php if ( $new_key ) : 
			$cursor_link = generate_cursor_install_link( $new_key );
			?>
			<div class="dlv-mcp-new-key-block">
				<h2>🔑 <?php esc_html_e( 'New API Key Generated', 'dlv-mcp' ); ?></h2>
				<p style="color: #8b6914; font-weight: 600; margin-bottom: 20px;">
					<?php esc_html_e( '⚠️ Copy this key now - it will not be shown again!', 'dlv-mcp' ); ?>
				</p>
				
				<div class="dlv-mcp-api-key-display" id="dlv-mcp-new-key">
					<?php echo esc_html( $new_key ); ?>
				</div>
				<p>
					<button type="button" class="button button-primary" onclick="(function() { const key = '<?php echo esc_js( $new_key ); ?>'; navigator.clipboard.writeText(key).then(() => { const btn = this; const orig = btn.textContent; btn.textContent = '<?php echo esc_js( __( 'Copied!', 'dlv-mcp' ) ); ?>'; setTimeout(() => { btn.textContent = orig; }, 2000); }); })();">
						<?php esc_html_e( 'Copy API Key', 'dlv-mcp' ); ?>
					</button>
				</p>
				
				<hr style="margin: 25px 0; border-color: #dba617;" />
				
				<h3 style="color: #8b6914; margin-top: 25px;"><?php esc_html_e( 'Quick Integration', 'dlv-mcp' ); ?></h3>
				
				<!-- Cursor IDE Integration -->
				<?php if ( $cursor_link ) : ?>
					<div class="dlv-mcp-integration-box">
						<h3>🎯 <?php esc_html_e( 'Cursor IDE', 'dlv-mcp' ); ?></h3>
						<p><?php esc_html_e( 'One-click installation in Cursor IDE:', 'dlv-mcp' ); ?></p>
						<p>
							<button type="button" class="button button-primary button-large" style="margin-right: 10px;" onclick="(function() { const link = '<?php echo esc_js( $cursor_link ); ?>'; window.location.href = link; })(); return false;">
								<?php esc_html_e( 'Add to Cursor IDE', 'dlv-mcp' ); ?> →
							</button>
							<button type="button" class="button button-secondary" onclick="navigator.clipboard.writeText('<?php echo esc_js( $cursor_link ); ?>').then(() => { const btn = this; const orig = btn.textContent; btn.textContent = '<?php echo esc_js( __( 'Copied!', 'dlv-mcp' ) ); ?>'; setTimeout(() => { btn.textContent = orig; }, 2000); });">
								<?php esc_html_e( 'Copy Link', 'dlv-mcp' ); ?>
							</button>
						</p>
						<p class="description" style="margin-bottom: 0;">
							<?php esc_html_e( 'Click the button to open Cursor IDE and install the MCP server automatically.', 'dlv-mcp' ); ?>
						</p>
					</div>
				<?php endif; ?>
				
				<!-- Claude Code Integration -->
				<div class="dlv-mcp-integration-box">
					<h3>🤖 <?php esc_html_e( 'Claude Code', 'dlv-mcp' ); ?></h3>
					<p><?php esc_html_e( 'Run this command in your terminal:', 'dlv-mcp' ); ?></p>
					<div class="dlv-mcp-code-block">
						<code id="dlv-mcp-claude-command-new"><?php echo esc_html( $claude_command ); ?></code>
					</div>
					<p>
						<button type="button" class="button button-primary" onclick="navigator.clipboard.writeText(document.getElementById('dlv-mcp-claude-command-new').textContent).then(() => { const btn = this; const orig = btn.textContent; btn.textContent = '<?php echo esc_js( __( 'Copied!', 'dlv-mcp' ) ); ?>'; setTimeout(() => { btn.textContent = orig; }, 2000); });">
							<?php esc_html_e( 'Copy Command', 'dlv-mcp' ); ?>
						</button>
					</p>
				</div>
				
				<!-- Manual Configuration -->
				<div class="dlv-mcp-integration-box">
					<h3>⚙️ <?php esc_html_e( 'Manual Configuration', 'dlv-mcp' ); ?></h3>
					<p><?php esc_html_e( 'Create a', 'dlv-mcp' ); ?> <code>.cursor/mcp.json</code> <?php esc_html_e( 'file in your project:', 'dlv-mcp' ); ?></p>
					<div class="dlv-mcp-code-block">
						<code id="dlv-mcp-manual-config-new"><?php echo esc_html( $manual_config_json ); ?></code>
					</div>
					<p>
						<button type="button" class="button button-primary" onclick="navigator.clipboard.writeText(document.getElementById('dlv-mcp-manual-config-new').textContent).then(() => { const btn = this; const orig = btn.textContent; btn.textContent = '<?php echo esc_js( __( 'Copied!', 'dlv-mcp' ) ); ?>'; setTimeout(() => { btn.textContent = orig; }, 2000); });">
							<?php esc_html_e( 'Copy Configuration', 'dlv-mcp' ); ?>
						</button>
					</p>
				</div>
			</div>
		<?php endif; ?>

		<!-- Status Cards -->
		<div class="dlv-mcp-stats">
			<div class="dlv-mcp-stat-card dlv-mcp-stat-card--<?php echo $mcp_enabled ? 'active' : 'inactive'; ?>">
				<div class="dlv-mcp-stat-icon"><?php echo $mcp_enabled ? '✓' : '✗'; ?></div>
				<div class="dlv-mcp-stat-content">
					<h3><?php echo $mcp_enabled ? esc_html__( 'Active', 'dlv-mcp' ) : esc_html__( 'Inactive', 'dlv-mcp' ); ?></h3>
					<p><?php echo $mcp_enabled ? esc_html__( 'MCP Server is enabled', 'dlv-mcp' ) : esc_html__( 'MCP Server is disabled', 'dlv-mcp' ); ?></p>
				</div>
			</div>
			<div class="dlv-mcp-stat-card dlv-mcp-stat-card--info">
				<div class="dlv-mcp-stat-icon">🔑</div>
				<div class="dlv-mcp-stat-content">
					<h3><?php echo count( $api_keys ); ?> <?php esc_html_e( 'API Keys', 'dlv-mcp' ); ?></h3>
					<p><?php esc_html_e( 'Active authentication keys', 'dlv-mcp' ); ?></p>
				</div>
			</div>
			<div class="dlv-mcp-stat-card dlv-mcp-stat-card--info">
				<div class="dlv-mcp-stat-icon">🛠️</div>
				<div class="dlv-mcp-stat-content">
					<h3>6 <?php esc_html_e( 'Tools', 'dlv-mcp' ); ?></h3>
					<p><?php esc_html_e( 'Available MCP tools', 'dlv-mcp' ); ?></p>
				</div>
			</div>
		</div>

		<!-- Server Status Section -->
		<div class="dlv-mcp-section">
			<div class="dlv-mcp-section-header">
				<h2>⚡ <?php esc_html_e( 'MCP Server Status', 'dlv-mcp' ); ?></h2>
			</div>
			<div class="dlv-mcp-section-body">
				<div class="dlv-mcp-toggle" style="margin-bottom: 20px;">
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<?php wp_nonce_field( 'dlv_mcp_mcp_action', 'dlv_mcp_mcp_nonce' ); ?>
						<input type="hidden" name="action" value="dlv_mcp_mcp_action" />
						<input type="hidden" name="dlv_mcp_mcp_action" value="toggle_mcp" />
						<label class="dlv-mcp-toggle">
							<input type="checkbox" <?php checked( $mcp_enabled ); ?> onchange="this.form.submit();" />
							<span class="dlv-mcp-toggle-slider"></span>
							<span class="dlv-mcp-toggle-label"><?php esc_html_e( 'Enable MCP Server', 'dlv-mcp' ); ?></span>
						</label>
					</form>
				</div>
				<p class="dlv-mcp-toggle-desc"><?php esc_html_e( 'Master switch for the MCP Server. When disabled, all API requests will be rejected.', 'dlv-mcp' ); ?></p>

				<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--dlv-border, #e2e8f0);">
					<strong style="display: block; margin-bottom: 8px;"><?php esc_html_e( 'MCP Endpoint', 'dlv-mcp' ); ?></strong>
					<code class="dlv-mcp-code-inline" id="dlv-mcp-endpoint"><?php echo esc_html( $mcp_endpoint ); ?></code>
					<button type="button" class="button button-small" style="margin-left: 10px;" onclick="navigator.clipboard.writeText(document.getElementById('dlv-mcp-endpoint').textContent).then(() => this.textContent = '<?php echo esc_js( __( 'Copied!', 'dlv-mcp' ) ); ?>');">
						<?php esc_html_e( 'Copy', 'dlv-mcp' ); ?>
					</button>
				</div>
			</div>
		</div>

		<!-- API Keys Section -->
		<div class="dlv-mcp-section">
			<div class="dlv-mcp-section-header">
				<h2>🔑 <?php esc_html_e( 'API Keys Management', 'dlv-mcp' ); ?></h2>
			</div>
			<div class="dlv-mcp-section-body">
				<p style="color: var(--dlv-text-secondary, #64748b); margin-bottom: 20px;"><?php esc_html_e( 'API keys are required to authenticate with the MCP Server. Generate a key to use with Claude Code or Cursor IDE.', 'dlv-mcp' ); ?></p>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 20px; background: var(--dlv-bg-light, #f1f5f9); border-radius: 8px;">
					<?php wp_nonce_field( 'dlv_mcp_mcp_action', 'dlv_mcp_mcp_nonce' ); ?>
					<input type="hidden" name="action" value="dlv_mcp_mcp_action" />
					<input type="hidden" name="dlv_mcp_mcp_action" value="generate_key" />

					<label for="key_name" class="dlv-mcp-form-label" style="margin-bottom: 0;"><?php esc_html_e( 'Key Name:', 'dlv-mcp' ); ?></label>
					<input type="text" name="key_name" id="key_name" class="dlv-mcp-input" placeholder="<?php esc_attr_e( 'e.g., Claude Code Local', 'dlv-mcp' ); ?>" style="width: 250px;" />
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Generate New API Key', 'dlv-mcp' ); ?></button>
				</form>

			<?php if ( ! empty( $api_keys ) ) : ?>
				<table class="dlv-mcp-table" style="margin-top: 20px;">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Name', 'dlv-mcp' ); ?></th>
							<th><?php esc_html_e( 'Created', 'dlv-mcp' ); ?></th>
							<th><?php esc_html_e( 'Last Used', 'dlv-mcp' ); ?></th>
							<th><?php esc_html_e( 'Actions', 'dlv-mcp' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $api_keys as $key_hash => $key_data ) : ?>
							<tr>
								<td><strong><?php echo esc_html( $key_data['name'] ); ?></strong></td>
								<td><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $key_data['created'] ) ); ?></td>
								<td>
									<?php
									if ( $key_data['last_used'] ) {
										echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $key_data['last_used'] ) );
									} else {
										echo '<span class="dlv-mcp-badge dlv-mcp-badge--neutral">' . esc_html__( 'Never', 'dlv-mcp' ) . '</span>';
									}
									?>
								</td>
								<td>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display: inline;">
										<?php wp_nonce_field( 'dlv_mcp_mcp_action', 'dlv_mcp_mcp_nonce' ); ?>
										<input type="hidden" name="action" value="dlv_mcp_mcp_action" />
										<input type="hidden" name="dlv_mcp_mcp_action" value="delete_key" />
										<input type="hidden" name="key_hash" value="<?php echo esc_attr( $key_hash ); ?>" />
										<button type="submit" class="dlv-mcp-btn dlv-mcp-btn--danger dlv-mcp-btn--small" onclick="return confirm('<?php echo esc_js( __( 'Are you sure you want to delete this API key?', 'dlv-mcp' ) ); ?>');">
											<?php esc_html_e( 'Delete', 'dlv-mcp' ); ?>
										</button>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php else : ?>
				<div class="dlv-mcp-info-box dlv-mcp-info-box--info" style="margin-top: 20px;">
					<span>ℹ️</span>
					<p style="margin: 0;"><em><?php esc_html_e( 'No API keys yet. Generate one to get started.', 'dlv-mcp' ); ?></em></p>
				</div>
			<?php endif; ?>
			</div>
		</div>

		<?php if ( ! $new_key ) : ?>
			<!-- Integration Guides (only shown when no new key) -->
			<div class="dlv-mcp-section">
				<div class="dlv-mcp-section-header">
					<h2>📚 <?php esc_html_e( 'Integration Guides', 'dlv-mcp' ); ?></h2>
				</div>
				<div class="dlv-mcp-section-body">
					<p style="color: var(--dlv-text-secondary, #64748b); margin-bottom: 20px;"><?php esc_html_e( 'Generate an API key above to see integration instructions with your key pre-filled.', 'dlv-mcp' ); ?></p>

					<div class="dlv-mcp-integration-box">
						<h3>🎯 <?php esc_html_e( 'Cursor IDE', 'dlv-mcp' ); ?></h3>
						<p><?php esc_html_e( 'After generating an API key, you\'ll see a one-click installation button here.', 'dlv-mcp' ); ?></p>
					</div>

					<div class="dlv-mcp-integration-box">
						<h3>🤖 <?php esc_html_e( 'Claude Code', 'dlv-mcp' ); ?></h3>
						<p><?php esc_html_e( 'After generating an API key, you\'ll see a ready-to-use command here.', 'dlv-mcp' ); ?></p>
					</div>

					<div class="dlv-mcp-integration-box">
						<h3>⚙️ <?php esc_html_e( 'Manual Configuration', 'dlv-mcp' ); ?></h3>
						<p><?php esc_html_e( 'After generating an API key, you\'ll see the configuration JSON here.', 'dlv-mcp' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Available Tools -->
			<div class="dlv-mcp-section">
				<div class="dlv-mcp-section-header">
					<h2>🛠️ <?php esc_html_e( 'Available MCP Tools', 'dlv-mcp' ); ?></h2>
				</div>
				<div class="dlv-mcp-section-body">
					<p style="color: var(--dlv-text-secondary, #64748b); margin-bottom: 20px;"><?php esc_html_e( 'Once connected, these tools are available:', 'dlv-mcp' ); ?></p>

					<div class="dlv-mcp-tools-grid">
						<div class="dlv-mcp-tool-card">
							<h4>📄 get_debug_log</h4>
							<p><?php esc_html_e( 'Get the last N lines of the debug log', 'dlv-mcp' ); ?></p>
						</div>
						<div class="dlv-mcp-tool-card">
							<h4>🔍 search_debug_log</h4>
							<p><?php esc_html_e( 'Search for patterns in the log', 'dlv-mcp' ); ?></p>
						</div>
						<div class="dlv-mcp-tool-card">
							<h4>⏰ get_errors_since</h4>
							<p><?php esc_html_e( 'Get errors from the last N minutes', 'dlv-mcp' ); ?></p>
						</div>
						<div class="dlv-mcp-tool-card">
							<h4>ℹ️ get_log_info</h4>
							<p><?php esc_html_e( 'Get log file information (size, lines)', 'dlv-mcp' ); ?></p>
						</div>
						<div class="dlv-mcp-tool-card">
							<h4>📋 tail_debug_log</h4>
							<p><?php esc_html_e( 'Get the most recent log entries', 'dlv-mcp' ); ?></p>
						</div>
						<div class="dlv-mcp-tool-card">
							<h4>🗑️ clear_debug_log</h4>
							<p><?php esc_html_e( 'Clear the debug log', 'dlv-mcp' ); ?></p>
						</div>
					</div>

					<div class="dlv-mcp-info-box dlv-mcp-info-box--info" style="margin-top: 24px;">
						<div>
							<strong style="display: block; margin-bottom: 8px;">💡 <?php esc_html_e( 'Example Usage', 'dlv-mcp' ); ?></strong>
							<p style="margin: 0; color: var(--dlv-text-secondary, #64748b); font-style: italic;">
								"Show me the recent errors from my WordPress debug log"<br>
								"Search the debug log for 'Fatal error'"<br>
								"What errors occurred in the last 30 minutes?"
							</p>
						</div>
					</div>
				</div>
			</div>
		<?php endif; ?>
	</div>
	<?php
}

/**
 * Render the Tools → DLV MCP page.
 */
function render_tools_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'dlv-mcp' ) );
	}

	$settings = get_settings();
	$message  = '';
	$error    = '';

	// Handle messages from redirects.
	if ( isset( $_GET['dlv_mcp_message'] ) ) {
		$msg_type = sanitize_text_field( wp_unslash( $_GET['dlv_mcp_message'] ) );
		switch ( $msg_type ) {
			case 'enabled':
				$message = __( 'Logging has been enabled.', 'dlv-mcp' );
				break;
			case 'disabled':
				$message = __( 'Logging has been disabled.', 'dlv-mcp' );
				break;
			case 'cleared':
				$message = __( 'Log file has been cleared.', 'dlv-mcp' );
				break;
			case 'deleted':
				$message = __( 'Log file has been deleted.', 'dlv-mcp' );
				break;
			case 'max_size_saved':
				$message = __( 'Maximum log size has been updated.', 'dlv-mcp' );
				break;
		}
	}

	if ( isset( $_GET['dlv_mcp_error'] ) ) {
		$err_type = sanitize_text_field( wp_unslash( $_GET['dlv_mcp_error'] ) );
		switch ( $err_type ) {
			case 'enable_failed':
				$error = __( 'Could not enable logging. Please check file permissions.', 'dlv-mcp' );
				break;
			case 'clear_failed':
				$error = __( 'Could not clear the log file.', 'dlv-mcp' );
				break;
			case 'clear_not_writable':
				$error = __( 'Log file does not exist or is not writable.', 'dlv-mcp' );
				break;
			case 'delete_failed':
				$error = __( 'Could not delete the log file.', 'dlv-mcp' );
				break;
			case 'delete_not_found':
				$error = __( 'Log file not found or not writable.', 'dlv-mcp' );
				break;
			case 'delete_current':
				$error = __( 'Cannot delete the current log file.', 'dlv-mcp' );
				break;
			case 'delete_invalid':
				$error = __( 'Invalid log file name.', 'dlv-mcp' );
				break;
		}
	}

	$settings            = get_settings();
	$enabled             = ! empty( $settings['enabled'] );
	$log_file            = ! empty( $settings['log_file'] ) ? $settings['log_file'] : '';
	$wrap_lines          = (bool) $settings['wrap_lines'];
	$auto_refresh        = (bool) $settings['auto_refresh'];
	$auto_refresh_interval = absint( $settings['auto_refresh_interval'] );
	$hide_deprecated     = (bool) $settings['hide_deprecated'];
	$highlight           = (bool) $settings['highlight'];
	$log_data            = '';
	$log_info            = array();

	if ( $log_file && file_exists( $log_file ) && is_readable( $log_file ) ) {
		$log_data = tail_file( $log_file );
		$log_info = get_log_info( $log_file );
	} elseif ( $log_file && file_exists( $log_file ) ) {
		$log_info = get_log_info( $log_file );
	}

	?>
	<div class="dlv-mcp-wrap">
		<!-- Compact Header -->
		<div class="dlv-mcp-header dlv-mcp-header--compact">
			<h1>📋 Debug Log Viewer</h1>
		</div>

		<?php if ( $message ) : ?>
			<div class="notice notice-success is-dismissible">
				<p><?php echo esc_html( $message ); ?></p>
			</div>
		<?php endif; ?>

		<?php if ( $error ) : ?>
			<div class="notice notice-error is-dismissible">
				<p><?php echo esc_html( $error ); ?></p>
			</div>
		<?php endif; ?>

		<!-- Combined Log File Section -->
		<div class="dlv-mcp-section">
			<div class="dlv-mcp-section-header dlv-mcp-section-header--stacked">
				<div class="dlv-mcp-section-header-row">
					<h2>📁 <?php esc_html_e( 'Log File', 'dlv-mcp' ); ?></h2>
					<?php if ( $log_file ) : ?>
						<?php if ( file_exists( $log_file ) && is_readable( $log_file ) ) : ?>
							<a href="<?php echo esc_url( get_view_log_url( basename( $log_file ) ) ); ?>" target="_blank" class="dlv-mcp-link-icon" title="<?php esc_attr_e( 'View in browser', 'dlv-mcp' ); ?>">🔗</a>
						<?php endif; ?>
						<code class="dlv-mcp-code-inline dlv-mcp-code-inline--path"><?php echo esc_html( $log_file ); ?></code>
					<?php else : ?>
						<span style="color: var(--dlv-text-muted, #94a3b8); font-size: 13px;"><?php esc_html_e( 'No log file defined', 'dlv-mcp' ); ?></span>
					<?php endif; ?>
				</div>
				<div class="dlv-mcp-section-header-row">
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="dlv-mcp-main-form" style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 0;">
						<?php wp_nonce_field( 'dlv_mcp_tools_action', 'dlv_mcp_nonce' ); ?>
						<input type="hidden" name="action" value="dlv_mcp_action" />
						<?php if ( $enabled ) : ?>
							<button type="submit" class="dlv-mcp-btn dlv-mcp-btn--secondary dlv-mcp-btn--small" name="dlv_mcp_action" value="disable">
								⏸️ <?php esc_html_e( 'Disable logging', 'dlv-mcp' ); ?>
							</button>
						<?php else : ?>
							<button type="submit" class="dlv-mcp-btn dlv-mcp-btn--success dlv-mcp-btn--small" name="dlv_mcp_action" value="enable">
								▶️ <?php esc_html_e( 'Enable logging', 'dlv-mcp' ); ?>
							</button>
						<?php endif; ?>
						<?php if ( $enabled && $log_file && file_exists( $log_file ) && is_readable( $log_file ) ) : ?>
							<button type="button" class="dlv-mcp-btn dlv-mcp-btn--secondary dlv-mcp-btn--small" id="dlv-mcp-refresh-btn">
								🔄 <?php esc_html_e( 'Refresh', 'dlv-mcp' ); ?>
							</button>
							<button type="submit" class="dlv-mcp-btn dlv-mcp-btn--secondary dlv-mcp-btn--small" name="dlv_mcp_action" value="download">
								⬇️ <?php esc_html_e( 'Download', 'dlv-mcp' ); ?>
							</button>
						<?php endif; ?>
						<?php if ( $enabled && $log_file && file_exists( $log_file ) && is_writable( $log_file ) ) : ?>
							<button type="submit" class="dlv-mcp-btn dlv-mcp-btn--danger dlv-mcp-btn--small" name="dlv_mcp_action" value="clear">
								🗑️ <?php esc_html_e( 'Clear', 'dlv-mcp' ); ?>
							</button>
						<?php endif; ?>
					</form>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=dlv-mcp-settings' ) ); ?>" class="dlv-mcp-btn dlv-mcp-btn--outline dlv-mcp-btn--small">
						⚙️ <?php esc_html_e( 'MCP Server Settings...', 'dlv-mcp' ); ?>
					</a>
				</div>
			</div>
			<div class="dlv-mcp-section-body">
				<?php
				// Show all available log files
				$all_logs = get_all_log_files();
				if ( ! empty( $all_logs ) && count( $all_logs ) > 1 ) : ?>
					<details style="margin-bottom: 15px;">
						<summary style="cursor: pointer; font-weight: 600; font-size: 13px;">
							<?php
							printf(
								/* translators: %d: number of log files */
								esc_html__( 'All log files (%d)', 'dlv-mcp' ),
								count( $all_logs )
							);
							?>
						</summary>
						<table class="widefat striped" style="margin-top: 10px;">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'dlv-mcp' ); ?></th>
									<th><?php esc_html_e( 'Size', 'dlv-mcp' ); ?></th>
									<th><?php esc_html_e( 'Modified', 'dlv-mcp' ); ?></th>
									<th><?php esc_html_e( 'Actions', 'dlv-mcp' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $all_logs as $log ) : ?>
									<tr<?php echo $log['current'] ? ' style="background: #e7f3ff;"' : ''; ?>>
										<td>
											<code><?php echo esc_html( $log['name'] ); ?></code>
											<?php if ( $log['current'] ) : ?>
												<span class="dashicons dashicons-yes" title="<?php esc_attr_e( 'Current log file', 'dlv-mcp' ); ?>" style="color: #00a32a;"></span>
											<?php endif; ?>
										</td>
										<td><?php echo esc_html( size_format( $log['size'], 2 ) ); ?></td>
										<td><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $log['modified'] ) ); ?></td>
										<td>
											<a href="<?php echo esc_url( get_view_log_url( $log['name'] ) ); ?>" target="_blank">
												<?php esc_html_e( 'View', 'dlv-mcp' ); ?> ↗
											</a>
											<?php if ( ! $log['current'] ) : ?>
												<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display: inline; margin-left: 8px;">
													<?php wp_nonce_field( 'dlv_mcp_tools_action', 'dlv_mcp_nonce' ); ?>
													<input type="hidden" name="action" value="dlv_mcp_action" />
													<input type="hidden" name="dlv_mcp_action" value="delete_log" />
													<input type="hidden" name="dlv_mcp_log_name" value="<?php echo esc_attr( $log['name'] ); ?>" />
													<button type="submit" class="button-link" style="color: #b32d2e;" onclick="return confirm('<?php echo esc_js( __( 'Delete this log file?', 'dlv-mcp' ) ); ?>');">
														<?php esc_html_e( 'Delete', 'dlv-mcp' ); ?>
													</button>
												</form>
											<?php endif; ?>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>

						<!-- Max Log Size Setting -->
						<div class="dlv-mcp-max-size-setting" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--dlv-border, #e2e8f0);">
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
								<?php wp_nonce_field( 'dlv_mcp_tools_action', 'dlv_mcp_nonce' ); ?>
								<input type="hidden" name="action" value="dlv_mcp_action" />
								<input type="hidden" name="dlv_mcp_action" value="save_max_size" />
								<label style="display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--dlv-text-secondary, #64748b);">
									<?php esc_html_e( 'Max log size:', 'dlv-mcp' ); ?>
									<select name="dlv_mcp_max_log_size" class="dlv-mcp-select" style="padding: 6px 12px; border: 1px solid var(--dlv-border, #e2e8f0); border-radius: 4px; font-size: 13px; min-width: 100px;">
										<?php
										$current_max = ! empty( $settings['max_log_size'] ) ? (int) $settings['max_log_size'] : 1048576;
										$size_options = array(
											524288   => '512 KB',
											1048576  => '1 MB',
											2097152  => '2 MB',
											5242880  => '5 MB',
											10485760 => '10 MB',
											20971520 => '20 MB',
											52428800 => '50 MB',
										);
										foreach ( $size_options as $bytes => $label ) :
										?>
											<option value="<?php echo esc_attr( $bytes ); ?>" <?php selected( $current_max, $bytes ); ?>><?php echo esc_html( $label ); ?></option>
										<?php endforeach; ?>
									</select>
								</label>
								<button type="submit" class="dlv-mcp-btn dlv-mcp-btn--secondary dlv-mcp-btn--small">
									<?php esc_html_e( 'Save', 'dlv-mcp' ); ?>
								</button>
								<span style="font-size: 12px; color: var(--dlv-text-muted, #94a3b8);">
									<?php esc_html_e( 'Log rotates when this size is reached', 'dlv-mcp' ); ?>
								</span>
							</form>
						</div>
					</details>
				<?php endif; ?>

		<div class="dlv-mcp-controls">
			<label>
				<input type="checkbox" id="dlv-mcp-wrap-toggle" name="dlv_mcp_wrap_lines" <?php checked( $wrap_lines ); ?> form="dlv-mcp-main-form" />
				<?php esc_html_e( 'Wrap lines', 'dlv-mcp' ); ?>
			</label>
			
			<label>
				<input type="checkbox" id="dlv-mcp-highlight-toggle" name="dlv_mcp_highlight" <?php checked( $highlight ); ?> form="dlv-mcp-main-form" />
				<?php esc_html_e( 'Highlight', 'dlv-mcp' ); ?>
			</label>
			
			<label>
				<input type="checkbox" id="dlv-mcp-hide-deprecated-toggle" name="dlv_mcp_hide_deprecated" <?php checked( $hide_deprecated ); ?> form="dlv-mcp-main-form" />
				<?php esc_html_e( 'Hide Deprecated', 'dlv-mcp' ); ?>
			</label>
			
			<label>
				<?php esc_html_e( 'Filter:', 'dlv-mcp' ); ?>
				<input type="text" id="dlv-mcp-search-input" placeholder="<?php esc_attr_e( 'Search...', 'dlv-mcp' ); ?>" />
			</label>

			<?php if ( $enabled && $log_file && file_exists( $log_file ) && is_readable( $log_file ) ) : ?>
				<label>
					<input type="checkbox" id="dlv-mcp-auto-refresh-toggle" name="dlv_mcp_auto_refresh" <?php checked( $auto_refresh ); ?> form="dlv-mcp-main-form" />
					<?php esc_html_e( 'Auto-refresh', 'dlv-mcp' ); ?>
				</label>
				<label>
					<?php esc_html_e( 'Interval:', 'dlv-mcp' ); ?>
					<input type="number" id="dlv-mcp-auto-refresh-interval" name="dlv_mcp_auto_refresh_interval" value="<?php echo esc_attr( $auto_refresh_interval ); ?>" min="1" max="60" form="dlv-mcp-main-form" />
					<?php esc_html_e( 'seconds', 'dlv-mcp' ); ?>
				</label>

				<button type="button" class="button" id="dlv-mcp-copy-button">
					<?php esc_html_e( 'Copy to clipboard', 'dlv-mcp' ); ?>
				</button>
				<span id="dlv-mcp-copy-status"></span>
			<?php endif; ?>
		</div>

		<?php if ( $enabled && $log_file && file_exists( $log_file ) && is_readable( $log_file ) ) : ?>
			<div class="dlv-mcp-log-info" id="dlv-mcp-log-info">
				<?php esc_html_e( 'Size:', 'dlv-mcp' ); ?> <?php echo esc_html( $log_info['size_human'] ); ?>
				<?php if ( $log_info['lines'] > 0 ) : ?>
					| <?php esc_html_e( 'Lines:', 'dlv-mcp' ); ?> <?php echo esc_html( number_format_i18n( $log_info['lines'] ) ); ?>
				<?php endif; ?>
			</div>
		<?php endif; ?>

		<?php if ( ! $log_file ) : ?>
			<div class="dlv-mcp-info-box dlv-mcp-info-box--warning">
				<span>⚠️</span>
				<p style="margin: 0;"><?php esc_html_e( 'No log file is currently configured. Enable logging to create a new log file.', 'dlv-mcp' ); ?></p>
			</div>
		<?php elseif ( ! file_exists( $log_file ) ) : ?>
			<div class="dlv-mcp-info-box dlv-mcp-info-box--info">
				<span>ℹ️</span>
				<p style="margin: 0;"><?php esc_html_e( 'The configured log file does not exist yet. It will be created when the first error is logged.', 'dlv-mcp' ); ?></p>
			</div>
		<?php elseif ( ! is_readable( $log_file ) ) : ?>
			<div class="dlv-mcp-info-box dlv-mcp-info-box--error">
				<span>❌</span>
				<p style="margin: 0;"><?php esc_html_e( 'The log file exists but is not readable. Please check file permissions.', 'dlv-mcp' ); ?></p>
			</div>
		<?php else : ?>
			<textarea
				id="dlv-mcp-log-textarea"
				readonly="readonly"
				style="white-space:<?php echo esc_attr( $wrap_lines ? 'pre-wrap' : 'pre' ); ?>;"
			><?php echo esc_textarea( $log_data ); ?></textarea>
			<div id="dlv-mcp-log-display" style="white-space:<?php echo esc_attr( $wrap_lines ? 'pre-wrap' : 'pre' ); ?>;"></div>
		<?php endif; ?>
			</div>
		</div>
	</div>
	<?php
}
