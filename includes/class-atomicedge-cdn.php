<?php
/**
 * AtomicEdge CDN Main Class
 *
 * Core CDN functionality including settings management,
 * enable/disable logic, minification, and cache management.
 *
 * @package AtomicEdge
 * @since   2.0.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_CDN
 *
 * Main CDN functionality class.
 */
class AtomicEdge_CDN {

	/**
	 * Singleton instance.
	 *
	 * @var AtomicEdge_CDN|null
	 */
	private static $instance = null;

	/**
	 * Get singleton instance.
	 *
	 * @return AtomicEdge_CDN
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->init_hooks();

		// Initialize rewriter if CDN is enabled.
		if ( self::is_cdn_enabled() && ! is_admin() ) {
			new AtomicEdge_CDN_Rewrite();
		}

		// Add DNS prefetch for CDN.
		if ( self::is_cdn_enabled() ) {
			add_action( 'wp_head', array( $this, 'add_dns_prefetch' ), 0 );
		}

		// Add HTML minification if enabled.
		if ( self::is_html_minification_enabled() ) {
			add_filter( 'atomicedge_cdn_rewrite_urls', array( $this, 'minify_html' ), 999, 1 );
		}
	}

	/**
	 * Prevent cloning.
	 */
	private function __clone() {}

	/**
	 * Prevent unserialization.
	 */
	public function __wakeup() {
		throw new Exception( esc_html__( 'Cannot unserialize singleton', 'atomic-edge-security' ) );
	}

	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	private function init_hooks() {
		// Register settings.
		add_action( 'admin_init', array( $this, 'register_settings' ) );

		// AJAX handlers for minified cache.
		add_action( 'wp_ajax_atomicedge_cdn_clear_minified_cache', array( $this, 'ajax_clear_minified_cache' ) );
	}

	/**
	 * Register CDN settings.
	 *
	 * @return void
	 */
	public function register_settings() {
		// Master CDN enable switch.
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_local_enabled' );

		// Note: Site URL (atomicedge_cdn_url) removed - always use WordPress's site_url().

		// Dev mode - allows testing without dashboard connection.
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_dev_mode' );
		register_setting(
			'atomicedge-cdn-settings',
			'atomicedge_cdn_dev_url',
			array(
				'sanitize_callback' => array( __CLASS__, 'sanitize_cdn_url' ),
			)
		);

		// File type toggles.
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_css', array( 'default' => 'on' ) );
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_js', array( 'default' => 'on' ) );
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_media', array( 'default' => 'on' ) );

		// Minification toggles.
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_minify_css' );
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_minify_js' );
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_minify_html' );
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_minify_html_skip_logged_in' );
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_minify_html_preserve_comments' );

		// Advanced - URL exclusions.
		register_setting( 'atomicedge-cdn-settings', 'atomicedge_cdn_reject_files', 'atomicedge_cdn_sanitize_reject_field' );
	}

	/**
	 * Sanitize the site URL setting.
	 *
	 * Ensures the URL has http:// scheme and is properly sanitized.
	 * Also detects and repairs URL corruption patterns.
	 *
	 * @param string $url The URL to sanitize.
	 * @return string Sanitized URL.
	 */
	public static function sanitize_site_url( $url ) {
		$url = trim( $url );
		if ( empty( $url ) ) {
			return get_site_url();
		}

		// Repair corruption: strip "http" or "https" embedded in the hostname.
		// E.g., "http://httphttpshift8.local" -> "http://shift8.local".
		$url = self::repair_url_corruption( $url );

		// Only add scheme if URL doesn't already have http:// or https://.
		if ( ! preg_match( '#^https?://#i', $url ) ) {
			$url = 'http://' . $url;
		}

		return esc_url_raw( $url );
	}

	/**
	 * Sanitize the CDN URL setting.
	 *
	 * Ensures the URL has https:// scheme and is properly sanitized.
	 * Also detects and repairs URL corruption patterns.
	 *
	 * @param string $url The URL to sanitize.
	 * @return string Sanitized URL.
	 */
	public static function sanitize_cdn_url( $url ) {
		$url = trim( $url );
		if ( empty( $url ) ) {
			return '';
		}

		// Repair corruption: strip "http" or "https" embedded in the hostname.
		// E.g., "https://httpshttpscdn.example.com" -> "https://cdn.example.com".
		$url = self::repair_url_corruption( $url );

		// Only add scheme if URL doesn't already have http:// or https://.
		if ( ! preg_match( '#^https?://#i', $url ) ) {
			$url = 'https://' . $url;
		}

		return esc_url_raw( $url );
	}

	/**
	 * Repair URL corruption patterns.
	 *
	 * Detects and fixes common corruption patterns like:
	 * - "http://httphttpshift8.local" -> "http://shift8.local"
	 * - "https://httpshttpscdn.example.com" -> "https://cdn.example.com"
	 * - "http://http://example.com" -> "http://example.com"
	 *
	 * @param string $url The potentially corrupted URL.
	 * @return string Repaired URL.
	 */
	private static function repair_url_corruption( $url ) {
		// Pattern 1: Double scheme (http://http://example.com).
		$url = preg_replace( '#^(https?://)https?://#i', '$1', $url );

		// Pattern 2: Scheme embedded in hostname (http://httphttpexample.com).
		// Match scheme, then "http" or "https" prefix on hostname.
		$url = preg_replace( '#^(https?://)(https?)+#i', '$1', $url );

		return $url;
	}

	/**
	 * Check if CDN is enabled.
	 *
	 * Simple logic: Local switch ON + CDN URL available = enabled.
	 * No dashboard status gating - if the CDN URL doesn't work, assets fail to load.
	 * That's the user's problem to debug, not something we should prevent.
	 *
	 * CDN URL sources (in order of priority):
	 * 1. ATOMICEDGE_CDN_DEV_URL constant (wp-config.php) - for local dev
	 * 2. atomicedge_site_data['cdn_url'] - from dashboard API
	 * 3. atomicedge_site_data['cdn_prefix'] + suffix - fallback
	 *
	 * @return bool True if CDN should be active.
	 */
	public static function is_cdn_enabled() {
		// Check local master switch first.
		if ( 'on' !== get_option( 'atomicedge_cdn_local_enabled' ) ) {
			return false;
		}

		// Check if we have a CDN URL from any source.
		return ! empty( self::get_cdn_hostname() );
	}

	/**
	 * Check if HTML minification is enabled.
	 *
	 * @return bool True if HTML minification should be active.
	 */
	public static function is_html_minification_enabled() {
		return self::is_cdn_enabled() && 'on' === get_option( 'atomicedge_cdn_minify_html' );
	}

	/**
	 * Get all CDN options as an array.
	 *
	 * @return array CDN options.
	 */
	public static function get_cdn_options() {
		return array(
			// Always use WordPress's site_url() - no user override needed.
			'cdn_url'                           => get_site_url(),
			'cdn_css'                           => get_option( 'atomicedge_cdn_css', 'on' ),
			'cdn_js'                            => get_option( 'atomicedge_cdn_js', 'on' ),
			'cdn_media'                         => get_option( 'atomicedge_cdn_media', 'on' ),
			'cdn_minify_css'                    => get_option( 'atomicedge_cdn_minify_css', '' ),
			'cdn_minify_js'                     => get_option( 'atomicedge_cdn_minify_js', '' ),
			'cdn_minify_html'                   => get_option( 'atomicedge_cdn_minify_html', '' ),
			'cdn_minify_html_skip_logged_in'    => get_option( 'atomicedge_cdn_minify_html_skip_logged_in', '' ),
			'cdn_minify_html_preserve_comments' => get_option( 'atomicedge_cdn_minify_html_preserve_comments', '' ),
			'cdn_reject_files'                  => get_option( 'atomicedge_cdn_reject_files', '' ),
		);
	}

	/**
	 * Add DNS prefetch hints to page head.
	 *
	 * @return void
	 */
	public function add_dns_prefetch() {
		$site_data = get_option( 'atomicedge_site_data', array() );
		$cdn_prefix = $site_data['cdn_prefix'] ?? '';

		if ( empty( $cdn_prefix ) ) {
			return;
		}

		echo '<meta http-equiv="x-dns-prefetch-control" content="on">' . "\n";
		echo '<link rel="dns-prefetch" href="//' . esc_attr( $cdn_prefix ) . esc_attr( ATOMICEDGE_CDN_SUFFIX ) . '" />' . "\n";
	}

	/**
	 * Get the CDN hostname for display.
	 *
	 * CDN URL comes from dashboard API data.
	 * For local dev testing, define ATOMICEDGE_CDN_DEV_URL in wp-config.php.
	 *
	 * @return string CDN hostname.
	 */
	public static function get_cdn_hostname() {
		// DEV MODE: If ATOMICEDGE_CDN_DEV_URL constant is defined, use it.
		// Usage: define('ATOMICEDGE_CDN_DEV_URL', 'https://cdn.atomicedge.io'); in wp-config.php
		if ( defined( 'ATOMICEDGE_CDN_DEV_URL' ) && ATOMICEDGE_CDN_DEV_URL ) {
			$cdn_url = ATOMICEDGE_CDN_DEV_URL;
			// If it's just a hostname (no scheme), return it directly.
			if ( ! preg_match( '#^https?://#i', $cdn_url ) ) {
				return rtrim( $cdn_url, '/' );
			}
			// Otherwise parse out the host.
			$parsed = wp_parse_url( $cdn_url );
			return $parsed['host'] ?? '';
		}

		// Get from site data (set by dashboard API).
		$site_data = get_option( 'atomicedge_site_data', array() );

		// Use cdn_url from API response if available.
		if ( ! empty( $site_data['cdn_url'] ) ) {
			$cdn_url = $site_data['cdn_url'];
			// If it's just a hostname (no scheme), return it directly.
			if ( ! preg_match( '#^https?://#i', $cdn_url ) ) {
				return rtrim( $cdn_url, '/' );
			}
			// Otherwise parse out the host.
			$parsed = wp_parse_url( $cdn_url );
			return $parsed['host'] ?? '';
		}

		// Build from prefix + unified suffix.
		$cdn_prefix = $site_data['cdn_prefix'] ?? '';
		if ( empty( $cdn_prefix ) ) {
			return '';
		}

		return $cdn_prefix . ATOMICEDGE_CDN_SUFFIX;
	}

	/**
	 * Get cache directory path for minified files.
	 *
	 * @return string Cache directory path.
	 */
	public static function get_cache_dir() {
		$upload_dir = wp_upload_dir();
		return $upload_dir['basedir'] . '/' . ATOMICEDGE_CDN_CACHE_DIR;
	}

	/**
	 * Get cache stats for minified files.
	 *
	 * @return array Cache statistics with keys: count, size_human, css_count, js_count, total_size.
	 */
	public static function get_cache_stats() {
		$stats = array(
			'count'      => 0,
			'css_count'  => 0,
			'js_count'   => 0,
			'total_size' => 0,
			'size_human' => '0 B',
		);

		$cache_dir = self::get_cache_dir();

		// Count CSS files.
		$css_dir = $cache_dir . '/css';
		if ( is_dir( $css_dir ) ) {
			$css_files = glob( $css_dir . '/*.css' );
			if ( $css_files ) {
				$stats['css_count'] = count( $css_files );
				foreach ( $css_files as $file ) {
					$stats['total_size'] += filesize( $file );
				}
			}
		}

		// Count JS files.
		$js_dir = $cache_dir . '/js';
		if ( is_dir( $js_dir ) ) {
			$js_files = glob( $js_dir . '/*.js' );
			if ( $js_files ) {
				$stats['js_count'] = count( $js_files );
				foreach ( $js_files as $file ) {
					$stats['total_size'] += filesize( $file );
				}
			}
		}

		// Calculate total count and human-readable size.
		$stats['count']      = $stats['css_count'] + $stats['js_count'];
		$stats['size_human'] = size_format( $stats['total_size'], 2 );

		return $stats;
	}

	/**
	 * Clear minified file cache.
	 *
	 * @return bool True on success.
	 */
	public static function clear_minified_cache() {
		$cache_dir = self::get_cache_dir();

		if ( ! is_dir( $cache_dir ) ) {
			return true;
		}

		// Clear CSS files.
		$css_dir = $cache_dir . '/css';
		if ( is_dir( $css_dir ) ) {
			$css_files = glob( $css_dir . '/*' );
			if ( $css_files ) {
				foreach ( $css_files as $file ) {
					if ( is_file( $file ) ) {
						wp_delete_file( $file );
					}
				}
			}
		}

		// Clear JS files.
		$js_dir = $cache_dir . '/js';
		if ( is_dir( $js_dir ) ) {
			$js_files = glob( $js_dir . '/*' );
			if ( $js_files ) {
				foreach ( $js_files as $file ) {
					if ( is_file( $file ) ) {
						wp_delete_file( $file );
					}
				}
			}
		}

		// Clear minify map transient.
		delete_transient( 'atomicedge_cdn_minify_map' );

		return true;
	}

	/**
	 * AJAX handler to clear minified cache.
	 *
	 * @return void
	 */
	public function ajax_clear_minified_cache() {
		check_ajax_referer( 'atomicedge_cdn_clear_cache', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized', 'atomic-edge-security' ) ) );
		}

		if ( self::clear_minified_cache() ) {
			wp_send_json_success( array( 'message' => __( 'Cache cleared successfully.', 'atomic-edge-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to clear cache.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Get minified URL for a file.
	 *
	 * @param string $url       Original URL.
	 * @param string $extension File extension.
	 * @return string Minified URL or original.
	 */
	public static function get_minified_url( $url, $extension ) {
		// Get file path from URL.
		$site_url  = get_site_url();
		$file_path = str_replace( $site_url, ABSPATH, $url );
		$file_path = preg_replace( '/\?.*$/', '', $file_path ); // Remove query string.

		if ( ! file_exists( $file_path ) ) {
			return $url;
		}

		// Generate cache key.
		$file_hash = md5( $file_path . filemtime( $file_path ) );
		$cache_dir = self::get_cache_dir() . '/' . $extension;

		// Ensure cache directory exists.
		if ( ! is_dir( $cache_dir ) ) {
			wp_mkdir_p( $cache_dir );
		}

		$cache_file = $cache_dir . '/' . $file_hash . '.' . $extension;
		$upload_dir = wp_upload_dir();

		// Check if minified version exists.
		if ( file_exists( $cache_file ) ) {
			return str_replace(
				$upload_dir['basedir'],
				$upload_dir['baseurl'],
				$cache_file
			);
		}

		// Read original file.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$content = file_get_contents( $file_path );
		if ( false === $content ) {
			return $url;
		}

		// Minify content.
		$minified = self::minify_content( $content, $extension );
		if ( empty( $minified ) || $minified === $content ) {
			return $url;
		}

		// Save minified file.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === file_put_contents( $cache_file, $minified ) ) {
			return $url;
		}

		return str_replace(
			$upload_dir['basedir'],
			$upload_dir['baseurl'],
			$cache_file
		);
	}

	/**
	 * Minify content based on type.
	 *
	 * @param string $content   Content to minify.
	 * @param string $extension File extension.
	 * @return string Minified content.
	 */
	public static function minify_content( $content, $extension ) {
		if ( 'css' === $extension ) {
			return self::minify_css( $content );
		}

		if ( 'js' === $extension ) {
			return self::minify_js( $content );
		}

		return $content;
	}

	/**
	 * Minify CSS content.
	 *
	 * @param string $content CSS content.
	 * @return string Minified CSS.
	 */
	public static function minify_css( $content ) {
		// Remove comments.
		$content = preg_replace( '!/\*[^*]*\*+([^/][^*]*\*+)*/!', '', $content );

		// Remove whitespace.
		$content = str_replace( array( "\r\n", "\r", "\n", "\t" ), '', $content );

		// Remove spaces around selectors and braces.
		$content = preg_replace( '/\s*([\{\}\:\;\,])\s*/', '$1', $content );

		// Remove trailing semicolons before closing braces.
		$content = str_replace( ';}', '}', $content );

		return trim( $content );
	}

	/**
	 * Minify JavaScript content.
	 *
	 * Uses a basic minification approach for safety.
	 *
	 * @param string $content JS content.
	 * @return string Minified JS.
	 */
	public static function minify_js( $content ) {
		// Remove single-line comments (but not URLs with //).
		$content = preg_replace( '#(?<!:)//[^\n\r]*[\n\r]#', "\n", $content );

		// Remove multi-line comments.
		$content = preg_replace( '#/\*[^*]*\*+([^/*][^*]*\*+)*/#', '', $content );

		// Remove multiple whitespace.
		$content = preg_replace( '/\s+/', ' ', $content );

		// Remove spaces around operators.
		$content = preg_replace( '/\s*([\{\}\(\)\[\];,:<>+\-\*\/=])\s*/', '$1', $content );

		return trim( $content );
	}

	/**
	 * Minify HTML content.
	 *
	 * @param string $html HTML content.
	 * @return string Minified HTML.
	 */
	public function minify_html( $html ) {
		// Skip in admin area.
		if ( is_admin() ) {
			return $html;
		}

		// Skip for logged-in users if option is enabled.
		if ( 'on' === get_option( 'atomicedge_cdn_minify_html_skip_logged_in' ) && is_user_logged_in() ) {
			return $html;
		}

		// Skip for page builder edit modes.
		if ( $this->is_page_builder_active() ) {
			return $html;
		}

		try {
			// Preserve important blocks.
			$preserved = array();
			$index     = 0;

			// Preserve script tags.
			$html = preg_replace_callback(
				'/<script\b[^>]*>.*?<\/script>/is',
				function ( $matches ) use ( &$preserved, &$index ) {
					$placeholder               = '___ATOMICEDGE_PRESERVE_' . $index . '___';
					$preserved[ $placeholder ] = $matches[0];
					++$index;
					return $placeholder;
				},
				$html
			);

			// Preserve style tags.
			$html = preg_replace_callback(
				'/<style\b[^>]*>.*?<\/style>/is',
				function ( $matches ) use ( &$preserved, &$index ) {
					$placeholder               = '___ATOMICEDGE_PRESERVE_' . $index . '___';
					$preserved[ $placeholder ] = $matches[0];
					++$index;
					return $placeholder;
				},
				$html
			);

			// Preserve pre tags.
			$html = preg_replace_callback(
				'/<pre\b[^>]*>.*?<\/pre>/is',
				function ( $matches ) use ( &$preserved, &$index ) {
					$placeholder               = '___ATOMICEDGE_PRESERVE_' . $index . '___';
					$preserved[ $placeholder ] = $matches[0];
					++$index;
					return $placeholder;
				},
				$html
			);

			// Preserve textarea tags.
			$html = preg_replace_callback(
				'/<textarea\b[^>]*>.*?<\/textarea>/is',
				function ( $matches ) use ( &$preserved, &$index ) {
					$placeholder               = '___ATOMICEDGE_PRESERVE_' . $index . '___';
					$preserved[ $placeholder ] = $matches[0];
					++$index;
					return $placeholder;
				},
				$html
			);

			// Remove HTML comments (unless preserve option is set).
			if ( 'on' !== get_option( 'atomicedge_cdn_minify_html_preserve_comments' ) ) {
				$html = preg_replace( '/<!--(?!\[if).*?-->/s', '', $html );
			}

			// Remove whitespace between tags.
			$html = preg_replace( '/>\s+</', '><', $html );

			// Remove multiple whitespace.
			$html = preg_replace( '/\s+/', ' ', $html );

			// Restore preserved blocks.
			foreach ( $preserved as $placeholder => $content ) {
				$html = str_replace( $placeholder, $content, $html );
			}

			return $html;
		} catch ( Exception $e ) {
			// Return original on error.
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'AtomicEdge CDN: HTML minification error - ' . esc_html( $e->getMessage() ) );
			}
			return $html;
		}
	}

	/**
	 * Check if a page builder edit mode is active.
	 *
	 * @return bool True if page builder edit mode is active.
	 */
	private function is_page_builder_active() {
		// Elementor.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['elementor-preview'] ) || isset( $_GET['action'] ) && 'elementor' === $_GET['action'] ) {
			return true;
		}

		// Divi.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['et_fb'] ) || isset( $_GET['PageSpeed'] ) ) {
			return true;
		}

		// Beaver Builder.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['fl_builder'] ) ) {
			return true;
		}

		// WPBakery.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['vc_editable'] ) || isset( $_GET['vc_action'] ) ) {
			return true;
		}

		// Brizy.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['brizy-edit'] ) || isset( $_GET['brizy-edit-iframe'] ) ) {
			return true;
		}

		// Oxygen.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['ct_builder'] ) ) {
			return true;
		}

		return false;
	}
}

/**
 * Sanitize CDN reject files textarea.
 *
 * @param string $input Raw input.
 * @return string Sanitized input.
 */
function atomicedge_cdn_sanitize_reject_field( $input ) {
	if ( empty( $input ) ) {
		return '';
	}

	$lines     = explode( "\n", $input );
	$sanitized = array();

	foreach ( $lines as $line ) {
		$line = trim( $line );
		if ( ! empty( $line ) ) {
			// Allow paths, wildcards, basic characters.
			$sanitized[] = preg_replace( '/[^a-zA-Z0-9\/\-_\.\*]/', '', $line );
		}
	}

	return implode( "\n", $sanitized );
}
