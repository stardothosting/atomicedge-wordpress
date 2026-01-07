<?php
/**
 * AtomicEdge Malware Scanner
 *
 * File integrity checking and malware scanning functionality.
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_Scanner
 *
 * Handles malware scanning and file integrity checks.
 * WordPress-aware with whitelisting for known legitimate patterns.
 */
class AtomicEdge_Scanner {

	/**
	 * Whitelisted plugin slugs known to use suspicious-looking but legitimate code.
	 * These plugins use eval/exec/shell functions legitimately.
	 *
	 * @var array
	 */
	private $whitelisted_plugins = array(
		'wordfence',
		'sucuri-scanner',
		'ithemes-security',
		'all-in-one-wp-security-and-firewall',
		'updraftplus',
		'duplicator',
		'jetpack',
		'wp-rocket',
		'w3-total-cache',
		'wp-super-cache',
		'litespeed-cache',
		'redis-cache',
		'wp-mail-smtp',
		'akismet',
		'woocommerce',
		'elementor',
		'wpbakery',
		'divi',
		'query-monitor',
		'debug-bar',
		'developer',
		'theme-check',
		'plugin-check',
		'phpunit',
		'atomicedge', // Our own plugin.
	);

	/**
	 * Whitelisted theme slugs.
	 *
	 * @var array
	 */
	private $whitelisted_themes = array(
		'developer',
		'developer-developer',
		'developer-developer',
	);

	/**
	 * Paths that are always excluded from suspicious pattern scanning.
	 * These contain legitimate code that would trigger false positives.
	 *
	 * @var array
	 */
	private $excluded_paths = array(
		// Composer autoload and vendor directories.
		'/vendor/',
		'/node_modules/',
		// Test directories.
		'/tests/',
		'/test/',
		'/phpunit/',
		// Build/dist directories.
		'/build/',
		'/dist/',
		// Language files.
		'/languages/',
	);

	/**
	 * Known legitimate cache directories in uploads that contain PHP files.
	 * These are created by trusted plugins for caching purposes.
	 *
	 * @var array
	 */
	private $legitimate_upload_cache_paths = array(
		// WPML multilingual plugin Twig cache.
		'/uploads/cache/wpml/',
		// WP Rocket cache.
		'/uploads/wp-rocket/',
		'/uploads/cache/wp-rocket/',
		// Shift8 CDN cache (our partner plugin).
		'/uploads/shift8-cdn-cache/',
		// W3 Total Cache.
		'/uploads/cache/w3tc/',
		// LiteSpeed Cache.
		'/uploads/litespeed/',
		// Autoptimize.
		'/uploads/autoptimize/',
		// Ultimate Addons / Smile fonts.
		'/uploads/smile_fonts/',
		// Elementor CSS cache.
		'/uploads/elementor/css/',
		// WooCommerce logs.
		'/uploads/wc-logs/',
		// Gravity Forms.
		'/uploads/gravity_forms/',
		// WPBakery Page Builder.
		'/uploads/js_composer/',
		// Divi cache.
		'/uploads/et-cache/',
		// Fusion Builder cache.
		'/uploads/fusion-styles/',
	);

	/**
	 * Constructor.
	 */
	public function __construct() {
		// Scanner doesn't need hooks - it's called on demand.
	}

	/**
	 * Run a full scan.
	 *
	 * @return array|false Scan results or false on failure.
	 */
	public function run_full_scan() {
		// Extend time limit for long-running scan, respecting server limits.
		$this->extend_time_limit();

		// Initialize scan state for resumability.
		$scan_state = $this->get_scan_state();

		$results = array(
			'started_at'     => $scan_state ? $scan_state['started_at'] : current_time( 'mysql' ),
			'completed_at'   => '',
			'core_files'     => array(),
			'plugin_files'   => array(),
			'theme_files'    => array(),
			'suspicious'     => array(),
			'summary'        => array(),
			'scan_stats'     => array(
				'files_scanned'  => 0,
				'time_elapsed'   => 0,
				'memory_peak'    => 0,
			),
		);

		// Scan WordPress core files.
		$core_issues = $this->scan_core_files();
		if ( false !== $core_issues ) {
			$results['core_files'] = $core_issues;
		}

		// Scan for suspicious files across ALL WordPress directories.
		$suspicious = $this->scan_suspicious_files();
		if ( false !== $suspicious ) {
			$results['suspicious'] = $suspicious;
		}

		// Generate summary.
		$results['summary'] = array(
			'core_modified'   => count( $results['core_files'] ),
			'suspicious'      => count( $results['suspicious'] ),
			'total_issues'    => count( $results['core_files'] ) + count( $results['suspicious'] ),
		);

		// Add scan statistics.
		$results['scan_stats']['memory_peak'] = memory_get_peak_usage( true );
		$results['scan_stats']['time_elapsed'] = time() - strtotime( $results['started_at'] );

		$results['completed_at'] = current_time( 'mysql' );

		// Clear scan state on completion.
		$this->clear_scan_state();

		// Save results.
		update_option( 'atomicedge_scan_results', $results );
		update_option( 'atomicedge_last_scan', current_time( 'mysql' ) );

		AtomicEdge::log( 'Scan completed', $results['summary'] );

		return $results;
	}

	/**
	 * Extend PHP time limit safely.
	 *
	 * Respects server configuration and handles restrictions gracefully.
	 *
	 * @param int $seconds Desired time limit in seconds.
	 * @return bool Whether time limit was extended.
	 */
	private function extend_time_limit( $seconds = 300 ) {
		// Check if set_time_limit is disabled.
		$disabled = explode( ',', ini_get( 'disable_functions' ) );
		$disabled = array_map( 'trim', $disabled );

		if ( in_array( 'set_time_limit', $disabled, true ) ) {
			return false;
		}

		// Check safe mode (deprecated but may exist on old servers).
		// phpcs:ignore PHPCompatibility.IniDirectives.RemovedIniDirectives.safe_modeDeprecatedRemoved
		if ( @ini_get( 'safe_mode' ) ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return @set_time_limit( $seconds );
	}

	/**
	 * Get saved scan state for resumability.
	 *
	 * @return array|false Scan state or false if no scan in progress.
	 */
	private function get_scan_state() {
		return get_transient( 'atomicedge_scan_state' );
	}

	/**
	 * Save scan state for resumability.
	 *
	 * @param array $state Current scan state.
	 * @return void
	 */
	private function save_scan_state( $state ) {
		set_transient( 'atomicedge_scan_state', $state, HOUR_IN_SECONDS );
	}

	/**
	 * Clear scan state.
	 *
	 * @return void
	 */
	private function clear_scan_state() {
		delete_transient( 'atomicedge_scan_state' );
	}

	/**
	 * Scan WordPress core files against official checksums.
	 *
	 * @return array|false Array of modified files or false on error.
	 */
	public function scan_core_files() {
		global $wp_version;

		// Get official checksums from WordPress.org.
		$checksums = $this->get_core_checksums( $wp_version );

		if ( false === $checksums || ! is_array( $checksums ) ) {
			AtomicEdge::log( 'Failed to fetch core checksums' );
			return false;
		}

		// Bundled plugins/themes that ship with WordPress but are often
		// updated independently - exclude from core checksum verification.
		$bundled_exclusions = array(
			'wp-content/plugins/akismet/',
			'wp-content/plugins/hello.php',
			'wp-content/themes/twentytwenty/',
			'wp-content/themes/twentytwentyone/',
			'wp-content/themes/twentytwentytwo/',
			'wp-content/themes/twentytwentythree/',
			'wp-content/themes/twentytwentyfour/',
			'wp-content/themes/twentytwentyfive/',
		);

		$modified = array();

		foreach ( $checksums as $file => $expected_hash ) {
			$file_path = ABSPATH . $file;

			if ( $this->should_skip_core_file_checksum( $file, $file_path, $bundled_exclusions ) ) {
				continue;
			}

			// Calculate actual hash (WordPress.org core checksums are md5).
			$actual_hash = md5_file( $file_path );

			if ( $actual_hash !== $expected_hash ) {
				$modified[] = array(
					'file'          => $file,
					'file_path'     => $file_path,
					'type'          => 'modified_core',
					'severity'      => 'high',
					'expected_hash' => $expected_hash,
					'actual_hash'   => $actual_hash,
				);
			}
		}

		return $modified;
	}

	/**
	 * Determine whether a core checksum file should be skipped.
	 *
	 * @param string $file Relative core file path.
	 * @param string $file_path Absolute core file path.
	 * @param array  $bundled_exclusions Bundled plugin/theme prefixes to exclude.
	 * @return bool
	 */
	private function should_skip_core_file_checksum( $file, $file_path, $bundled_exclusions ) {
		// Skip if file doesn't exist (might be optional).
		if ( ! file_exists( $file_path ) ) {
			return true;
		}

		// Skip wp-config.php as it's always modified.
		if ( $this->is_core_config_file( $file ) ) {
			return true;
		}

		// Skip bundled plugins/themes (they're often updated independently).
		if ( $this->is_bundled_core_exclusion( $file, $bundled_exclusions ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if a core file is a wp-config variant.
	 *
	 * @param string $file Relative core file path.
	 * @return bool
	 */
	private function is_core_config_file( $file ) {
		return 'wp-config.php' === $file || 'wp-config-sample.php' === $file;
	}

	/**
	 * Check if a file is a bundled plugin/theme excluded from core checksums.
	 *
	 * @param string $file Relative core file path.
	 * @param array  $bundled_exclusions Bundled plugin/theme prefixes.
	 * @return bool
	 */
	private function is_bundled_core_exclusion( $file, $bundled_exclusions ) {
		foreach ( $bundled_exclusions as $exclusion ) {
			if ( 0 === strpos( $file, $exclusion ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get core file checksums from WordPress.org API.
	 *
	 * @param string $version WordPress version.
	 * @return array|false Checksums array or false on failure.
	 */
	private function get_core_checksums( $version ) {
		$locale = get_locale();
		$url    = sprintf(
			'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
			rawurlencode( $version ),
			rawurlencode( $locale )
		);

		$response = wp_remote_get(
			$url,
			array(
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			AtomicEdge::log( 'Checksums API error', $response->get_error_message() );
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! isset( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
			AtomicEdge::log( 'Invalid checksums response', $body );
			return false;
		}

		return $body['checksums'];
	}

	/**
	 * Scan for suspicious files and patterns across ALL WordPress directories.
	 * WordPress-aware: skips whitelisted plugins/themes and excluded paths.
	 *
	 * Scans:
	 * - WordPress root (ABSPATH) for loose PHP files
	 * - wp-admin directory
	 * - wp-includes directory
	 * - wp-content/uploads (any PHP is suspicious)
	 * - wp-content/themes
	 * - wp-content/plugins
	 *
	 * @return array Array of suspicious findings.
	 */
	public function scan_suspicious_files() {
		$suspicious = array();

		// Get comprehensive pattern definitions.
		$pattern_groups = $this->get_malware_patterns();

		// Track already reported files to avoid duplicates.
		$reported_files = array();

		// Track files scanned for stats.
		$files_scanned = 0;

		// Memory limit check - reserve 20MB headroom.
		$memory_limit = $this->get_memory_limit_bytes();
		$memory_threshold = $memory_limit - ( 20 * 1024 * 1024 );

		// 1. SCAN WORDPRESS ROOT DIRECTORY (loose PHP files - common attack vector).
		$this->scan_suspicious_root_files( $pattern_groups, $suspicious, $reported_files, $files_scanned, $memory_threshold );

		// 2. SCAN WP-ADMIN DIRECTORY (should only contain core files).
		$this->scan_directory_for_critical_patterns( ABSPATH . 'wp-admin', __( 'Suspicious pattern in wp-admin', 'atomicedge' ), $suspicious, $reported_files, $files_scanned, $memory_threshold );

		// 3. SCAN WP-INCLUDES DIRECTORY (should only contain core files).
		$this->scan_directory_for_critical_patterns( ABSPATH . WPINC, __( 'Suspicious pattern in wp-includes', 'atomicedge' ), $suspicious, $reported_files, $files_scanned, $memory_threshold );

		// 4. SCAN WP-CONTENT SUBDIRECTORIES.
		$this->scan_wp_content_directories( $pattern_groups, $suspicious, $reported_files, $files_scanned, $memory_threshold );

		// 5. FLAG ANY PHP FILES IN UPLOADS (even without pattern matches).
		$this->flag_php_files_in_uploads( $suspicious, $reported_files );

		// Update scan stats.
		$this->save_scan_state( array(
			'files_scanned' => $files_scanned,
			'started_at'    => current_time( 'mysql' ),
		) );

		return $suspicious;
	}

	/**
	 * Scan the WordPress root directory for suspicious PHP files.
	 *
	 * @param array $pattern_groups Pattern definitions.
	 * @param array $suspicious Output array of findings.
	 * @param array $reported_files Map of already reported relative paths.
	 * @param int   $files_scanned Output count of scanned files.
	 * @param int   $memory_threshold Threshold at which to stop processing.
	 * @return void
	 */
	private function scan_suspicious_root_files( $pattern_groups, &$suspicious, &$reported_files, &$files_scanned, $memory_threshold ) {
		$root_files = $this->get_root_php_files();
		foreach ( $root_files as $file ) {
			// Memory check before processing.
			if ( memory_get_usage( true ) > $memory_threshold ) {
				AtomicEdge::log( 'Scan memory limit approaching, stopping early' );
				break;
			}

			$relative_path = str_replace( ABSPATH, '', $file );
			$files_scanned++;

			// Skip already reported and core files.
			if ( isset( $reported_files[ $relative_path ] ) || $this->is_core_root_file( $relative_path ) ) {
				continue;
			}

			// Non-core PHP files in root are highly suspicious.
			$result = $this->scan_file_for_patterns( $file, $pattern_groups, true );
			if ( $result ) {
				$result['file']          = $relative_path;
				$result['file_path']     = $file;
				$result['location_note'] = __( 'Non-core file in WordPress root', 'atomicedge' );
				$suspicious[]            = $result;
				$reported_files[ $relative_path ] = true;
			} else {
				// Even without pattern match, non-core PHP in root is suspicious.
				$suspicious[] = array(
					'file'      => $relative_path,
					'file_path' => $file,
					'type'     => 'unknown_root_file',
					'severity' => 'high',
					'pattern'  => __( 'Unknown PHP file in WordPress root directory', 'atomicedge' ),
				);
				$reported_files[ $relative_path ] = true;
			}
		}
	}

	/**
	 * Scan a directory for critical malware patterns only.
	 *
	 * @param string $dir Absolute directory path.
	 * @param string $location_note Location note to apply to findings.
	 * @param array  $suspicious Output array of findings.
	 * @param array  $reported_files Map of already reported relative paths.
	 * @param int    $files_scanned Output count of scanned files.
	 * @param int    $memory_threshold Threshold at which to stop processing.
	 * @return void
	 */
	private function scan_directory_for_critical_patterns( $dir, $location_note, &$suspicious, &$reported_files, &$files_scanned, $memory_threshold ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}

		$files = $this->get_php_files( $dir );
		foreach ( $files as $file ) {
			if ( memory_get_usage( true ) > $memory_threshold ) {
				break;
			}

			$relative_path = str_replace( ABSPATH, '', $file );
			$files_scanned++;

			if ( isset( $reported_files[ $relative_path ] ) ) {
				continue;
			}

			$result = $this->scan_file_for_patterns( $file, $this->get_critical_patterns_only(), false );
			if ( $result ) {
				$result['file']          = $relative_path;
				$result['file_path']     = $file;
				$result['location_note'] = $location_note;
				$suspicious[]            = $result;
				$reported_files[ $relative_path ] = true;
			}
		}
	}

	/**
	 * Scan wp-content uploads/themes/plugins.
	 *
	 * @param array $pattern_groups Pattern definitions.
	 * @param array $suspicious Output array of findings.
	 * @param array $reported_files Map of already reported relative paths.
	 * @param int   $files_scanned Output count of scanned files.
	 * @param int   $memory_threshold Threshold at which to stop processing.
	 * @return void
	 */
	private function scan_wp_content_directories( $pattern_groups, &$suspicious, &$reported_files, &$files_scanned, $memory_threshold ) {
		$scan_dirs = array(
			ABSPATH . 'wp-content/uploads' => true,  // is_uploads.
			ABSPATH . 'wp-content/themes'  => false,
			ABSPATH . 'wp-content/plugins' => false,
		);

		foreach ( $scan_dirs as $dir => $is_uploads_dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			$files = $this->get_php_files( $dir );
			foreach ( $files as $file ) {
				if ( memory_get_usage( true ) > $memory_threshold ) {
					AtomicEdge::log( 'Scan memory limit approaching, stopping early' );
					break 2;
				}

				$relative_path = str_replace( ABSPATH, '', $file );
				$files_scanned++;

				if ( isset( $reported_files[ $relative_path ] ) ) {
					continue;
				}

				// Skip whitelisted paths (but NOT in uploads - uploads should always be scanned).
				if ( ! $is_uploads_dir && $this->is_whitelisted_path( $relative_path ) ) {
					continue;
				}

				$patterns_to_check = $is_uploads_dir
					? $pattern_groups
					: $this->get_refined_patterns_for_plugins();

				$result = $this->scan_file_for_patterns( $file, $patterns_to_check, $is_uploads_dir );
				if ( $result ) {
					$result['file']      = $relative_path;
					$result['file_path'] = $file;
					$suspicious[]         = $result;
					$reported_files[ $relative_path ] = true;
				}
			}
		}
	}

	/**
	 * Flag any PHP files in uploads (even if they don't match patterns).
	 *
	 * @param array $suspicious Output array of findings.
	 * @param array $reported_files Map of already reported relative paths.
	 * @return void
	 */
	private function flag_php_files_in_uploads( &$suspicious, &$reported_files ) {
		$uploads_dir = wp_upload_dir();
		if ( ! isset( $uploads_dir['basedir'] ) || ! is_dir( $uploads_dir['basedir'] ) ) {
			return;
		}

		$upload_php_files = $this->get_php_files( $uploads_dir['basedir'] );
		foreach ( $upload_php_files as $file ) {
			$relative_path = str_replace( ABSPATH, '', $file );

			if ( isset( $reported_files[ $relative_path ] ) ) {
				continue;
			}

			if ( $this->is_legitimate_upload_cache( $file ) ) {
				continue;
			}

			$suspicious[] = array(
				'file'      => $relative_path,
				'file_path' => $file,
				'type'     => 'php_in_uploads',
				'severity' => 'high',
				'reason'   => __( 'PHP file found in uploads directory', 'atomicedge' ),
			);
			$reported_files[ $relative_path ] = true;
		}
	}

	/**
	 * Get PHP files in the WordPress root directory only (not recursive).
	 *
	 * @return array Array of PHP file paths in root.
	 */
	private function get_root_php_files() {
		$files = array();
		$root  = ABSPATH;

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$dir_handle = @opendir( $root );
		if ( ! $dir_handle ) {
			return $files;
		}

		// phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
		while ( false !== ( $entry = readdir( $dir_handle ) ) ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			$filepath = $root . $entry;

			// Only files, not directories.
			if ( is_file( $filepath ) && preg_match( '/\.php$/i', $entry ) ) {
				$files[] = $filepath;
			}
		}

		closedir( $dir_handle );

		return $files;
	}

	/**
	 * Check if a file is a known WordPress core root file.
	 *
	 * @param string $relative_path Relative file path.
	 * @return bool True if core file.
	 */
	private function is_core_root_file( $relative_path ) {
		$core_root_files = array(
			'index.php',
			'wp-activate.php',
			'wp-blog-header.php',
			'wp-comments-post.php',
			'wp-config.php',
			'wp-config-sample.php',
			'wp-cron.php',
			'wp-links-opml.php',
			'wp-load.php',
			'wp-login.php',
			'wp-mail.php',
			'wp-settings.php',
			'wp-signup.php',
			'wp-trackback.php',
			'xmlrpc.php',
		);

		return in_array( $relative_path, $core_root_files, true );
	}

	/**
	 * Get critical-only patterns for scanning core directories.
	 *
	 * These patterns are definitive indicators of compromise.
	 *
	 * @return array Critical pattern groups.
	 */
	private function get_critical_patterns_only() {
		$all_patterns = $this->get_malware_patterns();

		return array(
			'backdoor_patterns' => $all_patterns['backdoor_patterns'],
			'webshells'         => $all_patterns['webshells'],
			'wordpress_malware' => $all_patterns['wordpress_malware'],
		);
	}

	/**
	 * Scan a single file for malware patterns.
	 *
	 * @param string $filepath           Full path to file.
	 * @param array  $pattern_groups     Pattern groups to check.
	 * @param bool   $check_php_in_image Whether to check for PHP in images.
	 * @return array|false Finding array or false if clean.
	 */
	private function scan_file_for_patterns( $filepath, $pattern_groups, $check_php_in_image = false ) {
		// Read file content with size limit (skip files > 5MB).
		$filesize = @filesize( $filepath );
		if ( false === $filesize || $filesize > 5 * 1024 * 1024 ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$content = @file_get_contents( $filepath );

		if ( false === $content ) {
			return false;
		}

		// Check for hidden PHP in image files.
		if ( $check_php_in_image && $this->is_php_in_image( $filepath, $content ) ) {
			return array(
				'type'     => 'php_in_image',
				'severity' => 'critical',
				'pattern'  => __( 'PHP code hidden in image file', 'atomicedge' ),
			);
		}

		// Check against pattern groups.
		foreach ( $pattern_groups as $group_name => $patterns ) {
			foreach ( $patterns as $pattern => $description ) {
				// Use # as delimiter to avoid issues with / in patterns.
				if ( preg_match( '#' . $pattern . '#i', $content ) ) {
					$severity = $this->get_pattern_severity( $group_name );
					return array(
						'type'     => 'suspicious_pattern',
						'severity' => $severity,
						'pattern'  => $description,
						'category' => $group_name,
					);
				}
			}
		}

		return false;
	}

	/**
	 * Get PHP memory limit in bytes.
	 *
	 * @return int Memory limit in bytes.
	 */
	private function get_memory_limit_bytes() {
		$memory_limit = ini_get( 'memory_limit' );

		if ( '-1' === $memory_limit ) {
			return PHP_INT_MAX; // Unlimited.
		}

		$value = (int) $memory_limit;
		$unit  = strtoupper( substr( $memory_limit, -1 ) );

		switch ( $unit ) {
			case 'G':
				$value *= 1024 * 1024 * 1024;
				break;
			case 'M':
				$value *= 1024 * 1024;
				break;
			case 'K':
				$value *= 1024;
				break;
		}

		return $value;
	}

	/**
	 * Get all PHP files in a directory recursively.
	 *
	 * @param string $dir Directory to scan.
	 * @return array Array of file paths.
	 */
	private function get_php_files( $dir ) {
		$files = array();

		if ( ! is_dir( $dir ) || ! is_readable( $dir ) ) {
			return $files;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() && preg_match( '/\.php$/i', $file->getFilename() ) ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}

	/**
	 * Get last scan timestamp.
	 *
	 * @return string|false Last scan time or false if never scanned.
	 */
	public function get_last_scan_time() {
		return get_option( 'atomicedge_last_scan', false );
	}

	/**
	 * Get last scan results.
	 *
	 * @return array Scan results array.
	 */
	public function get_last_results() {
		return get_option( 'atomicedge_scan_results', array() );
	}

	/**
	 * Get comprehensive malware detection patterns.
	 *
	 * Patterns are organized by category for better reporting.
	 * Based on community research and known malware signatures.
	 *
	 * @return array Associative array of pattern groups.
	 */
	private function get_malware_patterns() {
		return array(
			// Critical: Direct code execution patterns.
			'code_execution'       => array(
				'eval\s*\('                                                          => __( 'Eval function (code execution)', 'atomicedge' ),
				'assert\s*\('                                                        => __( 'Assert function (potential code execution)', 'atomicedge' ),
				'create_function\s*\('                                               => __( 'Create function (dynamic code creation)', 'atomicedge' ),
				'call_user_func\s*\('                                                => __( 'Call user func (dynamic function call)', 'atomicedge' ),
				'call_user_func_array\s*\('                                          => __( 'Call user func array (dynamic function call)', 'atomicedge' ),
				'preg_replace\s*\([^,]+["\'].*\/e["\']'                               => __( 'Preg replace with eval modifier', 'atomicedge' ),
				'preg_replace_callback\s*\('                                         => __( 'Preg replace callback (potential code execution)', 'atomicedge' ),
			),

			// Critical: Shell/system execution.
			'shell_execution'      => array(
				'\bsystem\s*\('                                                      => __( 'System command execution', 'atomicedge' ),
				'\bexec\s*\('                                                        => __( 'Exec command execution', 'atomicedge' ),
				'\bshell_exec\s*\('                                                  => __( 'Shell exec command', 'atomicedge' ),
				'\bpassthru\s*\('                                                    => __( 'Passthru command execution', 'atomicedge' ),
				'\bpopen\s*\('                                                       => __( 'Popen command execution', 'atomicedge' ),
				'\bproc_open\s*\('                                                   => __( 'Proc open command execution', 'atomicedge' ),
				'\bpcntl_exec\s*\('                                                  => __( 'PCNTL exec', 'atomicedge' ),
				'`[^`]+`'                                                            => __( 'Backtick command execution', 'atomicedge' ),
			),

			// Critical: Backdoor patterns.
			'backdoor_patterns'    => array(
				'@eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'                        => __( 'Backdoor: eval with user input', 'atomicedge' ),
				'@eval\s*\(\s*base64_decode'                                         => __( 'Backdoor: eval with base64', 'atomicedge' ),
				'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\('                   => __( 'Direct superglobal execution', 'atomicedge' ),
				'extract\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Dangerous extract from user input', 'atomicedge' ),
				'include\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Remote file inclusion via user input', 'atomicedge' ),
				'require\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Remote file inclusion via user input', 'atomicedge' ),
				'file_put_contents\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)'             => __( 'File write from user input', 'atomicedge' ),
				'fwrite\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)'                        => __( 'File write from user input', 'atomicedge' ),
			),

			// High: Obfuscation techniques.
			'obfuscation'          => array(
				'base64_decode\s*\('                                                 => __( 'Base64 decoding (potential obfuscation)', 'atomicedge' ),
				'gzinflate\s*\('                                                     => __( 'Gzip inflate (potential obfuscation)', 'atomicedge' ),
				'gzuncompress\s*\('                                                  => __( 'Gzip uncompress (potential obfuscation)', 'atomicedge' ),
				'str_rot13\s*\('                                                     => __( 'ROT13 encoding (potential obfuscation)', 'atomicedge' ),
				'convert_uudecode\s*\('                                              => __( 'UUdecode (potential obfuscation)', 'atomicedge' ),
				'\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){5,}'                        => __( 'Hex encoded strings', 'atomicedge' ),
				'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)(\s*\.\s*chr\s*\(\s*\d+\s*\)){3,}' => __( 'Chr() string building', 'atomicedge' ),
				'edoced_46esab'                                                      => __( 'Reversed base64_decode', 'atomicedge' ),
				'strrev\s*\(["\'][^"\']+["\']\)'                                      => __( 'String reversal (obfuscation)', 'atomicedge' ),
			),

			// High: Known webshell signatures.
			'webshells'            => array(
				'c99shell'                                                           => __( 'C99 shell signature', 'atomicedge' ),
				'r57shell'                                                           => __( 'R57 shell signature', 'atomicedge' ),
				'b374k'                                                              => __( 'B374K shell signature', 'atomicedge' ),
				'FilesMan'                                                           => __( 'FilesMan shell signature', 'atomicedge' ),
				'WSO\s+[\d\.]+'                                                      => __( 'WSO shell signature', 'atomicedge' ),
				'Weevely'                                                            => __( 'Weevely shell signature', 'atomicedge' ),
				'php\s*spy'                                                          => __( 'PHPSpy shell signature', 'atomicedge' ),
				'PHANTOMJS'                                                          => __( 'PhantomJS shell signature', 'atomicedge' ),
				'Mister Spy'                                                         => __( 'Mister Spy shell signature', 'atomicedge' ),
				'Afghan Shell'                                                       => __( 'Afghan Shell signature', 'atomicedge' ),
				'Shell by'                                                           => __( 'Generic shell signature', 'atomicedge' ),
				'SHELL_PASSWORD'                                                     => __( 'Shell password variable', 'atomicedge' ),
				'0day'                                                               => __( '0day exploit reference', 'atomicedge' ),
			),

			// High: WordPress-specific malware.
			'wordpress_malware'    => array(
				'wp-vcd'                                                             => __( 'WP-VCD malware', 'atomicedge' ),
				'class\.theme-modules\.php'                                          => __( 'WP-VCD theme modules', 'atomicedge' ),
				'class\.plugin-modules\.php'                                         => __( 'WP-VCD plugin modules', 'atomicedge' ),
				'wp-tmp\.php'                                                        => __( 'WP-VCD temp file', 'atomicedge' ),
				'tmpcontentx'                                                        => __( 'WP-VCD content injection', 'atomicedge' ),
				'wp_temp_setupx'                                                     => __( 'WP-VCD setup function', 'atomicedge' ),
				'derna\.top'                                                         => __( 'Known malware domain', 'atomicedge' ),
				'/\*\s*@noupdate\s*\*/'                                              => __( 'Plugin update suppression', 'atomicedge' ),
			),

			// Medium: Suspicious file operations.
			'file_operations'      => array(
				'file_get_contents\s*\(["\']https?://'                               => __( 'Remote file fetch', 'atomicedge' ),
				'file_get_contents\s*\(["\']php://input'                             => __( 'Raw POST data read', 'atomicedge' ),
				'curl_exec\s*\('                                                     => __( 'cURL execution', 'atomicedge' ),
				'fsockopen\s*\('                                                     => __( 'Socket connection', 'atomicedge' ),
				'stream_socket_client\s*\('                                          => __( 'Stream socket client', 'atomicedge' ),
			),

			// Medium: Base64 encoded suspicious keywords.
			'base64_keywords'      => array(
				'ZXZhbCg'                                                            => __( 'Base64: eval(', 'atomicedge' ),
				'YXNzZXJ0'                                                           => __( 'Base64: assert', 'atomicedge' ),
				'c3lzdGVt'                                                           => __( 'Base64: system', 'atomicedge' ),
				'ZXhlYyg'                                                            => __( 'Base64: exec(', 'atomicedge' ),
				'c2hlbGxfZXhlYw'                                                     => __( 'Base64: shell_exec', 'atomicedge' ),
				'cGFzc3RocnU'                                                        => __( 'Base64: passthru', 'atomicedge' ),
				'JF9HRV'                                                             => __( 'Base64: $_GET', 'atomicedge' ),
				'JF9QT1NU'                                                           => __( 'Base64: $_POST', 'atomicedge' ),
				'JF9SRVFVRVNU'                                                       => __( 'Base64: $_REQUEST', 'atomicedge' ),
				'JF9DT09LSUU'                                                        => __( 'Base64: $_COOKIE', 'atomicedge' ),
				'SFRUUF9VU0VSX0FHRU5U'                                               => __( 'Base64: HTTP_USER_AGENT', 'atomicedge' ),
				'R0xPQkFMU'                                                          => __( 'Base64: GLOBALS', 'atomicedge' ),
			),

			// Medium: Suspicious strings and indicators.
			'suspicious_strings'   => array(
				'/etc/passwd'                                                            => __( 'Password file access', 'atomicedge' ),
				'/etc/shadow'                                                            => __( 'Shadow file access', 'atomicedge' ),
				'HACKED BY'                                                          => __( 'Defacement signature', 'atomicedge' ),
				'owned by'                                                           => __( 'Defacement signature', 'atomicedge' ),
				'backdoor'                                                           => __( 'Backdoor keyword', 'atomicedge' ),
				'rootkit'                                                            => __( 'Rootkit keyword', 'atomicedge' ),
				'c999sh'                                                             => __( 'Shell variant', 'atomicedge' ),
				'r57sh'                                                              => __( 'Shell variant', 'atomicedge' ),
				'webshell'                                                           => __( 'Webshell keyword', 'atomicedge' ),
				'cmd\.exe'                                                           => __( 'Windows command execution', 'atomicedge' ),
				'powershell\.exe'                                                    => __( 'PowerShell execution', 'atomicedge' ),
				'uname\s+-a'                                                         => __( 'System information gathering', 'atomicedge' ),
				'whoami'                                                             => __( 'User identification command', 'atomicedge' ),
			),

			// Medium: Network indicators.
			'network_indicators'   => array(
'fsockopen\s*\(["\']udp://'                                              => __( 'UDP socket (potential DDoS)', 'atomicedge' ),
				'socket_create\s*\(\s*AF_INET'                                       => __( 'Raw socket creation', 'atomicedge' ),
				'curl_setopt[^;]+CURLOPT_FOLLOWLOCATION'                             => __( 'cURL with redirect following', 'atomicedge' ),
			),

			// Low: Potentially dangerous functions (context-dependent).
			'potentially_dangerous' => array(
				'unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'                  => __( 'Unserialize user input (object injection)', 'atomicedge' ),
				'serialize\s*\([^)]+\)\s*\.'                                         => __( 'Serialized data concatenation', 'atomicedge' ),
				'ini_set\s*\(["\'](?:allow_url_fopen|allow_url_include)'             => __( 'INI override for remote includes', 'atomicedge' ),
				'ini_set\s*\(["\']disable_functions'                                 => __( 'Attempt to modify disabled functions', 'atomicedge' ),
				'error_reporting\s*\(\s*0\s*\)'                                      => __( 'Error reporting disabled', 'atomicedge' ),
				'set_error_handler\s*\(\s*null'                                      => __( 'Error handler nullified', 'atomicedge' ),
			),
		);
	}

	/**
	 * Get severity level for a pattern category.
	 *
	 * @param string $category Pattern category name.
	 * @return string Severity level: 'critical', 'high', 'medium', or 'low'.
	 */
	private function get_pattern_severity( $category ) {
		$severity_map = array(
			'code_execution'        => 'critical',
			'shell_execution'       => 'critical',
			'backdoor_patterns'     => 'critical',
			'webshells'             => 'critical',
			'wordpress_malware'     => 'critical',
			'obfuscation'           => 'high',
			'file_operations'       => 'medium',
			'base64_keywords'       => 'medium',
			'suspicious_strings'    => 'medium',
			'network_indicators'    => 'medium',
			'potentially_dangerous' => 'low',
		);

		return isset( $severity_map[ $category ] ) ? $severity_map[ $category ] : 'medium';
	}

	/**
	 * Check if a file contains PHP code hidden in an image.
	 *
	 * @param string $filepath Full path to the file.
	 * @param string $content  File contents.
	 * @return bool True if PHP is hidden in image, false otherwise.
	 */
	private function is_php_in_image( $filepath, $content ) {
		// Check file extension.
		$extension = strtolower( pathinfo( $filepath, PATHINFO_EXTENSION ) );
		$image_extensions = array( 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'webp' );

		if ( ! in_array( $extension, $image_extensions, true ) ) {
			return false;
		}

		// Check for PHP opening tags in image files.
		if ( preg_match( '/<\?php/i', $content ) ) {
			return true;
		}

		// Check for short tags.
		if ( preg_match( '/<\?[^x]/i', $content ) ) {
			return true;
		}

		// Common pattern: GIF89a followed by PHP.
		if ( preg_match( '/^GIF8[79]a.*<\?/s', $content ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Get scan statistics.
	 *
	 * @return array Statistics about the scanner configuration.
	 */
	public function get_scan_statistics() {
		$patterns = $this->get_malware_patterns();

		$total_patterns = 0;
		$categories     = array();

		foreach ( $patterns as $category => $pattern_list ) {
			$count = count( $pattern_list );
			$total_patterns += $count;
			$categories[ $category ] = $count;
		}

		return array(
			'total_patterns' => $total_patterns,
			'categories'     => $categories,
			'scan_areas'     => array(
				'WordPress root (loose PHP files)',
				'wp-admin',
				'wp-includes',
				'wp-content/uploads',
				'wp-content/themes',
				'wp-content/plugins',
			),
			'whitelisted_plugins' => count( $this->whitelisted_plugins ),
			'excluded_paths'      => count( $this->excluded_paths ),
		);
	}

	/**
	 * Check if a file path should be whitelisted (skipped during scanning).
	 *
	 * @param string $relative_path Relative path from ABSPATH.
	 * @return bool True if path should be skipped.
	 */
	public function is_whitelisted_path( $relative_path ) {
		// Check excluded paths (vendor, node_modules, tests, etc.).
		foreach ( $this->excluded_paths as $excluded ) {
			if ( false !== strpos( $relative_path, $excluded ) ) {
				return true;
			}
		}

		// Check if in a whitelisted plugin directory.
		if ( preg_match( '#^wp-content/plugins/([^/]+)/#', $relative_path, $matches ) ) {
			$plugin_slug = $matches[1];
			if ( in_array( $plugin_slug, $this->whitelisted_plugins, true ) ) {
				return true;
			}
		}

		// Check if in a whitelisted theme directory.
		if ( preg_match( '#^wp-content/themes/([^/]+)/#', $relative_path, $matches ) ) {
			$theme_slug = $matches[1];
			if ( in_array( $theme_slug, $this->whitelisted_themes, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if a file is in a known legitimate cache directory within uploads.
	 *
	 * Some plugins legitimately store PHP cache files in the uploads directory.
	 * This method identifies those known safe locations.
	 *
	 * @param string $file_path Full file path.
	 * @return bool True if in a legitimate cache directory.
	 */
	private function is_legitimate_upload_cache( $file_path ) {
		foreach ( $this->legitimate_upload_cache_paths as $cache_path ) {
			if ( false !== strpos( $file_path, $cache_path ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get refined patterns for plugin/theme scanning.
	 *
	 * These patterns focus on TRULY malicious indicators that are unlikely
	 * to appear in legitimate code. Generic functions like eval() and base64_decode()
	 * are NOT included here because many legitimate plugins use them.
	 *
	 * @return array Refined pattern groups.
	 */
	private function get_refined_patterns_for_plugins() {
		return array(
			// Critical: Definite backdoor patterns (these are ALWAYS malicious).
			'backdoor_patterns'    => array(
				'@eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'                        => __( 'Backdoor: eval with user input', 'atomicedge' ),
				'@eval\s*\(\s*base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'   => __( 'Backdoor: eval+base64 with user input', 'atomicedge' ),
				'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\('                   => __( 'Direct superglobal as function', 'atomicedge' ),
				'extract\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Dangerous extract from user input', 'atomicedge' ),
				'include\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Remote file inclusion via user input', 'atomicedge' ),
				'require\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Remote file inclusion via user input', 'atomicedge' ),
				'file_put_contents\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)'             => __( 'File write from user input', 'atomicedge' ),
				'assert\s*\(\s*\$_(?:GET|POST|REQUEST)'                              => __( 'Assert with user input', 'atomicedge' ),
				'preg_replace\s*\([^,]+["\'].*\/e["\'][^,]*,\s*\$_'                  => __( 'Preg replace eval with user input', 'atomicedge' ),
			),

			// Critical: Known webshell signatures (unique identifiers).
			'webshells'            => array(
				'c99shell'                                                           => __( 'C99 shell signature', 'atomicedge' ),
				'r57shell'                                                           => __( 'R57 shell signature', 'atomicedge' ),
				'b374k'                                                              => __( 'B374K shell signature', 'atomicedge' ),
				'FilesMan'                                                           => __( 'FilesMan shell signature', 'atomicedge' ),
				'WSO\s+[\d\.]+'                                                      => __( 'WSO shell signature', 'atomicedge' ),
				'Weevely'                                                            => __( 'Weevely shell signature', 'atomicedge' ),
				'Mister Spy'                                                         => __( 'Mister Spy shell signature', 'atomicedge' ),
				'Afghan Shell'                                                       => __( 'Afghan Shell signature', 'atomicedge' ),
				'SHELL_PASSWORD'                                                     => __( 'Shell password variable', 'atomicedge' ),
			),

			// Critical: WordPress-specific malware.
			'wordpress_malware'    => array(
				'wp-vcd'                                                             => __( 'WP-VCD malware', 'atomicedge' ),
				'class\.theme-modules\.php'                                          => __( 'WP-VCD theme modules', 'atomicedge' ),
				'class\.plugin-modules\.php'                                         => __( 'WP-VCD plugin modules', 'atomicedge' ),
				'wp-tmp\.php'                                                        => __( 'WP-VCD temp file', 'atomicedge' ),
				'tmpcontentx'                                                        => __( 'WP-VCD content injection', 'atomicedge' ),
				'wp_temp_setupx'                                                     => __( 'WP-VCD setup function', 'atomicedge' ),
				'derna\.top'                                                         => __( 'Known malware domain', 'atomicedge' ),
				'/\*\s*@noupdate\s*\*/'                                              => __( 'Plugin update suppression', 'atomicedge' ),
			),

			// High: Obfuscated code execution (multi-layer obfuscation is suspicious).
			'obfuscated_execution' => array(
				'eval\s*\(\s*gzinflate\s*\(\s*base64_decode'                         => __( 'Multi-layer obfuscation: eval+gzinflate+base64', 'atomicedge' ),
				'eval\s*\(\s*gzuncompress\s*\(\s*base64_decode'                      => __( 'Multi-layer obfuscation: eval+gzuncompress+base64', 'atomicedge' ),
				'eval\s*\(\s*str_rot13\s*\(\s*base64_decode'                         => __( 'Multi-layer obfuscation: eval+rot13+base64', 'atomicedge' ),
				'assert\s*\(\s*base64_decode'                                        => __( 'Obfuscated assert', 'atomicedge' ),
				'create_function\s*\([^)]*base64_decode'                             => __( 'Obfuscated create_function', 'atomicedge' ),
				'edoced_46esab'                                                      => __( 'Reversed base64_decode', 'atomicedge' ),
			),

			// High: Suspicious strings that are almost never legitimate.
			'suspicious_strings'   => array(
				'/etc/passwd'                                                        => __( 'Password file access attempt', 'atomicedge' ),
				'/etc/shadow'                                                        => __( 'Shadow file access attempt', 'atomicedge' ),
				'HACKED BY'                                                          => __( 'Defacement signature', 'atomicedge' ),
				'c999sh'                                                             => __( 'Shell variant', 'atomicedge' ),
				'r57sh'                                                              => __( 'Shell variant', 'atomicedge' ),
			),

			// Medium: Hex-encoded function calls (used to evade detection).
			'hex_obfuscation'      => array(
				'\\\\x65\\\\x76\\\\x61\\\\x6c'                                       => __( 'Hex-encoded eval', 'atomicedge' ),
				'\\\\x61\\\\x73\\\\x73\\\\x65\\\\x72\\\\x74'                         => __( 'Hex-encoded assert', 'atomicedge' ),
				'\\\\x73\\\\x79\\\\x73\\\\x74\\\\x65\\\\x6d'                         => __( 'Hex-encoded system', 'atomicedge' ),
				'\\\\x65\\\\x78\\\\x65\\\\x63'                                       => __( 'Hex-encoded exec', 'atomicedge' ),
			),
		);
	}

	/**
	 * Add a plugin to the whitelist.
	 *
	 * @param string $plugin_slug Plugin slug to whitelist.
	 * @return void
	 */
	public function add_whitelisted_plugin( $plugin_slug ) {
		if ( ! in_array( $plugin_slug, $this->whitelisted_plugins, true ) ) {
			$this->whitelisted_plugins[] = sanitize_file_name( $plugin_slug );
		}
	}

	/**
	 * Get the list of whitelisted plugins.
	 *
	 * @return array List of whitelisted plugin slugs.
	 */
	public function get_whitelisted_plugins() {
		return $this->whitelisted_plugins;
	}
}
