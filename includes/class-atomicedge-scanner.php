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
 */
class AtomicEdge_Scanner {

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
		// Set time limit for long-running scan.
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		@set_time_limit( 300 );

		$results = array(
			'started_at'     => current_time( 'mysql' ),
			'completed_at'   => '',
			'core_files'     => array(),
			'plugin_files'   => array(),
			'theme_files'    => array(),
			'suspicious'     => array(),
			'summary'        => array(),
		);

		// Scan WordPress core files.
		$core_issues = $this->scan_core_files();
		if ( false !== $core_issues ) {
			$results['core_files'] = $core_issues;
		}

		// Scan for suspicious files.
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

		$results['completed_at'] = current_time( 'mysql' );

		// Save results.
		update_option( 'atomicedge_scan_results', $results );
		update_option( 'atomicedge_last_scan', current_time( 'mysql' ) );

		AtomicEdge::log( 'Scan completed', $results['summary'] );

		return $results;
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

		$modified = array();

		foreach ( $checksums as $file => $expected_hash ) {
			$file_path = ABSPATH . $file;

			// Skip if file doesn't exist (might be optional).
			if ( ! file_exists( $file_path ) ) {
				continue;
			}

			// Skip wp-config.php as it's always modified.
			if ( 'wp-config.php' === $file || 'wp-config-sample.php' === $file ) {
				continue;
			}

			// Calculate actual hash.
			$actual_hash = md5_file( $file_path );

			if ( $actual_hash !== $expected_hash ) {
				$modified[] = array(
					'file'          => $file,
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
	 * Scan for suspicious files and patterns.
	 *
	 * @return array Array of suspicious findings.
	 */
	public function scan_suspicious_files() {
		$suspicious = array();

		// Suspicious patterns to look for.
		$dangerous_patterns = array(
			'base64_decode\s*\(' => 'Base64 decoding (potential obfuscation)',
			'eval\s*\('          => 'Eval function (code execution)',
			'gzinflate\s*\('     => 'Gzip inflate (potential obfuscation)',
			'str_rot13\s*\('     => 'ROT13 encoding (potential obfuscation)',
			'preg_replace.*\/e'  => 'Preg replace with eval modifier',
			'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(' => 'Direct superglobal execution',
		);

		// Directories to scan.
		$scan_dirs = array(
			ABSPATH . 'wp-content/uploads',
		);

		foreach ( $scan_dirs as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			$files = $this->get_php_files( $dir );

			foreach ( $files as $file ) {
				// Read file content.
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				$content = @file_get_contents( $file );

				if ( false === $content ) {
					continue;
				}

				// Check against patterns.
				foreach ( $dangerous_patterns as $pattern => $description ) {
					if ( preg_match( '/' . $pattern . '/i', $content ) ) {
						$suspicious[] = array(
							'file'        => str_replace( ABSPATH, '', $file ),
							'type'        => 'suspicious_pattern',
							'severity'    => 'critical',
							'pattern'     => $description,
						);
						break; // Only report once per file.
					}
				}
			}
		}

		// Check for PHP files in uploads directory.
		$uploads_dir = wp_upload_dir();
		if ( isset( $uploads_dir['basedir'] ) && is_dir( $uploads_dir['basedir'] ) ) {
			$upload_php_files = $this->get_php_files( $uploads_dir['basedir'] );

			foreach ( $upload_php_files as $file ) {
				// Any PHP file in uploads is suspicious.
				$suspicious[] = array(
					'file'     => str_replace( ABSPATH, '', $file ),
					'type'     => 'php_in_uploads',
					'severity' => 'high',
					'reason'   => __( 'PHP file found in uploads directory', 'atomicedge' ),
				);
			}
		}

		return $suspicious;
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
	 * Create baseline of current file hashes.
	 *
	 * @return bool True on success.
	 */
	public function create_baseline() {
		$baseline = array(
			'created_at' => current_time( 'mysql' ),
			'files'      => array(),
		);

		// Get all PHP files in wp-content.
		$wp_content_dir = WP_CONTENT_DIR;
		$files          = $this->get_php_files( $wp_content_dir );

		foreach ( $files as $file ) {
			$relative_path = str_replace( ABSPATH, '', $file );
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$hash = @md5_file( $file );

			if ( false !== $hash ) {
				$baseline['files'][ $relative_path ] = $hash;
			}
		}

		update_option( 'atomicedge_scan_baseline', $baseline );

		AtomicEdge::log( 'Baseline created', array( 'files' => count( $baseline['files'] ) ) );

		return true;
	}

	/**
	 * Compare current files against baseline.
	 *
	 * @return array Changes since baseline.
	 */
	public function compare_to_baseline() {
		$baseline = get_option( 'atomicedge_scan_baseline', array() );

		if ( empty( $baseline ) || ! isset( $baseline['files'] ) ) {
			return array(
				'error' => __( 'No baseline exists. Please create one first.', 'atomicedge' ),
			);
		}

		$changes = array(
			'modified' => array(),
			'added'    => array(),
			'removed'  => array(),
		);

		$current_files = array();
		$wp_content_dir = WP_CONTENT_DIR;
		$files          = $this->get_php_files( $wp_content_dir );

		foreach ( $files as $file ) {
			$relative_path = str_replace( ABSPATH, '', $file );
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$hash          = @md5_file( $file );

			if ( false === $hash ) {
				continue;
			}

			$current_files[ $relative_path ] = $hash;

			if ( ! isset( $baseline['files'][ $relative_path ] ) ) {
				$changes['added'][] = $relative_path;
			} elseif ( $baseline['files'][ $relative_path ] !== $hash ) {
				$changes['modified'][] = $relative_path;
			}
		}

		// Check for removed files.
		foreach ( $baseline['files'] as $path => $hash ) {
			if ( ! isset( $current_files[ $path ] ) ) {
				$changes['removed'][] = $path;
			}
		}

		return $changes;
	}
}
