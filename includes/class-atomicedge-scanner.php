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
	 * Transient key for the active resumable scan run.
	 */
	private const RESUMABLE_SCAN_STATE_KEY = 'atomicedge_scan_run_state';

	/**
	 * Prefix for cached WordPress core checksums used by a run.
	 */
	private const CORE_CHECKSUMS_KEY_PREFIX = 'atomicedge_core_checksums_';

	/**
	 * Prefix for cached integrity manifest used by a run.
	 */
	private const INTEGRITY_MANIFEST_KEY_PREFIX = 'atomicedge_integrity_manifest_';

	/**
	 * Relative path (from plugin dir) to the shipped integrity manifest.
	 */
	private const INTEGRITY_MANIFEST_REL_PATH = 'admin/assets/integrity/atomicedge-manifest.json';

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
		'/.git/',
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
	 * Cached pattern groups to avoid rebuilding arrays per file.
	 *
	 * @var array|null
	 */
	private $patterns_cache = null;

	/**
	 * Cached refined plugin/theme patterns.
	 *
	 * @var array|null
	 */
	private $refined_patterns_cache = null;

	/**
	 * Cached critical-only patterns for core directories.
	 *
	 * @var array|null
	 */
	private $critical_patterns_cache = null;

	/**
	 * Cached combined regex patterns per category for faster matching.
	 *
	 * @var array|null
	 */
	private $combined_patterns_cache = null;

	/**
	 * Quick rejection indicators - if none present, skip expensive regex.
	 *
	 * IMPORTANT: These must be UNCOMMON in legitimate code to be effective.
	 * Avoid common PHP functions like include(), require(), file_get_contents().
	 * Focus on:
	 * - Obfuscation techniques (base64_decode+eval combos, hex encoding)
	 * - Known shell signatures
	 * - Malware-specific strings
	 * - Dangerous function+superglobal combos
	 *
	 * @var array
	 */
	private $quick_rejection_indicators = array(
		// Code execution with dynamic input (the dangerous combo).
		'eval(',
		'assert(',
		'create_function(',
		// Shell execution functions.
		'shell_exec(',
		'passthru(',
		'proc_open(',
		'popen(',
		'pcntl_exec(',
		// Obfuscation patterns.
		'base64_decode(',
		'gzinflate(',
		'gzuncompress(',
		'str_rot13(',
		'convert_uudecode(',
		'edoced_46esab',  // Reversed base64_decode.
		// Hex-encoded strings (5+ consecutive \xNN patterns).
		'\\x',
		// Known webshell signatures.
		'c99shell',
		'r57shell',
		'b374k',
		'filesman',
		'wso shell',
		'weevely',
		'phpspy',
		// WordPress-specific malware.
		'wp-vcd',
		'tmpcontentx',
		'wp_temp_setupx',
		'derna.top',
		'@noupdate',
		'class.theme-modules',
		'class.plugin-modules',
		// Dangerous superglobal access patterns.
		'$_get[',
		'$_post[',
		'$_request[',
		'$_cookie[',
		// Defacement/hack signatures.
		'hacked by',
		'owned by',
		'backdoor',
		'rootkit',
		'webshell',
		// System file access.
		'/etc/passwd',
		'/etc/shadow',
		// Base64-encoded dangerous keywords.
		'ZXZhbCg',      // eval(
		'YXNzZXJ0',     // assert
		'c3lzdGVt',     // system
		'c2hlbGxfZXhlYw', // shell_exec
	);

	/**
	 * Diagnostics collected during the most recent scan.
	 *
	 * @var array
	 */
	private $scan_diagnostics = array();

	/**
	 * IDs of queue items to mark as done in batch at end of step.
	 *
	 * @var array
	 */
	private $pending_done_ids = array();

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
		$this->scan_diagnostics = $this->get_default_scan_diagnostics();

		// Initialize scan state for resumability.
		$scan_state = $this->get_scan_state();

		$results = array(
			'started_at'     => $scan_state ? $scan_state['started_at'] : current_time( 'mysql' ),
			'completed_at'   => '',
			'core_files'     => array(),
			'plugin_files'   => array(),
			'theme_files'    => array(),
			'suspicious'     => array(),
			'scan_diagnostics' => array(),
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

		$results['scan_diagnostics'] = $this->scan_diagnostics;

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
	 * Default diagnostics structure for a scan.
	 *
	 * @return array
	 */
	private function get_default_scan_diagnostics() {
		return array(
			'complete' => true,
			'stopped_early' => false,
			'stopped_early_reason' => '',
			'warnings' => array(),
			'counts' => array(
				'dirs_unreadable' => 0,
				'dirs_missing' => 0,
				'files_partially_scanned' => 0,
				'files_stat_failed' => 0,
				'files_read_failed' => 0,
				'files_skipped_whitelist' => 0,
				// Performance counters for optimization diagnostics.
				'files_quick_rejected' => 0,
				'files_regex_scanned' => 0,
			),
			'samples' => array(
				'unreadable_dirs' => array(),
				'oversized_files' => array(),
				'read_failed_files' => array(),
			),
			'areas' => array(
				'root' => array( 'php_files_found' => 0, 'php_files_scanned' => 0 ),
				'wp-admin' => array( 'php_files_found' => 0, 'php_files_scanned' => 0 ),
				'wp-includes' => array( 'php_files_found' => 0, 'php_files_scanned' => 0 ),
				'uploads' => array( 'php_files_found' => 0, 'php_files_scanned' => 0 ),
				'themes' => array( 'php_files_found' => 0, 'php_files_scanned' => 0 ),
				'plugins' => array( 'php_files_found' => 0, 'php_files_scanned' => 0 ),
			),
			// Performance timing (milliseconds).
			'timing' => array(
				'total_file_read_ms' => 0,
				'total_quick_check_ms' => 0,
				'total_regex_ms' => 0,
			),
		);
	}

	/**
	 * Record a scan warning.
	 *
	 * @param string $message Warning message.
	 * @return void
	 */
	private function add_scan_warning( $message ) {
		$this->scan_diagnostics['warnings'][] = $message;
		$this->scan_diagnostics['complete']   = false;
	}

	/**
	 * Mark scan as stopped early.
	 *
	 * @param string $reason Reason code.
	 * @return void
	 */
	private function mark_stopped_early( $reason ) {
		$this->scan_diagnostics['complete']             = false;
		$this->scan_diagnostics['stopped_early']        = true;
		$this->scan_diagnostics['stopped_early_reason'] = $reason;
		$this->add_scan_warning( __( 'Scan stopped early; results may be incomplete.', 'atomic-edge-security' ) );
	}

	/**
	 * Increment a diagnostics count and optionally store a sample path.
	 *
	 * @param string      $key Count key.
	 * @param string|null $sampleKey Sample list key.
	 * @param string|null $sampleValue Sample value.
	 * @return void
	 */
	private function bump_diag_count( $key, $sampleKey = null, $sampleValue = null ) {
		if ( ! isset( $this->scan_diagnostics['counts'][ $key ] ) ) {
			$this->scan_diagnostics['counts'][ $key ] = 0;
		}
		$this->scan_diagnostics['counts'][ $key ]++;

		if ( $sampleKey && $sampleValue && isset( $this->scan_diagnostics['samples'][ $sampleKey ] ) ) {
			if ( count( $this->scan_diagnostics['samples'][ $sampleKey ] ) < 5 ) {
				$this->scan_diagnostics['samples'][ $sampleKey ][] = $sampleValue;
			}
		}
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
	 * Get optimal time budget for a scan step based on server configuration.
	 *
	 * Adapts to the server's max_execution_time setting to maximize work per step
	 * while staying safe from timeouts. The goal is to do as much work as possible
	 * per HTTP request to minimize AJAX round-trip overhead.
	 *
	 * @return int Time budget in seconds (5-45 range).
	 */
	private function get_optimal_time_budget() {
		// Get max_execution_time (0 means no limit).
		$max_time = (int) ini_get( 'max_execution_time' );

		// If unlimited or very high (local dev, CLI, or generous hosting), use 45s.
		// This dramatically reduces the number of AJAX round-trips needed.
		// 45s is safe even on most restrictive nginx/Apache timeouts (typically 60s+).
		if ( 0 === $max_time || $max_time >= 120 ) {
			return 45;
		}

		// For typical shared hosting (30s), use 50% to be safe (15s).
		// For restrictive hosting (15-20s), use 60% to balance safety with progress.
		$budget = (int) ( $max_time * 0.5 );

		// Clamp to reasonable range: minimum 5s, maximum 45s.
		// Raising the max from 25s to 45s allows more work on capable servers.
		return max( 5, min( 45, $budget ) );
	}

	/**
	 * Get normalized WordPress root path with trailing slash.
	 *
	 * Uses WordPress function APIs where available, avoiding direct use of internal constants.
	 *
	 * @return string
	 */
	private function get_wp_root_path() {
		// Ensure get_home_path() is available by loading the admin file.php if needed.
		// This is the WordPress-recommended way to get the installation root path.
		if ( ! function_exists( 'get_home_path' ) ) {
			// ABSPATH is the only internal constant allowed for building paths to admin files.
			// Per WordPress plugin guidelines, we check file existence for test compatibility.
			$file_php = ABSPATH . 'wp-admin/includes/file.php';
			if ( file_exists( $file_php ) ) {
				require_once $file_php;
			}
		}

		// Now get_home_path() should be available.
		if ( function_exists( 'get_home_path' ) ) {
			return trailingslashit( wp_normalize_path( get_home_path() ) );
		}

		// Ultimate fallback: use ABSPATH (the WordPress installation directory).
		return trailingslashit( wp_normalize_path( ABSPATH ) );
	}

	/**
	 * Get normalized wp-admin path.
	 *
	 * @return string
	 */
	private function get_wp_admin_path() {
		return wp_normalize_path( $this->get_wp_root_path() . 'wp-admin' );
	}

	/**
	 * Get normalized wp-includes path.
	 *
	 * @return string
	 */
	private function get_wp_includes_path() {
		// Use the standard 'wp-includes' directory name.
		// This is always 'wp-includes' in all WordPress installations.
		return wp_normalize_path( $this->get_wp_root_path() . 'wp-includes' );
	}

	/**
	 * Get normalized plugins directory path.
	 *
	 * Uses plugin_dir_path() API to derive the plugins directory.
	 *
	 * @return string
	 */
	private function get_wp_plugins_path() {
		// ATOMICEDGE_PLUGIN_DIR is defined using plugin_dir_path(__FILE__) in the main plugin file.
		// Go up one level to get the plugins directory.
		return wp_normalize_path( dirname( ATOMICEDGE_PLUGIN_DIR ) );
	}

	/**
	 * Get normalized themes directory path.
	 *
	 * @return string
	 */
	private function get_wp_themes_path() {
		return wp_normalize_path( get_theme_root() );
	}

	/**
	 * Get normalized mu-plugins directory path.
	 *
	 * Uses content_url() path derivation to avoid internal constants.
	 *
	 * @return string
	 */
	private function get_wp_mu_plugins_path() {
		// Derive wp-content directory from plugins path (go up one level).
		$content_dir = dirname( $this->get_wp_plugins_path() );
		return wp_normalize_path( trailingslashit( $content_dir ) . 'mu-plugins' );
	}

	/**
	 * Get normalized uploads base directory path.
	 *
	 * Uses wp_upload_dir() API which is the recommended approach.
	 *
	 * @return string
	 */
	private function get_wp_uploads_path() {
		$uploads = function_exists( 'wp_get_upload_dir' ) ? wp_get_upload_dir() : wp_upload_dir();
		if ( isset( $uploads['basedir'] ) ) {
			return wp_normalize_path( $uploads['basedir'] );
		}
		// Fallback: derive wp-content from plugins path.
		$content_dir = dirname( $this->get_wp_plugins_path() );
		return wp_normalize_path( trailingslashit( $content_dir ) . 'uploads' );
	}

	/**
	 * Convert an absolute path to a root-relative path.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function make_relative_to_root( $path ) {
		$root_path = $this->get_wp_root_path();
		return ltrim( str_replace( $root_path, '', wp_normalize_path( $path ) ), '/' );
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
	 * Start (or resume) a resumable scan run.
	 *
	 * @return array Run state.
	 */
	public function start_resumable_scan( $scan_mode = 'php', $options = array() ) {
		$this->ensure_queue_table_exists();

		$scan_mode = is_string( $scan_mode ) ? $scan_mode : 'all';
		$scan_mode = in_array( $scan_mode, array( 'php', 'all' ), true ) ? $scan_mode : 'all';
		$options = is_array( $options ) ? $options : array();
		$verify_integrity = ! empty( $options['verify_integrity'] );

		$state = $this->get_resumable_scan_state();
		if ( is_array( $state ) && isset( $state['run_id'], $state['status'] ) && 'running' === $state['status'] ) {
			return $state;
		}

		$this->scan_diagnostics = $this->get_default_scan_diagnostics();

		$run_id = function_exists( 'wp_generate_uuid4' ) ? wp_generate_uuid4() : hash( 'sha256', uniqid( 'atomicedge_scan_', true ) );

		$results = array(
			'started_at'       => current_time( 'mysql' ),
			'completed_at'     => '',
			'core_files'       => array(),
			'plugin_files'     => array(),
			'theme_files'      => array(),
			'suspicious'       => array(),
			'scan_diagnostics' => $this->scan_diagnostics,
			'summary'          => array(),
			'scan_stats'       => array(
				'files_scanned' => 0,
				'files_total'   => 0,
				'time_elapsed'  => 0,
				'memory_peak'   => 0,
			),
		);

		$results['scan_stats']['files_total'] = $this->estimate_total_files_for_scan( $scan_mode );

		$state = array(
			'run_id'     => $run_id,
			'status'     => 'running',
			'stage'      => $verify_integrity ? 'integrity' : ( ( 'php' === $scan_mode ) ? 'queue' : 'core' ),
			'scan_mode'  => $scan_mode,
			'verify_integrity' => (bool) $verify_integrity,
			'started_at' => $results['started_at'],
			'updated_at' => time(),
			'core_offset' => 0,
			'core_total'  => 0,
			'integrity_offset' => 0,
			'integrity_total'  => 0,
			'progress_floor' => 0,
			'results'     => $results,
			'diagnostics' => $this->scan_diagnostics,
		);

		if ( $verify_integrity ) {
			$manifest = $this->get_integrity_manifest();
			if ( ! is_array( $manifest ) || empty( $manifest['files'] ) || ! is_array( $manifest['files'] ) ) {
				$this->add_scan_warning( __( 'Integrity verification was enabled but the manifest could not be loaded; integrity checks were skipped.', 'atomic-edge-security' ) );
				$state['verify_integrity'] = false;
				$state['stage'] = ( 'php' === $scan_mode ) ? 'queue' : 'core';
			} else {
				set_transient( self::INTEGRITY_MANIFEST_KEY_PREFIX . $run_id, $manifest, HOUR_IN_SECONDS );
				$state['integrity_total'] = count( array_keys( $manifest['files'] ) );
				$state['results']['integrity_issues'] = array();
			}
		}

		if ( 'all' === $scan_mode ) {
			// Fetch and cache core checksums for incremental scanning.
			global $wp_version;
			$checksums = $this->get_core_checksums( $wp_version );
			if ( false === $checksums || ! is_array( $checksums ) ) {
				$this->add_scan_warning( __( 'Could not fetch WordPress core checksums; core integrity checks were skipped.', 'atomic-edge-security' ) );
				if ( ! $state['verify_integrity'] ) {
					$state['stage'] = 'queue';
				}
			} else {
				set_transient( self::CORE_CHECKSUMS_KEY_PREFIX . $run_id, $checksums, HOUR_IN_SECONDS );
				$state['core_total'] = count( $checksums );
			}
		}

		// Seed the DB-backed queue.
		$this->seed_queue_for_run( $run_id, $scan_mode );

		$state['diagnostics'] = $this->scan_diagnostics;
		$state['results']['scan_diagnostics'] = $this->scan_diagnostics;

		$this->save_resumable_scan_state( $state );
		return $state;
	}

	/**
	 * Perform a single time-sliced scan step.
	 *
	 * @param string $run_id Optional run id.
	 * @param int    $time_budget_seconds Time budget (0 = auto-detect based on server config).
	 * @return array Updated run state.
	 */
	public function step_resumable_scan( $run_id = '', $time_budget_seconds = 0 ) {
		$this->ensure_queue_table_exists();

		$state = $this->get_resumable_scan_state();
		if ( ! is_array( $state ) || ! isset( $state['run_id'] ) ) {
			return $this->start_resumable_scan();
		}

		if ( $run_id && $run_id !== $state['run_id'] ) {
			// If the caller is referencing an old run, just return the current run state.
			return $state;
		}

		if ( isset( $state['status'] ) && 'running' !== $state['status'] ) {
			return $state;
		}

		$this->scan_diagnostics = isset( $state['diagnostics'] ) && is_array( $state['diagnostics'] )
			? $state['diagnostics']
			: $this->get_default_scan_diagnostics();

		$started = microtime( true );

		// Auto-detect optimal time budget based on server configuration.
		if ( $time_budget_seconds <= 0 ) {
			$time_budget_seconds = $this->get_optimal_time_budget();
		}
		$time_budget_seconds = max( 1, (int) $time_budget_seconds );

		// Store the time budget in state so JS can adapt polling interval.
		$state['time_budget'] = $time_budget_seconds;

		if ( ! isset( $state['log'] ) || ! is_array( $state['log'] ) ) {
			$state['log'] = array();
		}
		if ( ! isset( $state['current_item'] ) || ! is_array( $state['current_item'] ) ) {
			$state['current_item'] = array();
		}

		$this->append_scan_log( $state, sprintf( '[%s] Step start (stage=%s)', current_time( 'mysql' ), isset( $state['stage'] ) ? (string) $state['stage'] : '' ) );

		// Reset pending done queue for this step.
		$this->pending_done_ids = array();

		try {
			$work_iterations = 0;
			while ( $work_iterations < 10 && ( microtime( true ) - $started ) < $time_budget_seconds ) {
				$work_iterations++;

				if ( 'integrity' === $state['stage'] ) {
					$did_integrity_work = $this->process_integrity_step( $state, $started, $time_budget_seconds );
					if ( ! $did_integrity_work ) {
						$this->append_scan_log( $state, sprintf( '[%s] Integrity verification complete', current_time( 'mysql' ) ) );
						$state['stage'] = ( isset( $state['scan_mode'] ) && 'all' === $state['scan_mode'] ) ? 'core' : 'queue';
					}
					continue;
				}

				if ( 'core' === $state['stage'] ) {
					$did_core_work = $this->process_core_checksums_step( $state, $started, $time_budget_seconds );
					if ( ! $did_core_work ) {
						$this->append_scan_log( $state, sprintf( '[%s] Core checksums complete', current_time( 'mysql' ) ) );
						$state['stage'] = 'queue';
					}
					continue;
				}

				// BATCH PROCESSING: Claim multiple items at once.
				$batch_size = 100; // Process up to 100 files per batch claim.
				$items = $this->claim_batch_queue_items( $state['run_id'], $batch_size );

				if ( empty( $items ) ) {
					// Flush any pending done items before finalizing.
					$this->flush_pending_done_items();
					// No more work.
					$state = $this->finalize_run_if_done( $state );
					break;
				}

				// Process all items in the batch.
				foreach ( $items as $item ) {
					// Check time budget within batch processing.
					if ( ( microtime( true ) - $started ) >= $time_budget_seconds ) {
						// Flush completed items so far.
						$this->flush_pending_done_items();
						break 2; // Exit both foreach and while.
					}

					$this->process_queue_item_batched( $item, $state );
				}

				// Flush completed items after each batch.
				$this->flush_pending_done_items();
			}
		} catch ( \Throwable $e ) {
			// Flush any pending items before error handling.
			$this->flush_pending_done_items();
			$state['status'] = 'error';
			$state['error']  = $e->getMessage();
			$this->add_scan_warning( __( 'Scan failed due to an unexpected error; results may be incomplete.', 'atomic-edge-security' ) );
			$this->append_scan_log( $state, sprintf( '[%s] Error: %s', current_time( 'mysql' ), $e->getMessage() ) );
		}

		// Final flush for any remaining items.
		$this->flush_pending_done_items();

		$state['updated_at'] = time();
		$state['diagnostics'] = $this->scan_diagnostics;
		$state['results']['scan_diagnostics'] = $this->scan_diagnostics;

		$counts = $this->get_queue_counts( $state['run_id'] );
		$state['queue_counts'] = $counts;

		$progress = $this->calculate_resumable_progress( $state, $counts );
		if ( ! isset( $state['progress_floor'] ) ) {
			$state['progress_floor'] = 0;
		}
		$progress = max( (int) $state['progress_floor'], (int) $progress );
		$state['progress_floor'] = $progress;
		$state['progress'] = $progress;
		$this->add_eta_estimate( $state );

		$this->save_resumable_scan_state( $state );
		return $state;
	}

	/**
	 * Append a scan log entry to the run state.
	 *
	 * @param array  $state Run state (by reference).
	 * @param string $message Log message.
	 * @return void
	 */
	private function append_scan_log( &$state, $message ) {
		if ( ! isset( $state['log'] ) || ! is_array( $state['log'] ) ) {
			$state['log'] = array();
		}

		$state['log'][] = (string) $message;
		if ( count( $state['log'] ) > 50 ) {
			$state['log'] = array_slice( $state['log'], -50 );
		}
	}

	/**
	 * Get the current resumable scan status.
	 *
	 * @param string $run_id Optional run id.
	 * @return array
	 */
	public function get_resumable_scan_status( $run_id = '' ) {
		$state = $this->get_resumable_scan_state();
		if ( ! is_array( $state ) ) {
			return array( 'status' => 'idle' );
		}

		if ( $run_id && isset( $state['run_id'] ) && $run_id !== $state['run_id'] ) {
			return $state;
		}

		$counts = $this->get_queue_counts( $state['run_id'] );
		$state['queue_counts'] = $counts;

		$progress = $this->calculate_resumable_progress( $state, $counts );
		if ( isset( $state['progress_floor'] ) ) {
			$progress = max( (int) $state['progress_floor'], (int) $progress );
			$state['progress_floor'] = $progress;
		}
		$state['progress'] = $progress;
		$this->add_eta_estimate( $state );

		return $state;
	}

	/**
	 * Calculate resumable scan progress across integrity/core/queue stages.
	 *
	 * @param array $state Run state.
	 * @param array $counts Queue counts.
	 * @return int Progress 0-99.
	 */
	private function calculate_resumable_progress( $state, $counts ) {
		$stage = isset( $state['stage'] ) ? (string) $state['stage'] : '';
		$scan_mode = isset( $state['scan_mode'] ) ? (string) $state['scan_mode'] : 'php';
		$verify_integrity = ! empty( $state['verify_integrity'] );

		$base = 0;

		if ( $verify_integrity ) {
			$span = 5;
			$total = isset( $state['integrity_total'] ) ? (int) $state['integrity_total'] : 0;
			$offset = isset( $state['integrity_offset'] ) ? (int) $state['integrity_offset'] : 0;
			if ( 'integrity' === $stage && $total > 0 ) {
				return (int) min( 99, floor( min( $span - 1, ( $offset / max( 1, $total ) ) * $span ) ) );
			}
			$base += $span;
		}

		if ( 'all' === $scan_mode ) {
			$span = 30;
			$total = isset( $state['core_total'] ) ? (int) $state['core_total'] : 0;
			$offset = isset( $state['core_offset'] ) ? (int) $state['core_offset'] : 0;
			if ( 'core' === $stage && $total > 0 ) {
				return (int) min( 99, $base + floor( min( $span - 1, ( $offset / max( 1, $total ) ) * $span ) ) );
			}
			if ( 'core' !== $stage ) {
				$base += $span;
			}
		}

		$remaining = 99 - $base;
		if ( $remaining < 0 ) {
			$remaining = 0;
		}

		$progress = $base;
		$files_total = isset( $state['results']['scan_stats']['files_total'] ) ? (int) $state['results']['scan_stats']['files_total'] : 0;
		$files_scanned = isset( $state['results']['scan_stats']['files_scanned'] ) ? (int) $state['results']['scan_stats']['files_scanned'] : 0;
		if ( $files_total > 0 ) {
			$ratio = $files_scanned / max( 1, $files_total );
			$ratio = max( 0, min( 1, $ratio ) );
			$progress += (int) floor( min( $remaining, $ratio * $remaining ) );
		} elseif ( isset( $counts['total'] ) && (int) $counts['total'] > 0 ) {
			$ratio = (int) $counts['done'] / max( 1, (int) $counts['total'] );
			$progress += (int) floor( min( $remaining, $ratio * $remaining ) );
		}

		return (int) max( 0, min( 99, $progress ) );
	}

	/**
	 * Estimate total PHP files to scan for progress/ETA.
	 *
	 * @param string $scan_mode Scan mode.
	 * @return int
	 */
	private function estimate_total_files_for_scan( $scan_mode ) {
		$scan_mode = is_string( $scan_mode ) ? $scan_mode : 'all';
		$scan_mode = in_array( $scan_mode, array( 'php', 'all' ), true ) ? $scan_mode : 'all';

		$total = 0;
		$total += count( $this->get_root_php_files() );
		$total += $this->count_php_files_for_dir( $this->get_wp_plugins_path(), 'plugins' );
		$total += $this->count_php_files_for_dir( $this->get_wp_themes_path(), 'themes' );
		$total += $this->count_php_files_for_dir( $this->get_wp_mu_plugins_path(), 'mu-plugins' );

		if ( 'all' === $scan_mode ) {
			$total += $this->count_php_files_for_dir( $this->get_wp_admin_path(), 'wp-admin' );
			$total += $this->count_php_files_for_dir( $this->get_wp_includes_path(), 'wp-includes' );
			$total += $this->count_php_files_for_dir( $this->get_wp_uploads_path(), 'uploads' );
		}

		return max( 0, (int) $total );
	}

	/**
	 * Count PHP files in a directory with scanner exclusions applied.
	 *
	 * @param string $dir Directory path.
	 * @param string $area Scan area.
	 * @return int
	 */
	private function count_php_files_for_dir( $dir, $area ) {
		if ( ! $dir || ! is_dir( $dir ) || ! is_readable( $dir ) ) {
			return 0;
		}

		$total = 0;

		try {
			$iterator = new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS );
			$filter = new RecursiveCallbackFilterIterator(
				$iterator,
				function ( $current ) {
					$path = wp_normalize_path( $current->getPathname() );
					$relative = $this->make_relative_to_root( $path );
					if ( $current->isDir() ) {
						return ! $this->is_whitelisted_path( $relative . '/' );
					}
					return true;
				}
			);
			$iter = new RecursiveIteratorIterator( $filter, RecursiveIteratorIterator::SELF_FIRST );
		} catch ( UnexpectedValueException $e ) {
			return 0;
		}

		foreach ( $iter as $file ) {
			if ( ! $file->isFile() || ! preg_match( '/\.php$/i', $file->getFilename() ) ) {
				continue;
			}

			$path = wp_normalize_path( $file->getPathname() );
			$relative = $this->make_relative_to_root( $path );
			if ( $this->is_whitelisted_path( $relative ) ) {
				continue;
			}
			if ( 'uploads' === $area && $this->is_legitimate_upload_cache( $path ) ) {
				continue;
			}

			$total++;
		}

		return $total;
	}

	/**
	 * Add ETA estimates to scan state if possible.
	 *
	 * @param array $state Scan state (by reference).
	 * @return void
	 */
	private function add_eta_estimate( &$state ) {
		$eta_seconds = $this->calculate_eta_seconds( $state );
		if ( null === $eta_seconds ) {
			$state['eta_seconds'] = null;
			$state['eta_label'] = '';
			return;
		}

		$state['eta_seconds'] = $eta_seconds;
		$state['eta_label'] = $this->format_eta_label( $eta_seconds );
	}

	/**
	 * Calculate ETA in seconds based on scan rate.
	 *
	 * @param array $state Scan state.
	 * @return int|null
	 */
	private function calculate_eta_seconds( $state ) {
		$total = isset( $state['results']['scan_stats']['files_total'] ) ? (int) $state['results']['scan_stats']['files_total'] : 0;
		$scanned = isset( $state['results']['scan_stats']['files_scanned'] ) ? (int) $state['results']['scan_stats']['files_scanned'] : 0;
		if ( $total <= 0 || $scanned < 5 ) {
			return null;
		}

		$started_at = isset( $state['results']['started_at'] ) ? strtotime( (string) $state['results']['started_at'] ) : 0;
		$elapsed = $started_at > 0 ? ( time() - $started_at ) : 0;
		if ( $elapsed <= 2 ) {
			return null;
		}

		$rate = $scanned / max( 1, $elapsed );
		if ( $rate <= 0 ) {
			return null;
		}

		$remaining = max( 0, $total - $scanned );
		return (int) round( $remaining / $rate );
	}

	/**
	 * Format ETA label (e.g. 2m 10s).
	 *
	 * @param int $seconds Remaining seconds.
	 * @return string
	 */
	private function format_eta_label( $seconds ) {
		$seconds = max( 0, (int) $seconds );
		$hours = (int) floor( $seconds / 3600 );
		$minutes = (int) floor( ( $seconds % 3600 ) / 60 );
		$secs = (int) ( $seconds % 60 );

		if ( $hours > 0 ) {
			return sprintf( '%dh %dm', $hours, $minutes );
		}
		if ( $minutes > 0 ) {
			return sprintf( '%dm %ds', $minutes, $secs );
		}
		return sprintf( '%ds', $secs );
	}

	/**
	 * Load the shipped integrity manifest.
	 *
	 * @return array|false
	 */
	private function get_integrity_manifest() {
		if ( ! defined( 'ATOMICEDGE_PLUGIN_DIR' ) ) {
			return false;
		}

		$path = rtrim( ATOMICEDGE_PLUGIN_DIR, '/' ) . '/' . self::INTEGRITY_MANIFEST_REL_PATH;
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents
		$raw = @file_get_contents( $path );
		if ( false === $raw ) {
			return false;
		}

		$manifest = json_decode( $raw, true );
		if ( ! is_array( $manifest ) ) {
			return false;
		}

		return $manifest;
	}

	/**
	 * Process an incremental chunk of integrity verification.
	 */
	private function process_integrity_step( &$state, $started, $time_budget_seconds ) {
		$manifest = get_transient( self::INTEGRITY_MANIFEST_KEY_PREFIX . $state['run_id'] );
		if ( ! is_array( $manifest ) || empty( $manifest['files'] ) || ! is_array( $manifest['files'] ) ) {
			return false;
		}
		if ( ! defined( 'ATOMICEDGE_PLUGIN_DIR' ) ) {
			return false;
		}

		$files = array_keys( $manifest['files'] );
		$total = count( $files );
		$offset = isset( $state['integrity_offset'] ) ? (int) $state['integrity_offset'] : 0;
		if ( $offset >= $total ) {
			delete_transient( self::INTEGRITY_MANIFEST_KEY_PREFIX . $state['run_id'] );
			return false;
		}

		$batch = array_slice( $files, $offset, 50 );
		foreach ( $batch as $rel_path ) {
			if ( ( microtime( true ) - $started ) >= $time_budget_seconds ) {
				break;
			}

			$expected = isset( $manifest['files'][ $rel_path ] ) ? (string) $manifest['files'][ $rel_path ] : '';
			$abs_path = rtrim( ATOMICEDGE_PLUGIN_DIR, '/' ) . '/' . ltrim( (string) $rel_path, '/' );

			if ( ! file_exists( $abs_path ) ) {
				$state['results']['integrity_issues'][] = array(
					'file'     => (string) $rel_path,
					'type'     => 'missing',
					'severity' => 'high',
					'reason'   => __( 'File missing', 'atomic-edge-security' ),
				);
				$offset++;
				continue;
			}

			if ( ! is_readable( $abs_path ) ) {
				$state['results']['integrity_issues'][] = array(
					'file'     => (string) $rel_path,
					'type'     => 'unreadable',
					'severity' => 'high',
					'reason'   => __( 'File not readable', 'atomic-edge-security' ),
				);
				$offset++;
				continue;
			}

			$actual = hash_file( 'sha256', $abs_path );
			if ( false === $actual ) {
				$state['results']['integrity_issues'][] = array(
					'file'     => (string) $rel_path,
					'type'     => 'hash_failed',
					'severity' => 'high',
					'reason'   => __( 'Could not compute file hash', 'atomic-edge-security' ),
				);
				$offset++;
				continue;
			}

			if ( $expected && $expected !== $actual ) {
				$state['results']['integrity_issues'][] = array(
					'file'          => (string) $rel_path,
					'type'          => 'mismatch',
					'severity'      => 'high',
					'reason'        => __( 'Hash mismatch', 'atomic-edge-security' ),
					'expected_hash' => $expected,
					'actual_hash'   => $actual,
				);
			}

			$offset++;
		}

		$state['integrity_offset'] = $offset;
		$state['integrity_total'] = $total;
		if ( $offset >= $total ) {
			delete_transient( self::INTEGRITY_MANIFEST_KEY_PREFIX . $state['run_id'] );
			return false;
		}

		return true;
	}

	/**
	 * Stop the current resumable scan.
	 *
	 * @return array
	 */
	public function stop_resumable_scan() {
		$state = $this->get_resumable_scan_state();
		if ( ! is_array( $state ) ) {
			return array( 'status' => 'idle' );
		}

		$state['status'] = 'stopped';
		$state['updated_at'] = time();
		$this->scan_diagnostics = isset( $state['diagnostics'] ) ? $state['diagnostics'] : $this->get_default_scan_diagnostics();
		$this->mark_stopped_early( 'manual_stop' );
		$state['diagnostics'] = $this->scan_diagnostics;
		$state['results']['scan_diagnostics'] = $this->scan_diagnostics;
		$this->save_resumable_scan_state( $state );
		return $state;
	}

	/**
	 * Cancel the current scan run and clear its cached state.
	 *
	 * @param string $run_id Optional run id (for safety).
	 * @return array
	 */
	public function cancel_resumable_scan( $run_id = '' ) {
		$state = $this->get_resumable_scan_state();
		if ( ! is_array( $state ) ) {
			return array( 'status' => 'idle' );
		}

		$current_run_id = isset( $state['run_id'] ) ? (string) $state['run_id'] : '';
		if ( '' !== $run_id && $current_run_id && $run_id !== $current_run_id ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Run id does not match the active scan.', 'atomic-edge-security' ),
			);
		}

		$this->scan_diagnostics = isset( $state['diagnostics'] ) && is_array( $state['diagnostics'] )
			? $state['diagnostics']
			: $this->get_default_scan_diagnostics();
		$this->mark_stopped_early( 'manual_cancel' );

		// Cleanup artifacts and clear state.
		if ( $current_run_id ) {
			$this->cleanup_run_artifacts( $current_run_id );
		}
		$this->clear_resumable_scan_state();
		// Legacy transient key (older scanner versions).
		delete_transient( 'atomicedge_scan_state' );

		return array(
			'status' => 'cancelled',
			'run_id' => $current_run_id,
		);
	}

	/**
	 * Reset scan state/cache so a new scan starts fresh.
	 *
	 * @return array
	 */
	public function reset_resumable_scan() {
		$state = $this->get_resumable_scan_state();
		$run_id = is_array( $state ) && isset( $state['run_id'] ) ? (string) $state['run_id'] : '';
		if ( $run_id ) {
			$this->cleanup_run_artifacts( $run_id );
		}

		$this->clear_resumable_scan_state();
		delete_transient( 'atomicedge_scan_state' );
		delete_option( 'atomicedge_scan_results' );
		delete_option( 'atomicedge_last_scan' );

		return array( 'status' => 'reset' );
	}

	/**
	 * Run a quick debug test scan on a limited number of files.
	 *
	 * This method runs a REAL scan (same code path as full scan) but limited
	 * to a small number of files for quick testing during development.
	 *
	 * Only works when WP_DEBUG is true.
	 *
	 * @param int $file_limit Maximum number of files to scan (default 500).
	 * @return array Test results with timing and file counts.
	 */
	public function run_debug_test( $file_limit = 500 ) {
		$file_limit = max( 100, min( 2000, (int) $file_limit ) );

		$results = array(
			'test_type'            => 'debug_scan',
			'file_limit'           => $file_limit,
			'files_found'          => 0,
			'files_scanned'        => 0,
			'files_quick_rejected' => 0,
			'files_regex_scanned'  => 0,
			'issues_found'         => array(),
			'timing'               => array(
				'start'          => gmdate( 'Y-m-d H:i:s' ),
				'end'            => '',
				'total_seconds'  => 0,
				'enumeration_ms' => 0,
				'scanning_ms'    => 0,
			),
			'server_info'          => array(
				'php_version'        => PHP_VERSION,
				'max_execution_time' => (int) ini_get( 'max_execution_time' ),
				'memory_limit'       => ini_get( 'memory_limit' ),
			),
		);

		// Initialize fresh diagnostics.
		$this->scan_diagnostics = $this->get_default_scan_diagnostics();

		$overall_start = microtime( true );

		// PHASE 1: Enumerate files from plugins directory.
		$enum_start = microtime( true );
		$files = $this->collect_test_files( $file_limit );
		$results['timing']['enumeration_ms'] = round( ( microtime( true ) - $enum_start ) * 1000, 1 );
		$results['files_found'] = count( $files );

		if ( empty( $files ) ) {
			$results['error'] = 'No PHP files found';
			return $results;
		}

		// PHASE 2: Scan files using the REAL scan logic.
		$scan_start = microtime( true );
		$patterns = $this->get_refined_patterns_for_plugins();

		foreach ( $files as $filepath ) {
			$result = $this->scan_file_for_patterns( $filepath, $patterns, false );
			if ( false !== $result && is_array( $result ) ) {
				$relative = $this->make_relative_to_root( $filepath );
				$results['issues_found'][] = array(
					'file'    => $relative,
					'type'    => $result['type'] ?? 'unknown',
					'pattern' => $result['pattern'] ?? '',
				);
			}
		}

		$results['timing']['scanning_ms'] = round( ( microtime( true ) - $scan_start ) * 1000, 1 );

		// Collect counts from diagnostics.
		$results['files_scanned'] = count( $files );
		$results['files_quick_rejected'] = $this->scan_diagnostics['counts']['files_quick_rejected'] ?? 0;
		$results['files_regex_scanned'] = $this->scan_diagnostics['counts']['files_regex_scanned'] ?? 0;

		// Final timing.
		$total_seconds = microtime( true ) - $overall_start;
		$results['timing']['end'] = gmdate( 'Y-m-d H:i:s' );
		$results['timing']['total_seconds'] = round( $total_seconds, 2 );

		// Calculate rate.
		if ( $total_seconds > 0 ) {
			$results['files_per_second'] = round( count( $files ) / $total_seconds, 1 );
		}

		// Quick rejection rate.
		$results['quick_rejection_rate'] = count( $files ) > 0
			? round( ( $results['files_quick_rejected'] / count( $files ) ) * 100, 1 ) . '%'
			: '0%';

		return $results;
	}

	/**
	 * Collect PHP files for debug testing.
	 *
	 * @param int $limit Maximum files to collect.
	 * @return array Array of file paths.
	 */
	private function collect_test_files( $limit ) {
		$files = array();
		$plugins_dir = $this->get_wp_plugins_path();

		if ( ! is_dir( $plugins_dir ) || ! is_readable( $plugins_dir ) ) {
			return $files;
		}

		try {
			$iterator = new RecursiveDirectoryIterator(
				$plugins_dir,
				RecursiveDirectoryIterator::SKIP_DOTS
			);
			$filter = new RecursiveCallbackFilterIterator(
				$iterator,
				function ( $current ) {
					$path = wp_normalize_path( $current->getPathname() );
					$relative = $this->make_relative_to_root( $path );
					if ( $current->isDir() ) {
						return ! $this->is_whitelisted_path( $relative . '/' );
					}
					return true;
				}
			);
			$iter = new RecursiveIteratorIterator(
				$filter,
				RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( UnexpectedValueException $e ) {
			return $files;
		}

		foreach ( $iter as $file ) {
			if ( count( $files ) >= $limit ) {
				break;
			}

			if ( ! $file->isFile() ) {
				continue;
			}

			if ( ! preg_match( '/\.php$/i', $file->getFilename() ) ) {
				continue;
			}

			$path = wp_normalize_path( $file->getPathname() );
			$relative = $this->make_relative_to_root( $path );

			if ( $this->is_whitelisted_path( $relative ) ) {
				continue;
			}

			$files[] = $path;
		}

		return $files;
	}

	/**
	 * Cleanup cached transients and DB queue rows for a run.
	 *
	 * @param string $run_id Run id.
	 * @return void
	 */
	private function cleanup_run_artifacts( $run_id ) {
		if ( ! $run_id ) {
			return;
		}

		delete_transient( self::CORE_CHECKSUMS_KEY_PREFIX . $run_id );
		delete_transient( self::INTEGRITY_MANIFEST_KEY_PREFIX . $run_id );

		global $wpdb;
		$table_sql = $this->get_queue_table_name_sql();
		if ( '' === $table_sql ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . $table_sql . ' WHERE run_id = %s', $run_id ) );
	}

	/**
	 * Fetch the resumable scan state.
	 *
	 * @return array|false
	 */
	private function get_resumable_scan_state() {
		return get_transient( self::RESUMABLE_SCAN_STATE_KEY );
	}

	/**
	 * Persist the resumable scan state.
	 *
	 * @param array $state State to store.
	 * @return void
	 */
	private function save_resumable_scan_state( $state ) {
		set_transient( self::RESUMABLE_SCAN_STATE_KEY, $state, HOUR_IN_SECONDS );
	}

	/**
	 * Clear resumable scan state.
	 *
	 * @return void
	 */
	private function clear_resumable_scan_state() {
		delete_transient( self::RESUMABLE_SCAN_STATE_KEY );
	}

	/**
	 * Get the DB table name for the scan queue.
	 *
	 * @return string
	 */
	private function get_queue_table_name() {
		global $wpdb;
		$table = $wpdb->prefix . 'atomicedge_scan_queue';
		return preg_match( '/^[A-Za-z0-9_]+$/', $table ) ? $table : '';
	}

	/**
	 * Get a safely-quoted table identifier for use in SQL.
	 *
	 * @return string Backticked table identifier, or empty string if invalid.
	 */
	private function get_queue_table_name_sql() {
		$table = $this->get_queue_table_name();
		if ( ! $table ) {
			return '';
		}
		return '`' . $table . '`';
	}

	/**
	 * Ensure the scan queue table exists (safe to call repeatedly).
	 *
	 * @return void
	 */
	private function ensure_queue_table_exists() {
		global $wpdb;
		$table_name = $this->get_queue_table_name();
		if ( ! $table_name ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) );
		if ( $exists === $table_name ) {
			return;
		}

		require_once $this->get_wp_root_path() . 'wp-admin/includes/upgrade.php';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			run_id char(36) NOT NULL,
			item_type varchar(10) NOT NULL,
			area varchar(20) NOT NULL DEFAULT '',
			path longtext NOT NULL,
			path_hash char(32) NOT NULL,
			status varchar(20) NOT NULL DEFAULT 'pending',
			meta longtext NULL,
			last_error longtext NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY run_status (run_id,status,id),
			KEY run_type_status (run_id,item_type,status,id),
			UNIQUE KEY run_item (run_id,item_type,path_hash)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	/**
	 * Seed the queue for a run.
	 *
	 * @param string $run_id Run id.
	 * @return void
	 */
	private function seed_queue_for_run( $run_id, $scan_mode = 'php' ) {
		$root_path = $this->get_wp_root_path();
		$plugins_dir = $this->get_wp_plugins_path();
		$themes_dir = $this->get_wp_themes_path();
		$mu_plugins_dir = $this->get_wp_mu_plugins_path();
		$admin_dir = $this->get_wp_admin_path();
		$includes_dir = $this->get_wp_includes_path();
		$uploads_dir = $this->get_wp_uploads_path();

		// Root PHP files (non-recursive) are treated specially.
		$this->enqueue_queue_item( $run_id, 'rootfiles', 'root', $root_path, array() );

		$scan_mode = is_string( $scan_mode ) ? $scan_mode : 'all';
		$scan_mode = in_array( $scan_mode, array( 'php', 'all' ), true ) ? $scan_mode : 'all';

		// Quick scan: focus on the most likely compromise surfaces with minimal I/O.
		$this->enqueue_queue_item( $run_id, 'dir', 'plugins', $plugins_dir, array() );
		$this->enqueue_queue_item( $run_id, 'dir', 'themes', $themes_dir, array() );
		$this->enqueue_queue_item( $run_id, 'dir', 'plugins', $mu_plugins_dir, array() );

		// Thorough scan: include core directories and uploads checks.
		if ( 'all' === $scan_mode ) {
			$this->enqueue_queue_item( $run_id, 'dir', 'wp-admin', $admin_dir, array() );
			$this->enqueue_queue_item( $run_id, 'dir', 'wp-includes', $includes_dir, array() );
			$this->enqueue_queue_item( $run_id, 'dir', 'uploads', $uploads_dir, array() );
		}
	}

	/**
	 * Insert a queue item if it doesn't already exist.
	 *
	 * @param string $run_id Run id.
	 * @param string $item_type Item type.
	 * @param string $area Scan area.
	 * @param string $path Absolute path.
	 * @param array  $meta Optional metadata.
	 * @return void
	 */
	private function enqueue_queue_item( $run_id, $item_type, $area, $path, $meta = array() ) {
		global $wpdb;
		$table = $this->get_queue_table_name();
		if ( ! $table ) {
			return;
		}
		$now = current_time( 'mysql' );
		$path_hash = substr( hash( 'sha256', $item_type . '|' . $area . '|' . $path ), 0, 32 );
		$meta_json = ! empty( $meta ) ? wp_json_encode( $meta ) : null;

		// Use $wpdb->insert() to avoid interpolated table SQL in prepared statements.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'run_id'     => $run_id,
				'item_type'  => $item_type,
				'area'       => $area,
				'path'       => $path,
				'path_hash'  => $path_hash,
				'status'     => 'pending',
				'meta'       => $meta_json,
				'created_at' => $now,
				'updated_at' => $now,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Claim the next pending queue item.
	 *
	 * @param string $run_id Run id.
	 * @return array|false
	 */
	private function claim_next_queue_item( $run_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'atomicedge_scan_queue';
		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $table_name ) ) {
			return false;
		}
		$table_sql = '`' . $table_name . '`';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$item = $wpdb->get_row(
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare( 'SELECT id, item_type, area, path, meta FROM ' . $table_sql . " WHERE run_id = %s AND status = 'pending' ORDER BY id ASC LIMIT 1", $run_id ),
			ARRAY_A
		);

		if ( ! is_array( $item ) ) {
			return false;
		}

		$now = current_time( 'mysql' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$updated = $wpdb->query(
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare( 'UPDATE ' . $table_sql . " SET status = 'processing', updated_at = %s WHERE id = %d AND status = 'pending'", $now, (int) $item['id'] )
		);

		if ( 1 !== (int) $updated ) {
			return false;
		}

		return $item;
	}

	/**
	 * Mark a queue item as done.
	 *
	 * @param int    $id Item id.
	 * @param string $status New status.
	 * @param array  $meta Optional meta.
	 * @param string $error Optional error.
	 * @return void
	 */
	private function update_queue_item( $id, $status, $meta = array(), $error = '' ) {
		global $wpdb;
		$table = $this->get_queue_table_name();
		$now = current_time( 'mysql' );
		$meta_json = ! empty( $meta ) ? wp_json_encode( $meta ) : null;
		$error_val = $error ? $error : null;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			$table,
			array(
				'status' => $status,
				'meta' => $meta_json,
				'last_error' => $error_val,
				'updated_at' => $now,
			),
			array( 'id' => (int) $id ),
			array( '%s', '%s', '%s', '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Claim a batch of pending queue items at once for processing.
	 *
	 * This dramatically reduces database overhead compared to claiming one item at a time.
	 *
	 * @param string $run_id Run id.
	 * @param int    $batch_size Number of items to claim (default 100).
	 * @return array Array of queue items (may be empty if no more work).
	 */
	private function claim_batch_queue_items( $run_id, $batch_size = 100 ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'atomicedge_scan_queue';
		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $table_name ) ) {
			return array();
		}
		$table_sql = '`' . $table_name . '`';
		$batch_size = max( 10, min( 500, (int) $batch_size ) );

		// Fetch batch of pending items.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$items = $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare(
				'SELECT id, item_type, area, path, meta FROM ' . $table_sql . " WHERE run_id = %s AND status = 'pending' ORDER BY id ASC LIMIT %d",
				$run_id,
				$batch_size
			),
			ARRAY_A
		);

		if ( empty( $items ) ) {
			return array();
		}

		// Mark them all as processing in one query.
		$ids = array_map( 'intval', array_column( $items, 'id' ) );
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$now = current_time( 'mysql' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare(
				'UPDATE ' . $table_sql . " SET status = 'processing', updated_at = %s WHERE id IN ($placeholders)",
				array_merge( array( $now ), $ids )
			)
		);

		return $items;
	}

	/**
	 * Mark a batch of queue items as done in one query.
	 *
	 * @param array $ids Array of item IDs to mark as done.
	 * @return void
	 */
	private function batch_mark_items_done( $ids ) {
		if ( empty( $ids ) ) {
			return;
		}

		global $wpdb;
		$table_name = $wpdb->prefix . 'atomicedge_scan_queue';
		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $table_name ) ) {
			return;
		}
		$table_sql = '`' . $table_name . '`';

		$ids = array_map( 'intval', $ids );
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$now = current_time( 'mysql' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare(
				'UPDATE ' . $table_sql . " SET status = 'done', updated_at = %s WHERE id IN ($placeholders)",
				array_merge( array( $now ), $ids )
			)
		);
	}

	/**
	 * Queue an item ID for batch completion at end of step.
	 *
	 * @param int $id Item id.
	 * @return void
	 */
	private function queue_item_done( $id ) {
		$this->pending_done_ids[] = (int) $id;
	}

	/**
	 * Flush all pending done items to the database.
	 *
	 * @return void
	 */
	private function flush_pending_done_items() {
		if ( ! empty( $this->pending_done_ids ) ) {
			$this->batch_mark_items_done( $this->pending_done_ids );
			$this->pending_done_ids = array();
		}
	}

	/**
	 * Get queue counts for a run.
	 *
	 * @param string $run_id Run id.
	 * @return array
	 */
	private function get_queue_counts( $run_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'atomicedge_scan_queue';
		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $table_name ) ) {
			return array(
				'total'      => 0,
				'pending'    => 0,
				'processing' => 0,
				'done'       => 0,
				'error'      => 0,
			);
		}
		$table_sql = '`' . $table_name . '`';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare( 'SELECT status, COUNT(*) as c FROM ' . $table_sql . ' WHERE run_id = %s GROUP BY status', $run_id ),
			ARRAY_A
		);

		$counts = array(
			'total' => 0,
			'pending' => 0,
			'processing' => 0,
			'done' => 0,
			'error' => 0,
		);

		foreach ( $rows as $row ) {
			$status = isset( $row['status'] ) ? (string) $row['status'] : '';
			$c = isset( $row['c'] ) ? (int) $row['c'] : 0;
			$counts['total'] += $c;
			if ( isset( $counts[ $status ] ) ) {
				$counts[ $status ] += $c;
			}
		}

		return $counts;
	}

	/**
	 * Process a single queue item.
	 *
	 * @param array $item Item row.
	 * @param array $state Run state (by reference).
	 * @param float $started Step start time.
	 * @param int   $time_budget_seconds Step budget.
	 * @return void
	 */
	private function process_queue_item( $item, &$state, $started, $time_budget_seconds ) {
		$item_type = isset( $item['item_type'] ) ? (string) $item['item_type'] : '';
		$area      = isset( $item['area'] ) ? (string) $item['area'] : '';
		$path      = isset( $item['path'] ) ? (string) $item['path'] : '';
		$meta      = isset( $item['meta'] ) && $item['meta'] ? json_decode( (string) $item['meta'], true ) : array();
		if ( ! is_array( $meta ) ) {
			$meta = array();
		}

		$state['current_item'] = array(
			'id'   => isset( $item['id'] ) ? (int) $item['id'] : 0,
			'type' => $item_type,
			'area' => $area,
			'path' => $this->make_relative_to_root( $path ),
		);
		$this->append_scan_log(
			$state,
			sprintf(
				'[%s] %s (%s): %s',
				current_time( 'mysql' ),
				$item_type,
				$area,
				isset( $state['current_item']['path'] ) ? (string) $state['current_item']['path'] : ''
			)
		);

		if ( 'rootfiles' === $item_type ) {
			$this->process_rootfiles_item( (int) $item['id'], $area, $path, $meta, $state, $started, $time_budget_seconds );
			return;
		}

		if ( 'dir' === $item_type ) {
			$this->process_dir_item( (int) $item['id'], $area, $path, $meta, $state, $started, $time_budget_seconds );
			return;
		}

		if ( 'file' === $item_type ) {
			$this->process_file_item( (int) $item['id'], $area, $path, $state );
			return;
		}

		$this->update_queue_item( (int) $item['id'], 'done' );
	}

	/**
	 * Process a queue item using batched completion (no per-item DB write).
	 *
	 * This is a streamlined version for batch processing that queues
	 * item completion instead of writing to DB immediately.
	 *
	 * For 'file' items, uses queue_item_done() for batch completion.
	 * For 'dir' and 'rootfiles' items, falls back to direct processing
	 * since these are less frequent and may need incremental saves.
	 *
	 * @param array $item Item row.
	 * @param array $state Run state (by reference).
	 * @return void
	 */
	private function process_queue_item_batched( $item, &$state ) {
		$item_type = isset( $item['item_type'] ) ? (string) $item['item_type'] : '';
		$area      = isset( $item['area'] ) ? (string) $item['area'] : '';
		$path      = isset( $item['path'] ) ? (string) $item['path'] : '';
		$item_id   = isset( $item['id'] ) ? (int) $item['id'] : 0;

		// For file items, use the batched processor.
		if ( 'file' === $item_type ) {
			$this->process_file_item_batched( $item_id, $area, $path, $state );
			return;
		}

		// For dir/rootfiles, these are less frequent and may spawn more items.
		// Use original processing with direct DB writes.
		$meta = isset( $item['meta'] ) && $item['meta'] ? json_decode( (string) $item['meta'], true ) : array();
		if ( ! is_array( $meta ) ) {
			$meta = array();
		}

		$state['current_item'] = array(
			'id'   => $item_id,
			'type' => $item_type,
			'area' => $area,
			'path' => $this->make_relative_to_root( $path ),
		);

		// Use a generous time budget for these since they're infrequent.
		$dummy_started = microtime( true );
		$dummy_budget = 30;

		if ( 'rootfiles' === $item_type ) {
			$this->process_rootfiles_item( $item_id, $area, $path, $meta, $state, $dummy_started, $dummy_budget );
			return;
		}

		if ( 'dir' === $item_type ) {
			$this->process_dir_item( $item_id, $area, $path, $meta, $state, $dummy_started, $dummy_budget );
			return;
		}

		// Unknown type, mark done.
		$this->queue_item_done( $item_id );
	}

	/**
	 * Process a file item using batched completion.
	 *
	 * Same logic as process_file_item but uses queue_item_done()
	 * instead of update_queue_item() for batch DB writes.
	 *
	 * @param int    $id Item id.
	 * @param string $area Scan area.
	 * @param string $filepath Full file path.
	 * @param array  $state Run state (by reference).
	 * @return void
	 */
	private function process_file_item_batched( $id, $area, $filepath, &$state ) {
		$relative_path = $this->make_relative_to_root( $filepath );

		if ( ! file_exists( $filepath ) ) {
			$this->queue_item_done( $id );
			return;
		}

		if ( in_array( $area, array( 'plugins', 'themes' ), true ) && $this->is_whitelisted_path( $relative_path ) ) {
			$this->bump_diag_count( 'files_skipped_whitelist' );
			$this->queue_item_done( $id );
			return;
		}

		if ( 'uploads' === $area && $this->is_legitimate_upload_cache( $filepath ) ) {
			$this->queue_item_done( $id );
			return;
		}

		if ( isset( $this->scan_diagnostics['areas'][ $area ] ) ) {
			$this->scan_diagnostics['areas'][ $area ]['php_files_scanned']++;
		}
		$state['results']['scan_stats']['files_scanned']++;

		$is_uploads = ( 'uploads' === $area );
		$pattern_groups = $this->get_malware_patterns();
		if ( in_array( $area, array( 'wp-admin', 'wp-includes' ), true ) ) {
			$pattern_groups = $this->get_critical_patterns_only();
		} elseif ( in_array( $area, array( 'plugins', 'themes' ), true ) && ! $is_uploads ) {
			$pattern_groups = $this->get_refined_patterns_for_plugins();
		}

		$result = $this->scan_file_for_patterns( $filepath, $pattern_groups, $is_uploads );
		if ( $result ) {
			$result['file']      = $relative_path;
			$result['file_path'] = $filepath;
			if ( 'wp-admin' === $area ) {
				$result['location_note'] = __( 'Suspicious pattern in wp-admin', 'atomic-edge-security' );
			} elseif ( 'wp-includes' === $area ) {
				$result['location_note'] = __( 'Suspicious pattern in wp-includes', 'atomic-edge-security' );
			}
			$state['results']['suspicious'][] = $result;
		} elseif ( $is_uploads ) {
			$state['results']['suspicious'][] = array(
				'file'      => $relative_path,
				'file_path' => $filepath,
				'type'     => 'php_in_uploads',
				'severity' => 'high',
				'reason'   => __( 'PHP file found in uploads directory', 'atomic-edge-security' ),
			);
		}

		$this->queue_item_done( $id );
	}

	/**
	 * Process the rootfiles item: scan loose PHP files in ABSPATH (non-recursive).
	 */
	private function process_rootfiles_item( $id, $area, $root, $meta, &$state, $started, $time_budget_seconds ) {
		if ( ! is_dir( $root ) ) {
			$this->update_queue_item( $id, 'done' );
			return;
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$dir_handle = @opendir( $root );
		if ( ! $dir_handle ) {
			$this->bump_diag_count( 'dirs_unreadable', 'unreadable_dirs', $root );
			$this->add_scan_warning( __( 'Could not read WordPress root directory; scan may be incomplete.', 'atomic-edge-security' ) );
			$this->update_queue_item( $id, 'done' );
			return;
		}

		$last_entry = isset( $meta['last_entry'] ) ? (string) $meta['last_entry'] : '';
		$skipping = '' !== $last_entry;
		$processed = 0;

		while ( false !== ( $entry = readdir( $dir_handle ) ) ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			if ( $skipping ) {
				if ( $entry === $last_entry ) {
					$skipping = false;
				}
				continue;
			}

			$processed++;
			$meta['last_entry'] = $entry;

			if ( $processed >= 300 || ( microtime( true ) - $started ) >= $time_budget_seconds ) {
				break;
			}

			$filepath = $root . $entry;
			if ( ! ( is_file( $filepath ) && preg_match( '/\.php$/i', $entry ) ) ) {
				continue;
			}

			$this->scan_diagnostics['areas']['root']['php_files_found']++;
			$this->scan_diagnostics['areas']['root']['php_files_scanned']++;
			$state['results']['scan_stats']['files_scanned']++;

			$relative_path = $this->make_relative_to_root( $filepath );
			if ( $this->is_core_root_file( $relative_path ) ) {
				continue;
			}

			$result = $this->scan_file_for_patterns( $filepath, $this->get_malware_patterns(), true );
			if ( $result ) {
				$result['file']          = $relative_path;
				$result['file_path']     = $filepath;
				$result['location_note'] = __( 'Non-core file in WordPress root', 'atomic-edge-security' );
				$state['results']['suspicious'][] = $result;
			} else {
				$state['results']['suspicious'][] = array(
					'file'      => $relative_path,
					'file_path' => $filepath,
					'type'     => 'unknown_root_file',
					'severity' => 'high',
					'pattern'  => __( 'Unknown PHP file in WordPress root directory', 'atomic-edge-security' ),
				);
			}
		}

		$finished = ( false === $entry );
		closedir( $dir_handle );
		if ( $finished ) {
			$this->update_queue_item( $id, 'done' );
			return;
		}

		$this->update_queue_item( $id, 'pending', $meta );
	}

	/**
	 * Process a directory queue item, expanding child dirs and PHP files.
	 */
	private function process_dir_item( $id, $area, $dir, $meta, &$state, $started, $time_budget_seconds ) {
		if ( ! is_dir( $dir ) ) {
			$this->scan_diagnostics['counts']['dirs_missing']++;
			$this->update_queue_item( $id, 'done' );
			return;
		}

		if ( ! is_readable( $dir ) ) {
			$this->bump_diag_count( 'dirs_unreadable', 'unreadable_dirs', $dir );
			$this->add_scan_warning( __( 'Some directories could not be read; scan may be incomplete.', 'atomic-edge-security' ) );
			$this->update_queue_item( $id, 'done' );
			return;
		}

		// Skip excluded/whitelisted directories for plugin/theme areas.
		$relative_dir = $this->make_relative_to_root( $dir );
		if ( in_array( $area, array( 'plugins', 'themes' ), true ) && $this->is_whitelisted_path( $relative_dir . '/' ) ) {
			$this->update_queue_item( $id, 'done' );
			return;
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$handle = @opendir( $dir );
		if ( ! $handle ) {
			$this->bump_diag_count( 'dirs_unreadable', 'unreadable_dirs', $dir );
			$this->add_scan_warning( __( 'Some directories could not be read; scan may be incomplete.', 'atomic-edge-security' ) );
			$this->update_queue_item( $id, 'done' );
			return;
		}

		$max_entries = 300;
		$processed = 0;
		$last_entry = isset( $meta['last_entry'] ) ? (string) $meta['last_entry'] : '';
		$skipping = '' !== $last_entry;

		while ( false !== ( $entry = readdir( $handle ) ) ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			if ( $skipping ) {
				if ( $entry === $last_entry ) {
					$skipping = false;
				}
				continue;
			}

			$child = rtrim( $dir, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR . $entry;
			$child_relative = $this->make_relative_to_root( $child );
			$processed++;
			$meta['last_entry'] = $entry;

			if ( is_dir( $child ) ) {
				if ( ! is_link( $child ) ) {
					if ( $this->is_whitelisted_path( $child_relative . '/' ) ) {
						continue;
					}
					if ( 'uploads' === $area && $this->is_legitimate_upload_cache( $child ) ) {
						continue;
					}
					$this->enqueue_queue_item( $state['run_id'], 'dir', $area, $child, array() );
				}
			} elseif ( is_file( $child ) && preg_match( '/\.php$/i', $entry ) ) {
				if ( $this->is_whitelisted_path( $child_relative ) ) {
					$this->bump_diag_count( 'files_skipped_whitelist' );
					continue;
				}
				if ( 'uploads' === $area && $this->is_legitimate_upload_cache( $child ) ) {
					continue;
				}
				if ( isset( $this->scan_diagnostics['areas'][ $area ] ) ) {
					$this->scan_diagnostics['areas'][ $area ]['php_files_found']++;
				}
				$this->enqueue_queue_item( $state['run_id'], 'file', $area, $child, array() );
			}

			if ( $processed >= $max_entries || ( microtime( true ) - $started ) >= $time_budget_seconds ) {
				break;
			}
		}

		$finished = ( false === $entry );
		closedir( $handle );

		if ( $finished ) {
			$this->update_queue_item( $id, 'done' );
			return;
		}

		// More work remains in this directory.
		$this->update_queue_item( $id, 'pending', $meta );
	}

	/**
	 * Process a file queue item.
	 */
	private function process_file_item( $id, $area, $filepath, &$state ) {
		$relative_path = $this->make_relative_to_root( $filepath );

		if ( ! file_exists( $filepath ) ) {
			$this->update_queue_item( $id, 'done' );
			return;
		}

		if ( in_array( $area, array( 'plugins', 'themes' ), true ) && $this->is_whitelisted_path( $relative_path ) ) {
			$this->bump_diag_count( 'files_skipped_whitelist' );
			$this->update_queue_item( $id, 'done' );
			return;
		}

		if ( 'uploads' === $area && $this->is_legitimate_upload_cache( $filepath ) ) {
			$this->update_queue_item( $id, 'done' );
			return;
		}

		if ( isset( $this->scan_diagnostics['areas'][ $area ] ) ) {
			$this->scan_diagnostics['areas'][ $area ]['php_files_scanned']++;
		}
		$state['results']['scan_stats']['files_scanned']++;

		$is_uploads = ( 'uploads' === $area );
		$pattern_groups = $this->get_malware_patterns();
		if ( in_array( $area, array( 'wp-admin', 'wp-includes' ), true ) ) {
			$pattern_groups = $this->get_critical_patterns_only();
		} elseif ( in_array( $area, array( 'plugins', 'themes' ), true ) && ! $is_uploads ) {
			$pattern_groups = $this->get_refined_patterns_for_plugins();
		}

		$result = $this->scan_file_for_patterns( $filepath, $pattern_groups, $is_uploads );
		if ( $result ) {
			$result['file']      = $relative_path;
			$result['file_path'] = $filepath;
			if ( 'wp-admin' === $area ) {
				$result['location_note'] = __( 'Suspicious pattern in wp-admin', 'atomic-edge-security' );
			} elseif ( 'wp-includes' === $area ) {
				$result['location_note'] = __( 'Suspicious pattern in wp-includes', 'atomic-edge-security' );
			}
			$state['results']['suspicious'][] = $result;
		} elseif ( $is_uploads ) {
			$state['results']['suspicious'][] = array(
				'file'      => $relative_path,
				'file_path' => $filepath,
				'type'     => 'php_in_uploads',
				'severity' => 'high',
				'reason'   => __( 'PHP file found in uploads directory', 'atomic-edge-security' ),
			);
		}

		$this->update_queue_item( $id, 'done' );
	}

	/**
	 * Process an incremental chunk of core checksum comparisons.
	 */
	private function process_core_checksums_step( &$state, $started, $time_budget_seconds ) {
		$checksums = get_transient( self::CORE_CHECKSUMS_KEY_PREFIX . $state['run_id'] );
		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			return false;
		}

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

		$keys = array_keys( $checksums );
		$total = count( $keys );
		$offset = isset( $state['core_offset'] ) ? (int) $state['core_offset'] : 0;
		if ( $offset >= $total ) {
			delete_transient( self::CORE_CHECKSUMS_KEY_PREFIX . $state['run_id'] );
			return false;
		}

		$batch = array_slice( $keys, $offset, 50 );
		$root_path = $this->get_wp_root_path();
		foreach ( $batch as $file ) {
			if ( ( microtime( true ) - $started ) >= $time_budget_seconds ) {
				break;
			}

			$expected_hash = $checksums[ $file ];
			$file_path = $root_path . ltrim( $file, '/' );
			if ( $this->should_skip_core_file_checksum( $file, $file_path, $bundled_exclusions ) ) {
				$offset++;
				continue;
			}

			$matches = $this->core_checksum_matches( $file_path, (string) $expected_hash );
			if ( false === $matches ) {
				$state['results']['core_files'][] = array(
					'file'          => $file,
					'file_path'     => $file_path,
					'type'          => 'modified_core',
					'severity'      => 'high',
					'expected_hash' => $expected_hash,
				);
			}
			$offset++;
		}

		$state['core_offset'] = $offset;
		$state['core_total'] = $total;
		if ( $offset >= $total ) {
			delete_transient( self::CORE_CHECKSUMS_KEY_PREFIX . $state['run_id'] );
			return false;
		}

		return true;
	}

	/**
	 * Finalize a run if there is no more pending work.
	 */
	private function finalize_run_if_done( $state ) {
		$counts = $this->get_queue_counts( $state['run_id'] );
		if ( isset( $counts['pending'] ) && (int) $counts['pending'] > 0 ) {
			return $state;
		}

		$state['results']['scan_diagnostics'] = $this->scan_diagnostics;
		$integrity_count = 0;
		if ( isset( $state['results']['integrity_issues'] ) && is_array( $state['results']['integrity_issues'] ) ) {
			$integrity_count = count( $state['results']['integrity_issues'] );
		}

		$summary = array(
			'core_modified' => count( $state['results']['core_files'] ),
			'suspicious'    => count( $state['results']['suspicious'] ),
			'total_issues'  => count( $state['results']['core_files'] ) + count( $state['results']['suspicious'] ) + $integrity_count,
		);
		if ( array_key_exists( 'integrity_issues', $state['results'] ) ) {
			$summary['integrity_issues'] = $integrity_count;
		}
		$state['results']['summary'] = $summary;

		$state['results']['scan_stats']['memory_peak'] = memory_get_peak_usage( true );
		$state['results']['scan_stats']['time_elapsed'] = time() - strtotime( $state['results']['started_at'] );
		$state['results']['completed_at'] = current_time( 'mysql' );

		update_option( 'atomicedge_scan_results', $state['results'] );
		update_option( 'atomicedge_last_scan', current_time( 'mysql' ) );

		// Cleanup queue rows for this run.
		global $wpdb;
		$table_sql = $this->get_queue_table_name_sql();
		if ( '' !== $table_sql ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . $table_sql . ' WHERE run_id = %s', $state['run_id'] ) );
		}

		$state['status'] = 'complete';
		$state['progress'] = 100;
		$this->save_resumable_scan_state( $state );

		// Clear transient state so next scan can start cleanly.
		$this->clear_resumable_scan_state();

		return $state;
	}

	/**
	 * Scan WordPress core files against official checksums.
	 *
	 * @return array|false Array of modified files or false on error.
	 */
	public function scan_core_files() {
		global $wp_version;

		// Extend time limit for checksum comparison only.
		$this->extend_time_limit();

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

		$root_path = $this->get_wp_root_path();
		foreach ( $checksums as $file => $expected_hash ) {
			$file_path = $root_path . ltrim( $file, '/' );

			if ( $this->should_skip_core_file_checksum( $file, $file_path, $bundled_exclusions ) ) {
				continue;
			}

			$matches = $this->core_checksum_matches( $file_path, (string) $expected_hash );

			if ( false === $matches ) {
				$modified[] = array(
					'file'          => $file,
					'file_path'     => $file_path,
					'type'          => 'modified_core',
					'severity'      => 'high',
					'expected_hash' => $expected_hash,
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
	 * Verify WordPress.org core checksums without computing hashes in plugin code.
	 *
	 * WordPress core checksums returned by WordPress.org are MD5, but we delegate
	 * to WordPress core's verifier to avoid implementing weak hashing here.
	 *
	 * @param string $file_path Absolute file path.
	 * @param string $expected_hash Expected MD5 checksum from WordPress.org.
	 * @return bool|null True if matches, false if mismatch, null if verification unavailable.
	 */
	private function core_checksum_matches( $file_path, $expected_hash ) {
		if ( ! is_readable( $file_path ) ) {
			$this->scan_diagnostics[] = array(
				'type'     => 'warning',
				'code'     => 'core_checksum_unreadable',
				'message'  => 'Unable to read core file for checksum verification.',
				'file'     => $file_path,
				'reason'   => 'not_readable',
				'detected' => current_time( 'mysql' ),
			);
			return null;
		}

		if ( ! function_exists( 'wp_verify_file_md5' ) ) {
			$file_php = $this->get_wp_root_path() . 'wp-admin/includes/file.php';
			if ( file_exists( $file_php ) ) {
				require_once $file_php;
			}
		}

		if ( ! function_exists( 'wp_verify_file_md5' ) ) {
			$this->scan_diagnostics[] = array(
				'type'     => 'warning',
				'code'     => 'core_checksum_verifier_missing',
				'message'  => 'Core checksum verification function missing; core file checks were skipped.',
				'file'     => $file_path,
				'reason'   => 'verifier_missing',
				'detected' => current_time( 'mysql' ),
			);
			return null;
		}

		$result = wp_verify_file_md5( $file_path, $expected_hash );
		return ( true === $result ) ? true : false;
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
		// Extend time limit for long-running suspicious file scan only.
		$this->extend_time_limit();
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
		$this->scan_directory_for_critical_patterns( 'wp-admin', $this->get_wp_admin_path(), __( 'Suspicious pattern in wp-admin', 'atomic-edge-security' ), $suspicious, $reported_files, $files_scanned, $memory_threshold );

		// 3. SCAN WP-INCLUDES DIRECTORY (should only contain core files).
		$this->scan_directory_for_critical_patterns( 'wp-includes', $this->get_wp_includes_path(), __( 'Suspicious pattern in wp-includes', 'atomic-edge-security' ), $suspicious, $reported_files, $files_scanned, $memory_threshold );

		// 4. SCAN WP-CONTENT SUBDIRECTORIES.
		$this->scan_wp_content_directories( $pattern_groups, $suspicious, $reported_files, $files_scanned, $memory_threshold );

		// 5. FLAG ANY PHP FILES IN UPLOADS (even without pattern matches).
		$this->flag_php_files_in_uploads( $suspicious, $reported_files );

		// Update scan stats.
		$this->save_scan_state( array(
			'files_scanned' => $files_scanned,
			'started_at'    => current_time( 'mysql' ),
		) );

		$this->scan_diagnostics['scan_stats_files_scanned'] = $files_scanned;

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
		$this->scan_diagnostics['areas']['root']['php_files_found'] = count( $root_files );
		foreach ( $root_files as $file ) {
			// Memory check before processing.
			if ( memory_get_usage( true ) > $memory_threshold ) {
				AtomicEdge::log( 'Scan memory limit approaching, stopping early' );
				$this->mark_stopped_early( 'memory_limit' );
				break;
			}

			$relative_path = $this->make_relative_to_root( $file );
			$files_scanned++;
			$this->scan_diagnostics['areas']['root']['php_files_scanned']++;

			// Skip already reported and core files.
			if ( isset( $reported_files[ $relative_path ] ) || $this->is_core_root_file( $relative_path ) ) {
				continue;
			}

			// Non-core PHP files in root are highly suspicious.
			$result = $this->scan_file_for_patterns( $file, $pattern_groups, true );
			if ( $result ) {
				$result['file']          = $relative_path;
				$result['file_path']     = $file;
				$result['location_note'] = __( 'Non-core file in WordPress root', 'atomic-edge-security' );
				$suspicious[]            = $result;
				$reported_files[ $relative_path ] = true;
			} else {
				// Even without pattern match, non-core PHP in root is suspicious.
				$suspicious[] = array(
					'file'      => $relative_path,
					'file_path' => $file,
					'type'     => 'unknown_root_file',
					'severity' => 'high',
					'pattern'  => __( 'Unknown PHP file in WordPress root directory', 'atomic-edge-security' ),
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
	private function scan_directory_for_critical_patterns( $area, $dir, $location_note, &$suspicious, &$reported_files, &$files_scanned, $memory_threshold ) {
		if ( ! is_dir( $dir ) ) {
			$this->scan_diagnostics['counts']['dirs_missing']++;
			return;
		}

		$files = $this->get_php_files( $dir );
		if ( isset( $this->scan_diagnostics['areas'][ $area ] ) ) {
			$this->scan_diagnostics['areas'][ $area ]['php_files_found'] = count( $files );
		}
		foreach ( $files as $file ) {
			if ( memory_get_usage( true ) > $memory_threshold ) {
				$this->mark_stopped_early( 'memory_limit' );
				break;
			}

			$relative_path = $this->make_relative_to_root( $file );
			$files_scanned++;
			if ( isset( $this->scan_diagnostics['areas'][ $area ] ) ) {
				$this->scan_diagnostics['areas'][ $area ]['php_files_scanned']++;
			}

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
			$this->get_wp_uploads_path() => true,  // is_uploads.
			$this->get_wp_themes_path()  => false,
			$this->get_wp_plugins_path() => false,
		);

		foreach ( $scan_dirs as $dir => $is_uploads_dir ) {
			if ( ! is_dir( $dir ) ) {
				$this->scan_diagnostics['counts']['dirs_missing']++;
				continue;
			}

			$area = 'plugins';
			if ( $is_uploads_dir ) {
				$area = 'uploads';
			} elseif ( $dir === $this->get_wp_themes_path() ) {
				$area = 'themes';
			}

			$files = $this->get_php_files( $dir );
			if ( isset( $this->scan_diagnostics['areas'][ $area ] ) ) {
				$this->scan_diagnostics['areas'][ $area ]['php_files_found'] = count( $files );
			}
			foreach ( $files as $file ) {
				if ( memory_get_usage( true ) > $memory_threshold ) {
					AtomicEdge::log( 'Scan memory limit approaching, stopping early' );
					$this->mark_stopped_early( 'memory_limit' );
					break 2;
				}

				$relative_path = $this->make_relative_to_root( $file );
				$files_scanned++;
				if ( isset( $this->scan_diagnostics['areas'][ $area ] ) ) {
					$this->scan_diagnostics['areas'][ $area ]['php_files_scanned']++;
				}

				if ( isset( $reported_files[ $relative_path ] ) ) {
					continue;
				}

				// Skip whitelisted paths (but NOT in uploads - uploads should always be scanned).
				if ( ! $is_uploads_dir && $this->is_whitelisted_path( $relative_path ) ) {
					$this->bump_diag_count( 'files_skipped_whitelist' );
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
		$uploads_dir = $this->get_wp_uploads_path();
		if ( ! $uploads_dir || ! is_dir( $uploads_dir ) ) {
			return;
		}

		$upload_php_files = $this->get_php_files( $uploads_dir );
		// This is a dedicated pass; include it in uploads found/scanned stats.
		$this->scan_diagnostics['areas']['uploads']['php_files_found'] = max( $this->scan_diagnostics['areas']['uploads']['php_files_found'], count( $upload_php_files ) );
		foreach ( $upload_php_files as $file ) {
			$relative_path = $this->make_relative_to_root( $file );
			$this->scan_diagnostics['areas']['uploads']['php_files_scanned']++;

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
				'reason'   => __( 'PHP file found in uploads directory', 'atomic-edge-security' ),
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
		$root  = $this->get_wp_root_path();

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$dir_handle = @opendir( $root );
		if ( ! $dir_handle ) {
			$this->bump_diag_count( 'dirs_unreadable', 'unreadable_dirs', $root );
			$this->add_scan_warning( __( 'Could not read WordPress root directory; scan may be incomplete.', 'atomic-edge-security' ) );
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
		if ( is_array( $this->critical_patterns_cache ) ) {
			return $this->critical_patterns_cache;
		}

		$all_patterns = $this->get_malware_patterns();

		$this->critical_patterns_cache = array(
			'backdoor_patterns' => $all_patterns['backdoor_patterns'],
			'webshells'         => $all_patterns['webshells'],
			'wordpress_malware' => $all_patterns['wordpress_malware'],
		);

		return $this->critical_patterns_cache;
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
		$filesize = @filesize( $filepath );
		if ( false === $filesize ) {
			$this->bump_diag_count( 'files_stat_failed' );
			return false;
		}

		$relative_path = $this->make_relative_to_root( $filepath );

		// Read a capped prefix of the file to avoid memory/time issues on large files.
		// We treat oversized files as partially scanned (not silently skipped).
		$max_bytes = 2 * 1024 * 1024;
		$bytes_to_read = (int) min( (int) $filesize, (int) $max_bytes );

		// WP-CLI plugin check enforces WP_Filesystem usage. Since WP_Filesystem does not
		// support efficient ranged reads, we only scan files up to the cap.
		if ( $filesize > $max_bytes ) {
			$this->bump_diag_count( 'files_partially_scanned', 'oversized_files', $relative_path );
			$this->add_scan_warning( __( 'Some large files were not fully scanned; results may be incomplete.', 'atomic-edge-security' ) );
			return false;
		}

		// TIMING: Track file read time.
		$read_start = microtime( true );
		$content = $this->read_file_prefix( $filepath, $bytes_to_read );
		$read_elapsed = ( microtime( true ) - $read_start ) * 1000;
		if ( isset( $this->scan_diagnostics['timing']['total_file_read_ms'] ) ) {
			$this->scan_diagnostics['timing']['total_file_read_ms'] += $read_elapsed;
		}

		if ( false === $content ) {
			$this->bump_diag_count( 'files_read_failed', 'read_failed_files', $relative_path );
			$this->add_scan_warning( __( 'Some files could not be read; scan may be incomplete.', 'atomic-edge-security' ) );
			return false;
		}

		// Check for hidden PHP in image files.
		if ( $check_php_in_image && $this->is_php_in_image( $filepath, $content ) ) {
			return array(
				'type'     => 'php_in_image',
				'severity' => 'critical',
				'pattern'  => __( 'PHP code hidden in image file', 'atomic-edge-security' ),
			);
		}

		// PERFORMANCE OPTIMIZATION: Quick rejection pre-filter.
		// If the file doesn't contain ANY of the indicator strings, skip expensive regex.
		// TIMING: Track quick check time.
		$quick_start = microtime( true );
		$content_lower = strtolower( $content );
		$has_indicator = false;
		foreach ( $this->quick_rejection_indicators as $indicator ) {
			if ( false !== strpos( $content_lower, $indicator ) ) {
				$has_indicator = true;
				break;
			}
		}
		$quick_elapsed = ( microtime( true ) - $quick_start ) * 1000;
		if ( isset( $this->scan_diagnostics['timing']['total_quick_check_ms'] ) ) {
			$this->scan_diagnostics['timing']['total_quick_check_ms'] += $quick_elapsed;
		}

		if ( ! $has_indicator ) {
			// File is clean - no suspicious indicators found. Track the rejection.
			$this->bump_diag_count( 'files_quick_rejected' );
			return false;
		}

		// File has potential indicators - run full regex scan.
		$this->bump_diag_count( 'files_regex_scanned' );

		// TIMING: Track regex time.
		$regex_start = microtime( true );

		// PERFORMANCE OPTIMIZATION: Use combined regex patterns per category.
		// Instead of 100+ individual preg_match calls, use one per category.
		$combined = $this->get_combined_patterns( $pattern_groups );

		$result = false;
		foreach ( $combined as $group_name => $group_data ) {
			// Single regex match for entire category.
			if ( preg_match( $group_data['regex'], $content, $matches ) ) {
				// Find which specific pattern matched for the description.
				$matched_pattern = isset( $matches[1] ) ? $matches[0] : $matches[0];
				$description = $this->identify_matched_pattern( $matched_pattern, $pattern_groups[ $group_name ] );
				$severity = $this->get_pattern_severity( $group_name );

				$result = array(
					'type'     => 'suspicious_pattern',
					'severity' => $severity,
					'pattern'  => $description,
					'category' => $group_name,
				);
				break;
			}
		}

		$regex_elapsed = ( microtime( true ) - $regex_start ) * 1000;
		if ( isset( $this->scan_diagnostics['timing']['total_regex_ms'] ) ) {
			$this->scan_diagnostics['timing']['total_regex_ms'] += $regex_elapsed;
		}

		return $result;
	}

	/**
	 * Get combined regex patterns for faster matching.
	 *
	 * Combines individual patterns within each category into a single alternation regex.
	 * This reduces the number of preg_match calls from 100+ to ~11 (one per category).
	 *
	 * @param array $pattern_groups Pattern groups to combine.
	 * @return array Combined patterns with 'regex' and 'patterns' keys per group.
	 */
	private function get_combined_patterns( $pattern_groups ) {
		// Generate a cache key based on the pattern groups structure.
		$cache_key = md5( wp_json_encode( array_keys( $pattern_groups ) ) );

		if ( is_array( $this->combined_patterns_cache ) && isset( $this->combined_patterns_cache[ $cache_key ] ) ) {
			return $this->combined_patterns_cache[ $cache_key ];
		}

		$combined = array();

		foreach ( $pattern_groups as $group_name => $patterns ) {
			if ( empty( $patterns ) ) {
				continue;
			}

			// Combine all patterns in this group using alternation.
			// Wrap each pattern in a non-capturing group to preserve alternation precedence.
			$pattern_list = array_keys( $patterns );
			$wrapped = array_map(
				function ( $p ) {
					return '(?:' . $p . ')';
				},
				$pattern_list
			);

			$combined[ $group_name ] = array(
				'regex'    => '#(' . implode( '|', $wrapped ) . ')#i',
				'patterns' => $patterns,
			);
		}

		if ( ! is_array( $this->combined_patterns_cache ) ) {
			$this->combined_patterns_cache = array();
		}
		$this->combined_patterns_cache[ $cache_key ] = $combined;

		return $combined;
	}

	/**
	 * Identify which specific pattern matched from a combined regex match.
	 *
	 * @param string $matched_text The text that matched the combined regex.
	 * @param array  $patterns     The original patterns array with descriptions.
	 * @return string The description of the matched pattern.
	 */
	private function identify_matched_pattern( $matched_text, $patterns ) {
		foreach ( $patterns as $pattern => $description ) {
			if ( preg_match( '#' . $pattern . '#i', $matched_text ) ) {
				return $description;
			}
		}

		// Fallback if no specific pattern identified (shouldn't happen).
		return __( 'Suspicious pattern detected', 'atomic-edge-security' );
	}

	/**
	 * Read the first N bytes of a file (binary-safe).
	 *
	 * PERFORMANCE NOTE: This method intentionally uses native file_get_contents()
	 * instead of WP_Filesystem for significant performance gains (3-5x faster).
	 *
	 * Per WordPress coding standards, WP_Filesystem is required for WRITE operations
	 * (to handle FTP/SSH credentials on restricted hosts). For READ operations,
	 * file_get_contents() is acceptable and used throughout WordPress core.
	 *
	 * Key advantages of native file_get_contents():
	 * 1. Supports partial reads via $length parameter (WP_Filesystem reads entire file)
	 * 2. No abstraction layer overhead
	 * 3. No WP_Filesystem initialization cost
	 * 4. 3-5x faster per file on benchmarks
	 *
	 * For a scan touching 30,000+ files, this difference is substantial.
	 *
	 * @param string $filepath File path.
	 * @param int    $bytes_to_read Maximum bytes to read.
	 * @return string|false File contents or false on failure.
	 */
	private function read_file_prefix( $filepath, $bytes_to_read ) {
		$bytes_to_read = max( 0, (int) $bytes_to_read );
		if ( 0 === $bytes_to_read ) {
			return '';
		}

		// Use native file_get_contents for best performance.
		// The $length parameter enables efficient partial reads - we only read what we need.
		// This is critical for large files where we cap reads at 2MB.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- READ operation, not write. See method docblock.
		$contents = @file_get_contents( $filepath, false, null, 0, $bytes_to_read );

		return false !== $contents ? $contents : false;
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
			if ( is_dir( $dir ) && ! is_readable( $dir ) ) {
				$this->bump_diag_count( 'dirs_unreadable', 'unreadable_dirs', $dir );
				$this->add_scan_warning( __( 'Some directories could not be read; scan may be incomplete.', 'atomic-edge-security' ) );
			}
			return $files;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( UnexpectedValueException $e ) {
			$this->bump_diag_count( 'dirs_unreadable', 'unreadable_dirs', $dir );
			$this->add_scan_warning( __( 'Some directories could not be scanned due to permissions; scan may be incomplete.', 'atomic-edge-security' ) );
			return $files;
		}

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
		if ( is_array( $this->patterns_cache ) ) {
			return $this->patterns_cache;
		}

		$this->patterns_cache = array(
			// Critical: Direct code execution patterns.
			'code_execution'       => array(
				'eval\s*\('                                                          => __( 'Eval function (code execution)', 'atomic-edge-security' ),
				'assert\s*\('                                                        => __( 'Assert function (potential code execution)', 'atomic-edge-security' ),
				'create_function\s*\('                                               => __( 'Create function (dynamic code creation)', 'atomic-edge-security' ),
				'call_user_func\s*\('                                                => __( 'Call user func (dynamic function call)', 'atomic-edge-security' ),
				'call_user_func_array\s*\('                                          => __( 'Call user func array (dynamic function call)', 'atomic-edge-security' ),
				'preg_replace\s*\([^,]+["\'].*\/e["\']'                               => __( 'Preg replace with eval modifier', 'atomic-edge-security' ),
				'preg_replace_callback\s*\('                                         => __( 'Preg replace callback (potential code execution)', 'atomic-edge-security' ),
			),

			// Critical: Shell/system execution.
			'shell_execution'      => array(
				'\bsystem\s*\('                                                      => __( 'System command execution', 'atomic-edge-security' ),
				'\bexec\s*\('                                                        => __( 'Exec command execution', 'atomic-edge-security' ),
				'\bshell_exec\s*\('                                                  => __( 'Shell exec command', 'atomic-edge-security' ),
				'\bpassthru\s*\('                                                    => __( 'Passthru command execution', 'atomic-edge-security' ),
				'\bpopen\s*\('                                                       => __( 'Popen command execution', 'atomic-edge-security' ),
				'\bproc_open\s*\('                                                   => __( 'Proc open command execution', 'atomic-edge-security' ),
				'\bpcntl_exec\s*\('                                                  => __( 'PCNTL exec', 'atomic-edge-security' ),
				'`[^`]+`'                                                            => __( 'Backtick command execution', 'atomic-edge-security' ),
			),

			// Critical: Backdoor patterns.
			'backdoor_patterns'    => array(
				'@eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'                        => __( 'Backdoor: eval with user input', 'atomic-edge-security' ),
				'@eval\s*\(\s*base64_decode'                                         => __( 'Backdoor: eval with base64', 'atomic-edge-security' ),
				'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\('                   => __( 'Direct superglobal execution', 'atomic-edge-security' ),
				'extract\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Dangerous extract from user input', 'atomic-edge-security' ),
				'include\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Remote file inclusion via user input', 'atomic-edge-security' ),
				'require\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Remote file inclusion via user input', 'atomic-edge-security' ),
				'file_put_contents\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)'             => __( 'File write from user input', 'atomic-edge-security' ),
				'fwrite\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)'                        => __( 'File write from user input', 'atomic-edge-security' ),
			),

			// High: Obfuscation techniques.
			'obfuscation'          => array(
				'base64_decode\s*\('                                                 => __( 'Base64 decoding (potential obfuscation)', 'atomic-edge-security' ),
				'gzinflate\s*\('                                                     => __( 'Gzip inflate (potential obfuscation)', 'atomic-edge-security' ),
				'gzuncompress\s*\('                                                  => __( 'Gzip uncompress (potential obfuscation)', 'atomic-edge-security' ),
				'str_rot13\s*\('                                                     => __( 'ROT13 encoding (potential obfuscation)', 'atomic-edge-security' ),
				'convert_uudecode\s*\('                                              => __( 'UUdecode (potential obfuscation)', 'atomic-edge-security' ),
				'\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){5,}'                        => __( 'Hex encoded strings', 'atomic-edge-security' ),
				'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)(\s*\.\s*chr\s*\(\s*\d+\s*\)){3,}' => __( 'Chr() string building', 'atomic-edge-security' ),
				'edoced_46esab'                                                      => __( 'Reversed base64_decode', 'atomic-edge-security' ),
				'strrev\s*\(["\'][^"\']+["\']\)'                                      => __( 'String reversal (obfuscation)', 'atomic-edge-security' ),
			),

			// High: Known webshell signatures.
			'webshells'            => array(
				'c99shell'                                                           => __( 'C99 shell signature', 'atomic-edge-security' ),
				'r57shell'                                                           => __( 'R57 shell signature', 'atomic-edge-security' ),
				'b374k'                                                              => __( 'B374K shell signature', 'atomic-edge-security' ),
				'FilesMan'                                                           => __( 'FilesMan shell signature', 'atomic-edge-security' ),
				'WSO\s+[\d\.]+'                                                      => __( 'WSO shell signature', 'atomic-edge-security' ),
				'Weevely'                                                            => __( 'Weevely shell signature', 'atomic-edge-security' ),
				'php\s*spy'                                                          => __( 'PHPSpy shell signature', 'atomic-edge-security' ),
				'PHANTOMJS'                                                          => __( 'PhantomJS shell signature', 'atomic-edge-security' ),
				'Mister Spy'                                                         => __( 'Mister Spy shell signature', 'atomic-edge-security' ),
				'Afghan Shell'                                                       => __( 'Afghan Shell signature', 'atomic-edge-security' ),
				'Shell by'                                                           => __( 'Generic shell signature', 'atomic-edge-security' ),
				'SHELL_PASSWORD'                                                     => __( 'Shell password variable', 'atomic-edge-security' ),
				'0day'                                                               => __( '0day exploit reference', 'atomic-edge-security' ),
			),

			// High: WordPress-specific malware.
			'wordpress_malware'    => array(
				'wp-vcd'                                                             => __( 'WP-VCD malware', 'atomic-edge-security' ),
				'class\.theme-modules\.php'                                          => __( 'WP-VCD theme modules', 'atomic-edge-security' ),
				'class\.plugin-modules\.php'                                         => __( 'WP-VCD plugin modules', 'atomic-edge-security' ),
				'wp-tmp\.php'                                                        => __( 'WP-VCD temp file', 'atomic-edge-security' ),
				'tmpcontentx'                                                        => __( 'WP-VCD content injection', 'atomic-edge-security' ),
				'wp_temp_setupx'                                                     => __( 'WP-VCD setup function', 'atomic-edge-security' ),
				'derna\.top'                                                         => __( 'Known malware domain', 'atomic-edge-security' ),
				'/\*\s*@noupdate\s*\*/'                                              => __( 'Plugin update suppression', 'atomic-edge-security' ),
			),

			// Medium: Suspicious file operations.
			'file_operations'      => array(
				'file_get_contents\s*\(["\']https?://'                               => __( 'Remote file fetch', 'atomic-edge-security' ),
				'file_get_contents\s*\(["\']php://input'                             => __( 'Raw POST data read', 'atomic-edge-security' ),
				'curl_exec\s*\('                                                     => __( 'cURL execution', 'atomic-edge-security' ),
				'fsockopen\s*\('                                                     => __( 'Socket connection', 'atomic-edge-security' ),
				'stream_socket_client\s*\('                                          => __( 'Stream socket client', 'atomic-edge-security' ),
			),

			// Medium: Base64 encoded suspicious keywords.
			'base64_keywords'      => array(
				'ZXZhbCg'                                                            => __( 'Base64: eval(', 'atomic-edge-security' ),
				'YXNzZXJ0'                                                           => __( 'Base64: assert', 'atomic-edge-security' ),
				'c3lzdGVt'                                                           => __( 'Base64: system', 'atomic-edge-security' ),
				'ZXhlYyg'                                                            => __( 'Base64: exec(', 'atomic-edge-security' ),
				'c2hlbGxfZXhlYw'                                                     => __( 'Base64: shell_exec', 'atomic-edge-security' ),
				'cGFzc3RocnU'                                                        => __( 'Base64: passthru', 'atomic-edge-security' ),
				'JF9HRV'                                                             => __( 'Base64: $_GET', 'atomic-edge-security' ),
				'JF9QT1NU'                                                           => __( 'Base64: $_POST', 'atomic-edge-security' ),
				'JF9SRVFVRVNU'                                                       => __( 'Base64: $_REQUEST', 'atomic-edge-security' ),
				'JF9DT09LSUU'                                                        => __( 'Base64: $_COOKIE', 'atomic-edge-security' ),
				'SFRUUF9VU0VSX0FHRU5U'                                               => __( 'Base64: HTTP_USER_AGENT', 'atomic-edge-security' ),
				'R0xPQkFMU'                                                          => __( 'Base64: GLOBALS', 'atomic-edge-security' ),
			),

			// Medium: Suspicious strings and indicators.
			'suspicious_strings'   => array(
				'/etc/passwd'                                                            => __( 'Password file access', 'atomic-edge-security' ),
				'/etc/shadow'                                                            => __( 'Shadow file access', 'atomic-edge-security' ),
				'HACKED BY'                                                          => __( 'Defacement signature', 'atomic-edge-security' ),
				'owned by'                                                           => __( 'Defacement signature', 'atomic-edge-security' ),
				'backdoor'                                                           => __( 'Backdoor keyword', 'atomic-edge-security' ),
				'rootkit'                                                            => __( 'Rootkit keyword', 'atomic-edge-security' ),
				'c999sh'                                                             => __( 'Shell variant', 'atomic-edge-security' ),
				'r57sh'                                                              => __( 'Shell variant', 'atomic-edge-security' ),
				'webshell'                                                           => __( 'Webshell keyword', 'atomic-edge-security' ),
				'cmd\.exe'                                                           => __( 'Windows command execution', 'atomic-edge-security' ),
				'powershell\.exe'                                                    => __( 'PowerShell execution', 'atomic-edge-security' ),
				'uname\s+-a'                                                         => __( 'System information gathering', 'atomic-edge-security' ),
				'whoami'                                                             => __( 'User identification command', 'atomic-edge-security' ),
			),

			// Medium: Network indicators.
			'network_indicators'   => array(
'fsockopen\s*\(["\']udp://'                                              => __( 'UDP socket (potential DDoS)', 'atomic-edge-security' ),
				'socket_create\s*\(\s*AF_INET'                                       => __( 'Raw socket creation', 'atomic-edge-security' ),
				'curl_setopt[^;]+CURLOPT_FOLLOWLOCATION'                             => __( 'cURL with redirect following', 'atomic-edge-security' ),
			),

			// Low: Potentially dangerous functions (context-dependent).
			'potentially_dangerous' => array(
				'unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'                  => __( 'Unserialize user input (object injection)', 'atomic-edge-security' ),
				'serialize\s*\([^)]+\)\s*\.'                                         => __( 'Serialized data concatenation', 'atomic-edge-security' ),
				'ini_set\s*\(["\'](?:allow_url_fopen|allow_url_include)'             => __( 'INI override for remote includes', 'atomic-edge-security' ),
				'ini_set\s*\(["\']disable_functions'                                 => __( 'Attempt to modify disabled functions', 'atomic-edge-security' ),
				'error_reporting\s*\(\s*0\s*\)'                                      => __( 'Error reporting disabled', 'atomic-edge-security' ),
				'set_error_handler\s*\(\s*null'                                      => __( 'Error handler nullified', 'atomic-edge-security' ),
			),
		);

		return $this->patterns_cache;
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
		// Exclude the scanner implementation file itself to prevent self-triggering
		// on its own signature strings. This is intentionally narrow.
		$scanner_suffix = 'includes/class-atomicedge-scanner.php';
		if ( strlen( $relative_path ) >= strlen( $scanner_suffix )
			&& substr( $relative_path, -strlen( $scanner_suffix ) ) === $scanner_suffix
		) {
			return true;
		}

		$relative_path = wp_normalize_path( $relative_path );
		$relative_with_slash = rtrim( $relative_path, '/' ) . '/';

		// Check excluded paths (vendor, node_modules, tests, etc.).
		foreach ( $this->excluded_paths as $excluded ) {
			if ( false !== strpos( $relative_path, $excluded ) || false !== strpos( $relative_with_slash, $excluded ) ) {
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
		if ( is_array( $this->refined_patterns_cache ) ) {
			return $this->refined_patterns_cache;
		}

		$this->refined_patterns_cache = array(
			// Critical: Definite backdoor patterns (these are ALWAYS malicious).
			'backdoor_patterns'    => array(
				'@eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'                        => __( 'Backdoor: eval with user input', 'atomic-edge-security' ),
				'@eval\s*\(\s*base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'   => __( 'Backdoor: eval+base64 with user input', 'atomic-edge-security' ),
				'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\('                   => __( 'Direct superglobal as function', 'atomic-edge-security' ),
				'extract\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Dangerous extract from user input', 'atomic-edge-security' ),
				'include\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Remote file inclusion via user input', 'atomic-edge-security' ),
				'require\s*\(\s*\$_(?:GET|POST|REQUEST)'                             => __( 'Remote file inclusion via user input', 'atomic-edge-security' ),
				'file_put_contents\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)'             => __( 'File write from user input', 'atomic-edge-security' ),
				'assert\s*\(\s*\$_(?:GET|POST|REQUEST)'                              => __( 'Assert with user input', 'atomic-edge-security' ),
				'preg_replace\s*\([^,]+["\'].*\/e["\'][^,]*,\s*\$_'                  => __( 'Preg replace eval with user input', 'atomic-edge-security' ),
			),

			// Critical: Known webshell signatures (unique identifiers).
			'webshells'            => array(
				'c99shell'                                                           => __( 'C99 shell signature', 'atomic-edge-security' ),
				'r57shell'                                                           => __( 'R57 shell signature', 'atomic-edge-security' ),
				'b374k'                                                              => __( 'B374K shell signature', 'atomic-edge-security' ),
				'WSO\s+[\d\.]+'                                                      => __( 'WSO shell signature', 'atomic-edge-security' ),
				'Weevely'                                                            => __( 'Weevely shell signature', 'atomic-edge-security' ),
			),

			// Critical: WordPress-specific malware.
			'wordpress_malware'    => array(
				'wp-vcd'                                                             => __( 'WP-VCD malware', 'atomic-edge-security' ),
				'class\.theme-modules\.php'                                          => __( 'WP-VCD theme modules', 'atomic-edge-security' ),
				'class\.plugin-modules\.php'                                         => __( 'WP-VCD plugin modules', 'atomic-edge-security' ),
				'wp-tmp\.php'                                                        => __( 'WP-VCD temp file', 'atomic-edge-security' ),
				'tmpcontentx'                                                        => __( 'WP-VCD content injection', 'atomic-edge-security' ),
				'wp_temp_setupx'                                                     => __( 'WP-VCD setup function', 'atomic-edge-security' ),
				'derna\.top'                                                         => __( 'Known malware domain', 'atomic-edge-security' ),
				'/\*\s*@noupdate\s*\*/'                                              => __( 'Plugin update suppression', 'atomic-edge-security' ),
			),

			// High: Obfuscated code execution (multi-layer obfuscation is suspicious).
			'obfuscated_execution' => array(
				'eval\s*\(\s*gzinflate\s*\(\s*base64_decode'                         => __( 'Multi-layer obfuscation: eval+gzinflate+base64', 'atomic-edge-security' ),
				'eval\s*\(\s*gzuncompress\s*\(\s*base64_decode'                      => __( 'Multi-layer obfuscation: eval+gzuncompress+base64', 'atomic-edge-security' ),
				'eval\s*\(\s*str_rot13\s*\(\s*base64_decode'                         => __( 'Multi-layer obfuscation: eval+rot13+base64', 'atomic-edge-security' ),
				'assert\s*\(\s*base64_decode'                                        => __( 'Obfuscated assert', 'atomic-edge-security' ),
				'create_function\s*\([^)]*base64_decode'                             => __( 'Obfuscated create_function', 'atomic-edge-security' ),
				'edoced_46esab'                                                      => __( 'Reversed base64_decode', 'atomic-edge-security' ),
			),

			// High: Suspicious strings that are almost never legitimate.
			'suspicious_strings'   => array(
				'/etc/passwd'                                                        => __( 'Password file access attempt', 'atomic-edge-security' ),
				'/etc/shadow'                                                        => __( 'Shadow file access attempt', 'atomic-edge-security' ),
				'HACKED BY'                                                          => __( 'Defacement signature', 'atomic-edge-security' ),
				'c999sh'                                                             => __( 'Shell variant', 'atomic-edge-security' ),
				'r57sh'                                                              => __( 'Shell variant', 'atomic-edge-security' ),
			),

			// Medium: Hex-encoded function calls (used to evade detection).
			'hex_obfuscation'      => array(
				'\\\\x65\\\\x76\\\\x61\\\\x6c'                                       => __( 'Hex-encoded eval', 'atomic-edge-security' ),
				'\\\\x61\\\\x73\\\\x73\\\\x65\\\\x72\\\\x74'                         => __( 'Hex-encoded assert', 'atomic-edge-security' ),
				'\\\\x73\\\\x79\\\\x73\\\\x74\\\\x65\\\\x6d'                         => __( 'Hex-encoded system', 'atomic-edge-security' ),
				'\\\\x65\\\\x78\\\\x65\\\\x63'                                       => __( 'Hex-encoded exec', 'atomic-edge-security' ),
			),
		);

		return $this->refined_patterns_cache;
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
