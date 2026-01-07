<?php
/**
 * AtomicEdge WP-CLI Commands
 *
 * Provides command-line interface for scanner operations.
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Only load if WP-CLI is available.
if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * AtomicEdge Security Scanner CLI Commands.
 *
 * @package AtomicEdge
 */
class AtomicEdge_CLI {

	/**
	 * Scanner instance.
	 *
	 * @var AtomicEdge_Scanner
	 */
	private $scanner;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->scanner = new AtomicEdge_Scanner();
	}

	/**
	 * Run a full malware scan.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * [--severity=<severity>]
	 * : Filter by minimum severity level.
	 * ---
	 * default: low
	 * options:
	 *   - critical
	 *   - high
	 *   - medium
	 *   - low
	 * ---
	 *
	 * [--type=<type>]
	 * : Type of scan to run.
	 * ---
	 * default: full
	 * options:
	 *   - full
	 *   - core
	 *   - suspicious
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Run a full scan
	 *     $ wp atomicedge scan
	 *
	 *     # Run suspicious files scan only with JSON output
	 *     $ wp atomicedge scan --type=suspicious --format=json
	 *
	 *     # Run scan and show only critical/high severity
	 *     $ wp atomicedge scan --severity=high
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function scan( $args, $assoc_args ) {
		$format   = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table';
		$severity = isset( $assoc_args['severity'] ) ? $assoc_args['severity'] : 'low';
		$type     = isset( $assoc_args['type'] ) ? $assoc_args['type'] : 'full';

		WP_CLI::log( 'Starting Atomic Edge security scan...' );
		WP_CLI::log( '' );

		$results = array();
		$start_time = microtime( true );

		switch ( $type ) {
			case 'core':
				WP_CLI::log( 'Scanning WordPress core files...' );
				$core_results = $this->scanner->scan_core_files();
				if ( false !== $core_results ) {
					$results = $core_results;
				}
				break;

			case 'suspicious':
				WP_CLI::log( 'Scanning for suspicious patterns...' );
				$suspicious_results = $this->scanner->scan_suspicious_files();
				if ( false !== $suspicious_results ) {
					$results = $suspicious_results;
				}
				break;

			case 'full':
			default:
				WP_CLI::log( 'Running full scan (core + suspicious patterns)...' );
				$full_results = $this->scanner->run_full_scan();
				if ( false !== $full_results ) {
					$results = array_merge(
						isset( $full_results['core_files'] ) ? $full_results['core_files'] : array(),
						isset( $full_results['suspicious'] ) ? $full_results['suspicious'] : array()
					);
				}
				break;
		}

		$elapsed = round( microtime( true ) - $start_time, 2 );
		WP_CLI::log( '' );
		WP_CLI::log( sprintf( 'Scan completed in %s seconds.', $elapsed ) );
		WP_CLI::log( '' );

		// Filter by severity.
		$severity_order = array( 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1 );
		$min_severity   = isset( $severity_order[ $severity ] ) ? $severity_order[ $severity ] : 1;

		$filtered_results = array_filter(
			$results,
			function ( $item ) use ( $severity_order, $min_severity ) {
				$item_severity = isset( $item['severity'] ) ? $item['severity'] : 'low';
				$item_level    = isset( $severity_order[ $item_severity ] ) ? $severity_order[ $item_severity ] : 1;
				return $item_level >= $min_severity;
			}
		);

		if ( empty( $filtered_results ) ) {
			WP_CLI::success( 'No issues found!' );
			return;
		}

		// Count by severity.
		$counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0 );
		foreach ( $filtered_results as $item ) {
			$sev = isset( $item['severity'] ) ? $item['severity'] : 'low';
			if ( isset( $counts[ $sev ] ) ) {
				++$counts[ $sev ];
			}
		}

		WP_CLI::log( sprintf(
			'Found %d issues: %d critical, %d high, %d medium, %d low',
			count( $filtered_results ),
			$counts['critical'],
			$counts['high'],
			$counts['medium'],
			$counts['low']
		) );
		WP_CLI::log( '' );

		// Format output.
		$output_items = array();
		foreach ( $filtered_results as $item ) {
			$output_items[] = array(
				'File'     => isset( $item['file'] ) ? $item['file'] : 'unknown',
				'Severity' => isset( $item['severity'] ) ? strtoupper( $item['severity'] ) : 'LOW',
				'Type'     => isset( $item['type'] ) ? $item['type'] : 'unknown',
				'Details'  => isset( $item['pattern'] ) ? $item['pattern'] : ( isset( $item['reason'] ) ? $item['reason'] : '' ),
			);
		}

		WP_CLI\Utils\format_items( $format, $output_items, array( 'File', 'Severity', 'Type', 'Details' ) );

		// Exit with error code if critical issues found.
		if ( $counts['critical'] > 0 ) {
			WP_CLI::error( 'Critical issues found!', false );
		}
	}

	/**
	 * Show scanner statistics and configuration.
	 *
	 * ## EXAMPLES
	 *
	 *     # Show scanner stats
	 *     $ wp atomicedge stats
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function stats( $args, $assoc_args ) {
		$stats = $this->scanner->get_scan_statistics();

		WP_CLI::log( 'Atomic Edge Scanner Statistics' );
		WP_CLI::log( '==============================' );
		WP_CLI::log( '' );
		WP_CLI::log( sprintf( 'Total Patterns: %d', $stats['total_patterns'] ) );
		WP_CLI::log( '' );
		WP_CLI::log( 'Patterns by Category:' );

		foreach ( $stats['categories'] as $category => $count ) {
			WP_CLI::log( sprintf( '  - %s: %d', $category, $count ) );
		}

		WP_CLI::log( '' );
		WP_CLI::log( 'Scan Areas:' );
		foreach ( $stats['scan_areas'] as $area ) {
			WP_CLI::log( sprintf( '  - %s', $area ) );
		}

		// Show whitelist stats if available.
		if ( isset( $stats['whitelisted_paths'] ) ) {
			WP_CLI::log( '' );
			WP_CLI::log( sprintf( 'Whitelisted Paths: %d', $stats['whitelisted_paths'] ) );
		}

		$last_scan = $this->scanner->get_last_scan_time();
		if ( $last_scan ) {
			WP_CLI::log( '' );
			WP_CLI::log( sprintf( 'Last Scan: %s', $last_scan ) );
		}
	}

	/**
	 * Test scanner patterns against a specific file.
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : Path to the file to test.
	 *
	 * [--show-content]
	 * : Show matching content snippets.
	 *
	 * ## EXAMPLES
	 *
	 *     # Test a specific file
	 *     $ wp atomicedge test-file /path/to/file.php
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function test_file( $args, $assoc_args ) {
		if ( empty( $args[0] ) ) {
			WP_CLI::error( 'Please specify a file path.' );
			return;
		}

		$file = $args[0];

		if ( ! file_exists( $file ) ) {
			WP_CLI::error( 'File not found: ' . $file );
			return;
		}

		$show_content = isset( $assoc_args['show-content'] );

		WP_CLI::log( sprintf( 'Testing file: %s', $file ) );
		WP_CLI::log( '' );

		// Read file content.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$content = file_get_contents( $file );

		if ( false === $content ) {
			WP_CLI::error( 'Could not read file.' );
			return;
		}

		// Test against patterns using reflection to access private method.
		$reflection = new ReflectionClass( $this->scanner );
		$method     = $reflection->getMethod( 'get_malware_patterns' );
		$method->setAccessible( true );
		$patterns = $method->invoke( $this->scanner );

		$matches = array();

		foreach ( $patterns as $group_name => $group_patterns ) {
			foreach ( $group_patterns as $pattern => $description ) {
				// Use # as delimiter to avoid issues with / in patterns.
				if ( preg_match( '#' . $pattern . '#i', $content, $match ) ) {
					$matches[] = array(
						'Category'    => $group_name,
						'Description' => $description,
						'Match'       => $show_content ? substr( $match[0], 0, 50 ) : '[hidden]',
					);
				}
			}
		}

		if ( empty( $matches ) ) {
			WP_CLI::success( 'No suspicious patterns found in this file.' );
			return;
		}

		WP_CLI::warning( sprintf( 'Found %d pattern matches:', count( $matches ) ) );
		WP_CLI::log( '' );

		WP_CLI\Utils\format_items( 'table', $matches, array( 'Category', 'Description', 'Match' ) );

		// Check if file should be whitelisted.
		$relative_path = str_replace( ABSPATH, '', $file );

		$whitelist_method = $reflection->getMethod( 'is_whitelisted_path' );
		$whitelist_method->setAccessible( true );
		$is_whitelisted = $whitelist_method->invoke( $this->scanner, $relative_path );

		if ( $is_whitelisted ) {
			WP_CLI::log( '' );
			WP_CLI::log( 'Note: This file path is WHITELISTED and would be skipped in a normal scan.' );
		}
	}
}

// Register commands.
WP_CLI::add_command( 'atomicedge', 'AtomicEdge_CLI' );
