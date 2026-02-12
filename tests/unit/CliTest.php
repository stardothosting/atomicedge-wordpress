<?php
/**
 * AtomicEdge CLI Tests
 *
 * Comprehensive tests for AtomicEdge_CLI WP-CLI commands.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;

/**
 * CLI Command Test Suite
 */
class CliTest extends TestCase {

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		if ( ! defined( 'WP_CLI' ) ) {
			define( 'WP_CLI', true );
		}

		\AtomicEdge\Tests\WP_CLI::reset();

		if ( ! class_exists( '\\AtomicEdge_CLI' ) ) {
			require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cli.php';
		}
	}

	/**
	 * Helper to inject mock scanner into CLI instance.
	 *
	 * @param \AtomicEdge_CLI                                       $cli     CLI instance.
	 * @param \AtomicEdge_Scanner|\PHPUnit\Framework\MockObject\MockObject $scanner Mock scanner.
	 * @return void
	 */
	private function inject_scanner( $cli, $scanner ) {
		$reflection = new \ReflectionClass( $cli );
		$property   = $reflection->getProperty( 'scanner' );
		$property->setAccessible( true );
		$property->setValue( $cli, $scanner );
	}

	// =========================================================================
	// Scan Command Tests
	// =========================================================================

	/**
	 * Test scan with full type reports success when no issues found.
	 */
	public function test_scan_full_reports_success_when_no_results() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'run_full_scan' )->willReturn(
			array(
				'core_files' => array(),
				'suspicious' => array(),
			)
		);

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array( 'type' => 'full' ) );

		$this->assertSame( array( 'No issues found!' ), \AtomicEdge\Tests\WP_CLI::$successes );
		$this->assertSame( array(), \AtomicEdge\Tests\WP_CLI::$errors );
	}

	/**
	 * Test scan with core type invokes core scan method.
	 */
	public function test_scan_core_invokes_core_scan() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->expects( $this->once() )->method( 'scan_core_files' )->willReturn( array() );

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array( 'type' => 'core' ) );

		$this->assertSame( array( 'No issues found!' ), \AtomicEdge\Tests\WP_CLI::$successes );
	}

	/**
	 * Test scan with suspicious type invokes suspicious scan method.
	 */
	public function test_scan_suspicious_invokes_suspicious_scan() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->expects( $this->once() )->method( 'scan_suspicious_files' )->willReturn( array() );

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array( 'type' => 'suspicious' ) );

		$this->assertSame( array( 'No issues found!' ), \AtomicEdge\Tests\WP_CLI::$successes );
	}

	/**
	 * Test scan outputs issue counts when issues found.
	 */
	public function test_scan_outputs_issue_counts() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'run_full_scan' )->willReturn(
			array(
				'core_files' => array(
					array(
						'file'     => 'wp-content/test.php',
						'severity' => 'critical',
						'type'     => 'malware',
						'pattern'  => 'eval(base64_decode',
					),
				),
				'suspicious' => array(
					array(
						'file'     => 'wp-content/suspicious.php',
						'severity' => 'high',
						'type'     => 'obfuscation',
						'pattern'  => 'str_rot13',
					),
					array(
						'file'     => 'wp-content/medium.php',
						'severity' => 'medium',
						'type'     => 'suspicious',
						'pattern'  => 'file_put_contents',
					),
				),
			)
		);

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array( 'type' => 'full', 'format' => 'table' ) );

		$logs = implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs );
		$this->assertStringContainsString( 'Found 3 issues', $logs );
		$this->assertStringContainsString( '1 critical', $logs );
		$this->assertStringContainsString( '1 high', $logs );
	}

	/**
	 * Test scan severity filter excludes lower severity issues.
	 */
	public function test_scan_severity_filter_high_excludes_medium_low() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'run_full_scan' )->willReturn(
			array(
				'core_files' => array(),
				'suspicious' => array(
					array( 'file' => 'high.php', 'severity' => 'high', 'type' => 'test', 'pattern' => 'x' ),
					array( 'file' => 'medium.php', 'severity' => 'medium', 'type' => 'test', 'pattern' => 'x' ),
					array( 'file' => 'low.php', 'severity' => 'low', 'type' => 'test', 'pattern' => 'x' ),
				),
			)
		);

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array( 'severity' => 'high', 'format' => 'table' ) );

		$logs = implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs );
		// With severity=high, only high and above should be counted.
		$this->assertStringContainsString( 'Found 1 issues', $logs );
	}

	/**
	 * Test scan severity filter critical only shows critical.
	 */
	public function test_scan_severity_filter_critical_only() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'run_full_scan' )->willReturn(
			array(
				'core_files' => array(),
				'suspicious' => array(
					array( 'file' => 'critical.php', 'severity' => 'critical', 'type' => 'test', 'pattern' => 'x' ),
					array( 'file' => 'high.php', 'severity' => 'high', 'type' => 'test', 'pattern' => 'x' ),
				),
			)
		);

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array( 'severity' => 'critical', 'format' => 'table' ) );

		$logs = implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs );
		$this->assertStringContainsString( 'Found 1 issues', $logs );
		$this->assertStringContainsString( '1 critical', $logs );
	}

	/**
	 * Test scan reports error exit when critical issues found.
	 */
	public function test_scan_reports_error_on_critical_issues() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'run_full_scan' )->willReturn(
			array(
				'core_files' => array(
					array( 'file' => 'bad.php', 'severity' => 'critical', 'type' => 'malware', 'pattern' => 'eval' ),
				),
				'suspicious' => array(),
			)
		);

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array( 'format' => 'table' ) );

		// Should call WP_CLI::error with "Critical issues found!".
		$this->assertContains( 'Critical issues found!', \AtomicEdge\Tests\WP_CLI::$errors );
	}

	/**
	 * Test scan handles scanner returning false.
	 */
	public function test_scan_handles_scanner_returning_false() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'run_full_scan' )->willReturn( false );

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array() );

		// Should still report no issues (false converts to empty array).
		$this->assertSame( array( 'No issues found!' ), \AtomicEdge\Tests\WP_CLI::$successes );
	}

	/**
	 * Test scan defaults to full type when invalid type provided.
	 */
	public function test_scan_defaults_to_full_type() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->expects( $this->once() )->method( 'run_full_scan' )->willReturn(
			array( 'core_files' => array(), 'suspicious' => array() )
		);

		$this->inject_scanner( $cli, $scanner );

		$cli->scan( array(), array( 'type' => 'invalid' ) );

		$this->assertSame( array( 'No issues found!' ), \AtomicEdge\Tests\WP_CLI::$successes );
	}

	// =========================================================================
	// Stats Command Tests
	// =========================================================================

	/**
	 * Test stats command logs summary information.
	 */
	public function test_stats_logs_summary() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'get_scan_statistics' )->willReturn(
			array(
				'total_patterns'    => 3,
				'categories'        => array( 'core' => 1, 'plugins' => 2 ),
				'scan_areas'        => array( 'core', 'plugins' ),
				'whitelisted_paths' => 0,
			)
		);
		$scanner->method( 'get_last_scan_time' )->willReturn( null );

		$this->inject_scanner( $cli, $scanner );

		$cli->stats( array(), array() );

		$this->assertNotEmpty( \AtomicEdge\Tests\WP_CLI::$logs );
		$this->assertStringContainsString( 'Total Patterns', implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs ) );
	}

	/**
	 * Test stats shows categories breakdown.
	 */
	public function test_stats_shows_categories() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'get_scan_statistics' )->willReturn(
			array(
				'total_patterns'    => 10,
				'categories'        => array( 'malware' => 5, 'obfuscation' => 3, 'backdoor' => 2 ),
				'scan_areas'        => array( 'core', 'plugins', 'themes' ),
				'whitelisted_paths' => 5,
			)
		);
		$scanner->method( 'get_last_scan_time' )->willReturn( null );

		$this->inject_scanner( $cli, $scanner );

		$cli->stats( array(), array() );

		$logs = implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs );
		$this->assertStringContainsString( 'malware: 5', $logs );
		$this->assertStringContainsString( 'obfuscation: 3', $logs );
		$this->assertStringContainsString( 'backdoor: 2', $logs );
	}

	/**
	 * Test stats shows scan areas.
	 */
	public function test_stats_shows_scan_areas() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'get_scan_statistics' )->willReturn(
			array(
				'total_patterns'    => 5,
				'categories'        => array(),
				'scan_areas'        => array( 'core', 'plugins', 'themes', 'uploads' ),
				'whitelisted_paths' => 0,
			)
		);
		$scanner->method( 'get_last_scan_time' )->willReturn( null );

		$this->inject_scanner( $cli, $scanner );

		$cli->stats( array(), array() );

		$logs = implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs );
		$this->assertStringContainsString( 'Scan Areas:', $logs );
		$this->assertStringContainsString( 'core', $logs );
		$this->assertStringContainsString( 'plugins', $logs );
	}

	/**
	 * Test stats shows whitelist count.
	 */
	public function test_stats_shows_whitelist_count() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'get_scan_statistics' )->willReturn(
			array(
				'total_patterns'    => 5,
				'categories'        => array(),
				'scan_areas'        => array(),
				'whitelisted_paths' => 12,
			)
		);
		$scanner->method( 'get_last_scan_time' )->willReturn( null );

		$this->inject_scanner( $cli, $scanner );

		$cli->stats( array(), array() );

		$logs = implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs );
		$this->assertStringContainsString( 'Whitelisted Paths: 12', $logs );
	}

	/**
	 * Test stats shows last scan time when available.
	 */
	public function test_stats_shows_last_scan_time() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'get_scan_statistics' )->willReturn(
			array(
				'total_patterns' => 5,
				'categories'     => array(),
				'scan_areas'     => array(),
			)
		);
		$scanner->method( 'get_last_scan_time' )->willReturn( '2026-01-15 10:30:00' );

		$this->inject_scanner( $cli, $scanner );

		$cli->stats( array(), array() );

		$logs = implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs );
		$this->assertStringContainsString( 'Last Scan: 2026-01-15 10:30:00', $logs );
	}

	// =========================================================================
	// Test File Command Tests
	// =========================================================================

	/**
	 * Test test_file command errors when no file specified.
	 */
	public function test_test_file_errors_when_no_file() {
		$cli = new \AtomicEdge_CLI();

		$cli->test_file( array(), array() );

		$this->assertContains( 'Please specify a file path.', \AtomicEdge\Tests\WP_CLI::$errors );
	}

	/**
	 * Test test_file command errors when file not found.
	 */
	public function test_test_file_errors_when_file_not_found() {
		$cli = new \AtomicEdge_CLI();

		$cli->test_file( array( '/nonexistent/file.php' ), array() );

		$errors = implode( "\n", \AtomicEdge\Tests\WP_CLI::$errors );
		$this->assertStringContainsString( 'File not found', $errors );
	}

	/**
	 * Test test_file succeeds on clean file.
	 */
	public function test_test_file_succeeds_on_clean_file() {
		$cli = new \AtomicEdge_CLI();

		// Inject scanner with mocked API to avoid real HTTP requests.
		$scanner = $this->create_scanner_with_mocked_api();
		$this->inject_scanner( $cli, $scanner );

		// Create a temp file with clean content.
		$temp_file = sys_get_temp_dir() . '/atomicedge_test_clean_' . uniqid() . '.php';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $temp_file, '<?php echo "Hello World"; ?>' );

		try {
			$cli->test_file( array( $temp_file ), array() );

			$this->assertSame( array( 'No suspicious patterns found in this file.' ), \AtomicEdge\Tests\WP_CLI::$successes );
		} finally {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			unlink( $temp_file );
		}
	}

	/**
	 * Test test_file detects suspicious patterns.
	 */
	public function test_test_file_detects_suspicious_patterns() {
		$cli = new \AtomicEdge_CLI();

		// Create a mock API that returns malware signatures.
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->onlyMethods( array( 'get_malware_signatures' ) )
			->getMock();

		$mock_api->method( 'get_malware_signatures' )->willReturn(
			array(
				'version'          => '1.0.0',
				'patterns'         => array(
					'code_execution' => array(
						'eval\s*\(' => 'Eval function call',
						'base64_decode\s*\(' => 'Base64 decode usage',
					),
				),
				'quick_indicators' => array( 'eval(', 'base64_decode(' ),
				'severity_map'     => array( 'code_execution' => 'critical' ),
			)
		);

		// Create a scanner with the mock API.
		$scanner = new \AtomicEdge_Scanner( $mock_api );
		$this->inject_scanner( $cli, $scanner );

		// Create a temp file with suspicious content.
		$temp_file = sys_get_temp_dir() . '/atomicedge_test_suspicious_' . uniqid() . '.php';
		// Use eval/base64 which is a common malware pattern.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $temp_file, '<?php eval(base64_decode("test")); ?>' );

		try {
			$cli->test_file( array( $temp_file ), array() );

			// Should have warnings about pattern matches.
			$this->assertNotEmpty( \AtomicEdge\Tests\WP_CLI::$warnings );
			$warnings = implode( "\n", \AtomicEdge\Tests\WP_CLI::$warnings );
			$this->assertStringContainsString( 'pattern matches', $warnings );
		} finally {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			unlink( $temp_file );
		}
	}
}
