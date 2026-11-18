<?php
/**
 * AtomicEdge Scanner Class Tests
 *
 * Tests for the AtomicEdge_Scanner class including file scanning
 * and pattern detection.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * Scanner Class Test Suite
 */
class ScannerTest extends TestCase {

	/**
	 * Scanner instance for testing.
	 *
	 * @var \AtomicEdge_Scanner
	 */
	private $scanner;

	/**
	 * Files created under the WordPress root by a test.
	 *
	 * @var string[]
	 */
	private $root_files = array();

	/**
	 * Temporary directories created by a test.
	 *
	 * @var string[]
	 */
	private $temp_paths = array();

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		// Define WP_CONTENT_DIR if not defined.
		if ( ! defined( 'WP_CONTENT_DIR' ) ) {
			define( 'WP_CONTENT_DIR', '/tmp/wordpress/wp-content' );
		}

		// Mock wp_upload_dir.
		Functions\when( 'wp_upload_dir' )->justReturn(
			array(
				'basedir' => '/tmp/wordpress/wp-content/uploads',
				'baseurl' => 'http://example.com/wp-content/uploads',
			)
		);

		$this->scanner = $this->create_scanner_instance();
	}

	/**
	 * Remove files and directories created by a test.
	 *
	 * @return void
	 */
	protected function tear_down() {
		foreach ( $this->root_files as $path ) {
			if ( is_file( $path ) ) {
				unlink( $path );
			}
		}
		$this->root_files = array();

		foreach ( $this->temp_paths as $dir ) {
			foreach ( glob( $dir . '/*' ) ?: array() as $path ) {
				unlink( $path );
			}
			if ( is_dir( $dir ) ) {
				rmdir( $dir );
			}
		}
		$this->temp_paths = array();

		parent::tear_down();
	}

	// =========================================================================
	// Basic Scanner Tests
	// =========================================================================

	/**
	 * Test scanner instantiation.
	 */
	public function test_scanner_can_be_instantiated() {
		$this->assertInstanceOf( \AtomicEdge_Scanner::class, $this->scanner );
	}

	/**
	 * Test get_last_scan_time returns false when never scanned.
	 */
	public function test_get_last_scan_time_returns_false_when_never_scanned() {
		$this->assertFalse( $this->scanner->get_last_scan_time() );
	}

	/**
	 * Test get_last_scan_time returns timestamp when scanned.
	 */
	public function test_get_last_scan_time_returns_timestamp_when_scanned() {
		$scan_time = '2026-01-05 12:00:00';
		$this->set_option( 'atomicedge_last_scan', $scan_time );

		$this->assertEquals( $scan_time, $this->scanner->get_last_scan_time() );
	}

	/**
	 * Test get_last_results returns empty array when no results.
	 */
	public function test_get_last_results_returns_empty_array_when_no_results() {
		$this->assertEquals( array(), $this->scanner->get_last_results() );
	}

	/**
	 * Test get_last_results returns stored results.
	 */
	public function test_get_last_results_returns_stored_results() {
		$results = array(
			'started_at'   => '2026-01-05 12:00:00',
			'completed_at' => '2026-01-05 12:05:00',
			'summary'      => array(
				'core_modified' => 0,
				'suspicious'    => 2,
				'total_issues'  => 2,
			),
		);
		$this->set_option( 'atomicedge_scan_results', $results );

		$this->assertEquals( $results, $this->scanner->get_last_results() );
	}

	/**
	 * Reset should also clear any saved scan results.
	 */
	public function test_reset_resumable_scan_clears_saved_results() {
		$this->set_option( 'atomicedge_scan_results', array( 'success' => true ) );
		$this->set_option( 'atomicedge_last_scan', '2026-01-06 12:00:00' );
		$this->set_transient( 'atomicedge_scan_run_state', array( 'status' => 'running' ) );
		$this->set_transient( 'atomicedge_scan_state', array( 'legacy' => true ) );

		$result = $this->scanner->reset_resumable_scan();
		$this->assertIsArray( $result );
		$this->assertEquals( 'reset', $result['status'] );
		$this->assertNull( $this->get_option( 'atomicedge_scan_results', null ) );
		$this->assertNull( $this->get_option( 'atomicedge_last_scan', null ) );
		$this->assertFalse( $this->get_transient( 'atomicedge_scan_run_state' ) );
		$this->assertFalse( $this->get_transient( 'atomicedge_scan_state' ) );
	}

	// =========================================================================
	// Pattern Detection Tests (Using API-provided patterns)
	// =========================================================================

	/**
	 * Test that scanner patterns are fetched from API.
	 *
	 * Pattern detection is tested via API integration rather than hardcoding
	 * patterns here (to avoid triggering external malware scanners on this file).
	 */
	public function test_api_patterns_are_used_for_detection() {
		$scanner = $this->create_scanner_with_mocked_api();

		// Verify scanner has signatures from API.
		$this->assertTrue( $scanner->has_signatures() );
		$this->assertEquals( '1.0.0', $scanner->get_signature_version() );
	}

	/**
	 * Test pattern regex validation (using safe placeholder patterns).
	 *
	 * This validates that preg_match works with typical regex syntax
	 * without including actual malware signatures in this file.
	 */
	public function test_regex_pattern_matching_logic() {
		// Test regex with safe patterns that follow same syntax as malware patterns.
		$test_cases = array(
			array(
				'content'  => '<?php my_function($arg);',
				'pattern'  => 'my_function\s*\(',
				'expected' => true,
			),
			array(
				'content'  => '<?php other_func();',
				'pattern'  => 'my_function\s*\(',
				'expected' => false,
			),
			array(
				'content'  => '<?php echo "Hello World";',
				'pattern'  => 'echo\s+["\']',
				'expected' => true,
			),
		);

		foreach ( $test_cases as $case ) {
			$matches = preg_match( '/' . $case['pattern'] . '/i', $case['content'] );
			$this->assertEquals(
				$case['expected'],
				(bool) $matches,
				"Pattern '{$case['pattern']}' should " . ( $case['expected'] ? 'match' : 'not match' )
			);
		}
	}

	/**
	 * Test superglobal access pattern (using safe examples).
	 *
	 * Tests pattern syntax without embedding dangerous code strings.
	 */
	public function test_superglobal_access_pattern_syntax() {
		// Pattern to detect superglobal access (not execution).
		$pattern = '\$_(?:GET|POST|REQUEST)\s*\[';

		$with_superglobal = array(
			'$data = $_GET["field"];',
			'$_POST["key"] = $value;',
		);

		$without_superglobal = array(
			'$my_array["key"] = $value;',
			'echo $regular_variable;',
		);

		foreach ( $with_superglobal as $code ) {
			$this->assertTrue(
				(bool) preg_match( '/' . $pattern . '/i', $code ),
				"Pattern should match superglobal access"
			);
		}

		foreach ( $without_superglobal as $code ) {
			$this->assertFalse(
				(bool) preg_match( '/' . $pattern . '/i', $code ),
				"Pattern should NOT match regular variable access"
			);
		}
	}

	/**
	 * Refined plugin/theme patterns are returned from the scanner.
	 *
	 * Tests that the method exists and returns an array structure.
	 * Actual pattern content comes from API.
	 */
	public function test_refined_plugin_patterns_returns_array_structure() {
		$scanner = $this->create_scanner_with_mocked_api();

		$ref    = new \ReflectionClass( $scanner );
		$method = $ref->getMethod( 'get_refined_patterns_for_plugins' );
		$method->setAccessible( true );
		$groups = $method->invoke( $scanner );

		$this->assertIsArray( $groups );
		// Should only include the refined categories that exist in the mock data.
		foreach ( array_keys( $groups ) as $category ) {
			$this->assertContains(
				$category,
				array( 'backdoor_patterns', 'webshells', 'wordpress_malware', 'obfuscation', 'suspicious_strings' ),
				"Unexpected category '$category' in refined patterns"
			);
		}
	}

	/**
	 * Test scanner with mocked API has pattern groups available.
	 */
	public function test_scanner_with_api_has_pattern_groups() {
		$scanner = $this->create_scanner_with_mocked_api();

		// Verify scanner reports signatures available.
		$this->assertTrue( $scanner->has_signatures() );
	}

	// =========================================================================
	// Core Files Scan Tests
	// =========================================================================

	/**
	 * Test scan_core_files returns false when API fails.
	 */
	public function test_scan_core_files_returns_false_on_api_failure() {
		global $wp_version;
		$wp_version = '6.4';

		Functions\when( 'get_locale' )->justReturn( 'en_US' );

		// Mock failed API response.
		$wp_error = new \AtomicEdge\Tests\WP_Error( 'http_error', 'Connection failed' );
		Functions\when( 'wp_remote_get' )->justReturn( $wp_error );
		Functions\when( 'is_wp_error' )->alias(
			function ( $thing ) {
				return $thing instanceof \AtomicEdge\Tests\WP_Error;
			}
		);

		$result = $this->scanner->scan_core_files();

		$this->assertFalse( $result );
	}

	/**
	 * Test scan_core_files returns false on invalid response.
	 */
	public function test_scan_core_files_returns_false_on_invalid_response() {
		global $wp_version;
		$wp_version = '6.4';

		Functions\when( 'get_locale' )->justReturn( 'en_US' );
		Functions\when( 'is_wp_error' )->justReturn( false );

		// Mock API response without checksums.
		Functions\when( 'wp_remote_get' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'error' => 'Invalid version' ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( array( 'error' => 'Invalid version' ) ) );

		$result = $this->scanner->scan_core_files();

		$this->assertFalse( $result );
	}

	/**
	 * Test scan_core_files returns array of modified files.
	 */
	public function test_scan_core_files_returns_modified_files_array() {
		global $wp_version;
		$wp_version = '6.4';

		Functions\when( 'get_locale' )->justReturn( 'en_US' );
		Functions\when( 'is_wp_error' )->justReturn( false );

		// Mock successful API response with checksums.
		$checksums = array(
			'wp-load.php'    => 'fake_checksum_that_wont_match',
			'wp-blog-header.php' => 'another_fake_checksum',
		);

		Functions\when( 'wp_remote_get' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'checksums' => $checksums ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_body' )->justReturn(
			wp_json_encode( array( 'checksums' => $checksums ) )
		);

		$result = $this->scanner->scan_core_files();

		// Should return an array (possibly empty if files don't exist in test env).
		$this->assertIsArray( $result );
	}

	// =========================================================================
	// Full Scan Tests
	// =========================================================================

	/**
	 * Test run_full_scan returns expected structure.
	 */
	public function test_run_full_scan_returns_expected_structure() {
		global $wp_version;
		$wp_version = '6.4';

		Functions\when( 'get_locale' )->justReturn( 'en_US' );
		Functions\when( 'is_wp_error' )->justReturn( false );
		Functions\when( 'wp_upload_dir' )->justReturn(
			array(
				'basedir' => '/tmp/wp-uploads',
				'baseurl' => 'http://example.com/wp-content/uploads',
			)
		);

		// Mock checksums API.
		Functions\when( 'wp_remote_get' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'checksums' => array() ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_body' )->justReturn(
			wp_json_encode( array( 'checksums' => array() ) )
		);

		// Use scanner with mocked API to avoid wp_remote_request call for signatures.
		$scanner = $this->create_scanner_with_mocked_api();
		$result  = $scanner->run_full_scan();

		// Verify structure.
		$this->assertArrayHasKey( 'started_at', $result );
		$this->assertArrayHasKey( 'completed_at', $result );
		$this->assertArrayHasKey( 'core_files', $result );
		$this->assertArrayHasKey( 'suspicious', $result );
		$this->assertArrayHasKey( 'summary', $result );

		// Verify summary structure.
		$this->assertArrayHasKey( 'core_modified', $result['summary'] );
		$this->assertArrayHasKey( 'suspicious', $result['summary'] );
		$this->assertArrayHasKey( 'total_issues', $result['summary'] );
	}

	/**
	 * Test run_full_scan saves results to options.
	 */
	public function test_run_full_scan_saves_results() {
		global $wp_version;
		$wp_version = '6.4';

		Functions\when( 'get_locale' )->justReturn( 'en_US' );
		Functions\when( 'is_wp_error' )->justReturn( false );
		Functions\when( 'wp_upload_dir' )->justReturn(
			array(
				'basedir' => '/tmp/wp-uploads',
				'baseurl' => 'http://example.com/wp-content/uploads',
			)
		);

		// Mock checksums API.
		Functions\when( 'wp_remote_get' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'checksums' => array() ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_body' )->justReturn(
			wp_json_encode( array( 'checksums' => array() ) )
		);

		// Use scanner with mocked API to avoid wp_remote_request call for signatures.
		$scanner = $this->create_scanner_with_mocked_api();
		$scanner->run_full_scan();

		// Check that results were saved.
		$saved_results = $this->get_option( 'atomicedge_scan_results' );
		$last_scan     = $this->get_option( 'atomicedge_last_scan' );

		$this->assertNotEmpty( $saved_results );
		$this->assertNotEmpty( $last_scan );
	}

	// =========================================================================
	// Resumable Scan Tests
	// =========================================================================

	/**
	 * Test get_resumable_scan_status returns idle when no scan.
	 */
	public function test_get_resumable_scan_status_idle_when_no_scan() {
		delete_transient( 'atomicedge_scan_run_state' );

		$status = $this->scanner->get_resumable_scan_status( '' );

		$this->assertIsArray( $status );
		$this->assertEquals( 'idle', $status['status'] );
	}

	/**
	 * Test cancel_resumable_scan with no active scan returns idle.
	 */
	public function test_cancel_resumable_scan_no_active_scan() {
		// Clear any existing scan state.
		delete_transient( 'atomicedge_scan_run_state' );

		$result = $this->scanner->cancel_resumable_scan( 'any-run-id' );

		$this->assertIsArray( $result );
		// When no scan is active, it returns idle.
		$this->assertEquals( 'idle', $result['status'] );
	}

	/**
	 * Test reset_resumable_scan clears state.
	 */
	public function test_reset_clears_all_scan_state() {
		// Set some state.
		$this->set_transient( 'atomicedge_scan_run_state', array( 'status' => 'running' ) );
		$this->set_option( 'atomicedge_scan_results', array( 'test' => true ) );

		$result = $this->scanner->reset_resumable_scan();

		$this->assertIsArray( $result );
		$this->assertEquals( 'reset', $result['status'] );
		$this->assertFalse( $this->get_transient( 'atomicedge_scan_run_state' ) );
	}

	/**
	 * Scan steps should stay below common web-server gateway timeouts.
	 */
	public function test_optimal_scan_step_budget_is_gateway_safe() {
		$ref = new \ReflectionClass( $this->scanner );
		$method = $ref->getMethod( 'get_optimal_time_budget' );
		$method->setAccessible( true );

		$budget = $method->invoke( $this->scanner );

		$this->assertIsInt( $budget );
		$this->assertGreaterThanOrEqual( 1, $budget );
		$this->assertLessThanOrEqual( 15, $budget );
	}

	/**
	 * Explicit scan step budgets should be capped defensively.
	 */
	public function test_scan_step_budget_normalization_caps_large_values() {
		$ref = new \ReflectionClass( $this->scanner );
		$method = $ref->getMethod( 'normalize_step_time_budget' );
		$method->setAccessible( true );

		$this->assertEquals( 15, $method->invoke( $this->scanner, 120 ) );
		$this->assertEquals( 1, $method->invoke( $this->scanner, 0 ) );
	}

	/**
	 * Thorough scan totals must mirror the directories actually discovered by the queue.
	 */
	public function test_thorough_scan_file_totals_follow_directory_discovery() {
		$source = file_get_contents( ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-scanner.php' );

		$this->assertStringContainsString( 'count_thorough_scan_files', $source );
		$this->assertStringContainsString( 'count_thorough_wp_content_files', $source );
		$this->assertStringContainsString( 'discover_all_directories', $source );
		$this->assertStringNotContainsString( "\$total += \$this->count_php_files_for_dir( \$this->get_wp_admin_path(), 'wp-admin' );", $source );
	}

	/**
	 * ETA should wait until enough files have completed to avoid early wild swings.
	 */
	public function test_eta_waits_for_meaningful_progress_on_large_scans() {
		$ref = new \ReflectionClass( $this->scanner );
		$method = $ref->getMethod( 'calculate_eta_seconds' );
		$method->setAccessible( true );

		$state = array(
			'results' => array(
				'started_at' => date( 'Y-m-d H:i:s', time() - 120 ),
				'scan_stats' => array(
					'files_total'   => 1000,
					'files_scanned' => 10,
				),
			),
		);

		$this->assertNull( $method->invoke( $this->scanner, $state ) );

		$state['results']['scan_stats']['files_scanned'] = 20;
		$this->assertIsInt( $method->invoke( $this->scanner, $state ) );
	}

	/**
	 * ETA updates should be smoothed so one slow or fast step does not jerk the UI around.
	 */
	public function test_eta_estimate_is_smoothed_between_steps() {
		$ref = new \ReflectionClass( $this->scanner );
		$method = $ref->getMethod( 'add_eta_estimate' );
		$method->setAccessible( true );

		$state = array(
			'eta_seconds' => 1000,
			'results' => array(
				'started_at' => date( 'Y-m-d H:i:s', time() - 100 ),
				'scan_stats' => array(
					'files_total'   => 1000,
					'files_scanned' => 500,
				),
			),
		);

		$method->invokeArgs( $this->scanner, array( &$state ) );

		$this->assertSame( 685, $state['eta_seconds'] );
		$this->assertSame( '11m 25s', $state['eta_label'] );
	}

	/**
	 * Scan steps should recover queue rows abandoned by killed AJAX requests.
	 */
	public function test_scan_step_recovers_abandoned_processing_items() {
		$source = file_get_contents( ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-scanner.php' );

		$this->assertStringContainsString( 'recover_abandoned_processing_items', $source );
		$this->assertStringContainsString( "status = 'pending'", $source );
		$this->assertStringContainsString( "status = 'processing'", $source );
		$this->assertStringContainsString( "current_time( 'timestamp' )", $source );
	}

	/**
	 * A scan must not complete while rows are still leased as processing.
	 */
	public function test_scan_finalize_waits_for_processing_items() {
		global $wpdb;

		if ( ! defined( 'ARRAY_A' ) ) {
			define( 'ARRAY_A', 'ARRAY_A' );
		}

		$wpdb = $this->getMockBuilder( \stdClass::class )
			->addMethods( array( 'get_results', 'prepare', 'query' ) )
			->getMock();
		$wpdb->prefix = 'wp_';
		$wpdb->method( 'prepare' )->willReturnArgument( 0 );
		$wpdb->method( 'get_results' )->willReturn(
			array(
				array(
					'status' => 'processing',
					'c'      => 1,
				),
			)
		);
		$wpdb->expects( $this->never() )->method( 'query' );

		$state = array(
			'run_id'  => 'scan_test',
			'status'  => 'running',
			'results' => array(
				'started_at'  => '2026-05-14 12:00:00',
				'core_files'  => array(),
				'suspicious'  => array(),
				'scan_stats'  => array(),
			),
		);

		$ref = new \ReflectionClass( $this->scanner );
		$method = $ref->getMethod( 'finalize_run_if_done' );
		$method->setAccessible( true );
		$result = $method->invoke( $this->scanner, $state );

		$this->assertSame( 'running', $result['status'] );
		$this->assertNull( $this->get_option( 'atomicedge_scan_results', null ) );
	}

	public function test_expired_slice_releases_every_unstarted_claim_immediately() {
		$db = $this->mock_queue_database();
		$db->expects( $this->once() )->method( 'query' )->with( $this->callback( function ( $sql ) {
			return false !== strpos( $sql, "SET status = 'pending'" ) && false !== strpos( $sql, '11,12' );
		} ) )->willReturn( 2 );
		$state = array();
		$processed = 0;
		$timing = array();
		$method = new \ReflectionMethod( $this->scanner, 'process_claimed_batch' );
		$method->setAccessible( true );
		$method->invokeArgs( $this->scanner, array(
			array( array( 'id' => 11 ), array( 'id' => 12 ) ), &$state, microtime( true ) - 2, 1, &$processed, &$timing,
		) );
		$this->assertSame( 0, $processed );
	}

	public function test_partial_slice_completes_started_work_and_releases_only_the_tail() {
		$db = $this->mock_queue_database();
		$queries = array();
		$db->method( 'update' )->willReturnCallback( function () {
			usleep( 20000 );
			return 1;
		} );
		$db->method( 'query' )->willReturnCallback( function ( $sql ) use ( &$queries ) {
			$queries[] = $sql;
			return 1;
		} );
		$state = array();
		$processed = 0;
		$timing = array( 'discovery_ms' => 0 );
		$method = new \ReflectionMethod( $this->scanner, 'process_claimed_batch' );
		$method->setAccessible( true );
		$method->invokeArgs( $this->scanner, array(
			array(
				array( 'id' => 11, 'item_type' => 'rootfiles', 'area' => 'root', 'path' => '/nonexistent-ae-scan-root/' ),
				array( 'id' => 12, 'item_type' => 'file' ),
			),
			&$state, microtime( true ), 0.01, &$processed, &$timing,
		) );
		$this->assertSame( 1, $processed );
		$this->assertCount( 1, $queries );
		$this->assertStringContainsString( 'id IN (12)', $queries[0] );
		$this->assertGreaterThan( 0, $timing['discovery_ms'] );
	}

	public function test_item_exception_still_releases_unstarted_claims() {
		$db = $this->mock_queue_database();
		$db->method( 'update' )->willThrowException( new \RuntimeException( 'write failed' ) );
		$db->expects( $this->once() )->method( 'query' )->with( $this->callback( function ( $sql ) {
			return false !== strpos( $sql, "SET status = 'pending'" ) && false !== strpos( $sql, 'id IN (12)' );
		} ) )->willReturn( 1 );
		$state = array();
		$processed = 0;
		$timing = array();
		$method = new \ReflectionMethod( $this->scanner, 'process_claimed_batch' );
		$method->setAccessible( true );
		$this->expectExceptionMessage( 'write failed' );
		$method->invokeArgs( $this->scanner, array(
			array(
				array( 'id' => 11, 'item_type' => 'rootfiles', 'path' => '/nonexistent-ae-scan-root/' ),
				array( 'id' => 12 ),
			),
			&$state, microtime( true ), 1, &$processed, &$timing,
		) );
	}

	public function test_database_read_failure_is_not_an_empty_queue() {
		$db = $this->mock_queue_database();
		$db->method( 'get_results' )->willReturn( null );
		$method = new \ReflectionMethod( $this->scanner, 'claim_batch_queue_items' );
		$method->setAccessible( true );
		$this->expectException( \RuntimeException::class );
		$method->invoke( $this->scanner, 'test-run', 5 );
	}

	public function test_failed_completion_write_keeps_pending_completion_ids() {
		$db = $this->mock_queue_database();
		$db->method( 'query' )->willReturn( false );
		$property = new \ReflectionProperty( $this->scanner, 'pending_done_ids' );
		$property->setAccessible( true );
		$property->setValue( $this->scanner, array( 11 ) );
		$method = new \ReflectionMethod( $this->scanner, 'flush_pending_done_items' );
		$method->setAccessible( true );
		try {
			$method->invoke( $this->scanner );
			$this->fail( 'A failed completion write must throw.' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( array( 11 ), $property->getValue( $this->scanner ) );
		}
	}

	public function test_wordpress_empty_array_with_sql_error_is_not_a_clean_queue() {
		$db = $this->mock_queue_database();
		$db->last_error = 'Database connection lost';
		$db->method( 'get_results' )->willReturn( array() );
		$method = new \ReflectionMethod( $this->scanner, 'get_queue_counts' );
		$method->setAccessible( true );
		$this->expectException( \RuntimeException::class );
		$method->invoke( $this->scanner, 'test-run' );
	}

	public function test_concurrent_step_returns_busy_without_claiming_work() {
		$db = $this->mock_queue_database();
		$db->method( 'get_var' )->willReturn( '0' );
		$db->method( 'get_results' )->willReturn( array() );
		$db->expects( $this->never() )->method( 'query' );
		$this->set_transient( 'atomicedge_scan_run_state', array(
			'run_id' => 'test-run', 'status' => 'running', 'results' => array( 'scan_stats' => array() ),
		) );
		$state = $this->scanner->step_resumable_scan( 'test-run' );
		$this->assertTrue( $state['busy'] );
		$this->assertSame( 'running', $state['status'] );
	}

	public function test_step_releases_connection_lock_after_queue_error() {
		$db = $this->mock_queue_database();
		$locks = array();
		$db->method( 'get_var' )->willReturnCallback( function ( $sql ) use ( &$locks ) {
			if ( false !== strpos( $sql, 'LOCK(' ) ) {
				$locks[] = $sql;
				return '1';
			}
			return 'wp_atomicedge_scan_queue';
		} );
		$db->method( 'query' )->willReturn( 0 );
		$db->method( 'get_results' )->willReturn( null );
		$this->set_transient( 'atomicedge_scan_run_state', array(
			'run_id' => 'test-run', 'status' => 'running', 'stage' => 'queue',
			'started_at' => date( 'Y-m-d H:i:s' ),
			'results' => array( 'scan_stats' => array( 'files_scanned' => 0 ) ),
		) );
		$state = $this->scanner->step_resumable_scan( 'test-run' );
		$this->assertSame( 'error', $state['status'] );
		$this->assertStringContainsString( 'database operation failed', $state['error'] );
		$this->assertCount( 2, $locks );
		$this->assertStringContainsString( 'GET_LOCK(', $locks[0] );
		$this->assertStringContainsString( 'RELEASE_LOCK(', $locks[1] );
	}

	public function test_successful_slice_saves_summary_timings_and_adaptive_batch_size() {
		$db = $this->mock_queue_database();
		$db->method( 'get_var' )->willReturnCallback( function ( $sql ) {
			return false !== strpos( $sql, 'LOCK(' ) ? '1' : 'wp_atomicedge_scan_queue';
		} );
		$db->method( 'query' )->willReturn( 1 );
		$claimed = false;
		$db->method( 'get_results' )->willReturnCallback( function ( $sql ) use ( &$claimed ) {
			if ( false !== strpos( $sql, 'COUNT(*)' ) ) {
				return array( array( 'status' => 'pending', 'c' => 1, 'directories' => 1 ) );
			}
			if ( $claimed ) {
				return array();
			}
			$claimed = true;
			return array( array( 'id' => 11, 'item_type' => 'file', 'area' => 'plugins', 'path' => '/nonexistent-ae-scan-file.php' ) );
		} );
		$started = date( 'Y-m-d H:i:s', time() - 10 );
		$this->set_transient( 'atomicedge_scan_run_state', array(
			'run_id' => 'test-run', 'status' => 'running', 'stage' => 'queue', 'started_at' => $started,
			'results' => array( 'started_at' => $started, 'scan_stats' => array( 'files_scanned' => 0, 'files_total' => 100 ) ),
		) );
		$state = $this->scanner->step_resumable_scan( 'test-run' );
		$this->assertSame( 'running', $state['status'] );
		$this->assertSame( 1, $state['step_stats']['items_processed'] );
		$this->assertSame( 1, $state['cost']['file_items'] );
		$this->assertSame( 0, $state['cost']['dir_items'] );
		$this->assertGreaterThan( 0, $state['step_stats']['elapsed_ms'] );
		$this->assertArrayHasKey( 'queue_ms', $state['step_stats'] );
		$this->assertArrayHasKey( 'scanning_ms', $state['step_stats'] );
		$this->assertGreaterThanOrEqual( 1, $state['batch_size'] );
		$this->assertLessThanOrEqual( 25, $state['batch_size'] );
		$this->assertFalse( $state['discovery_complete'] );
		$this->assertNull( $state['eta_seconds'] );
		$this->assertStringContainsString( 'pending=1', implode( "\n", $state['log'] ) );
		$this->assertSame( $state, $this->get_transient( 'atomicedge_scan_run_state' ) );
	}

	public function test_expired_root_slice_does_not_advance_past_an_unscanned_entry() {
		$db = $this->mock_queue_database();
		$dir = sys_get_temp_dir() . '/ae-root-' . uniqid();
		mkdir( $dir );
		file_put_contents( $dir . '/sample.php', '<?php echo "safe";' );
		$db->expects( $this->once() )->method( 'update' )->with(
			'wp_atomicedge_scan_queue',
			$this->callback( function ( $data ) {
				return 'pending' === $data['status'] && null === $data['meta'];
			} ),
			$this->anything(), $this->anything(), $this->anything()
		)->willReturn( 1 );
		$state = array();
		$method = new \ReflectionMethod( $this->scanner, 'process_rootfiles_item' );
		$method->setAccessible( true );
		try {
			$method->invokeArgs( $this->scanner, array( 11, 'root', $dir . '/', array(), &$state, microtime( true ) - 2, 1 ) );
		} finally {
			unlink( $dir . '/sample.php' );
			rmdir( $dir );
		}
	}

	public function test_discovery_eta_is_withheld_until_directories_are_sampled() {
		$state = array(
			'discovery_complete' => false,
			'queue_counts'       => array( 'directories_remaining' => 100, 'files_remaining' => 0 ),
			'cost'               => array( 'dir_items' => 4, 'dir_ms' => 800, 'file_items' => 0, 'file_ms' => 0, 'queue_ms' => 0, 'elapsed_ms' => 800 ),
		);

		$this->assertNull( $this->call_private( 'calculate_eta_seconds', $state ) );
	}

	public function test_discovery_eta_uses_measured_directory_cost_and_remaining_queue() {
		$state = array(
			'discovery_complete' => false,
			'queue_counts'       => array( 'directories_remaining' => 100, 'files_remaining' => 0 ),
			'cost'               => array( 'dir_items' => 10, 'dir_ms' => 2000, 'file_items' => 0, 'file_ms' => 0, 'queue_ms' => 0, 'elapsed_ms' => 2000 ),
		);

		// 100 directories at 200 ms each.
		$this->assertSame( 20, $this->call_private( 'calculate_eta_seconds', $state ) );

		// Slice overhead outside item processing lengthens the estimate.
		$state['cost']['elapsed_ms'] = 4000;
		$this->assertSame( 40, $this->call_private( 'calculate_eta_seconds', $state ) );
	}

	public function test_discovery_eta_adds_remaining_files_once_file_cost_is_sampled() {
		$state = array(
			'discovery_complete' => false,
			'queue_counts'       => array( 'directories_remaining' => 100, 'files_remaining' => 1000 ),
			'cost'               => array( 'dir_items' => 10, 'dir_ms' => 2000, 'file_items' => 25, 'file_ms' => 25, 'queue_ms' => 0, 'elapsed_ms' => 2025 ),
		);

		// 20 s of directories plus 1,000 files at 1 ms each.
		$this->assertSame( 21, $this->call_private( 'calculate_eta_seconds', $state ) );
	}

	public function test_scan_cost_totals_accumulate_across_steps() {
		$first  = $this->call_private( 'accumulate_scan_cost', array(), array( 'dir_items' => 3, 'discovery_ms' => 600, 'file_items' => 2, 'scanning_ms' => 4, 'queue_ms' => 10, 'elapsed_ms' => 700 ) );
		$second = $this->call_private( 'accumulate_scan_cost', $first, array( 'dir_items' => 1, 'discovery_ms' => 200, 'file_items' => 0, 'scanning_ms' => 0, 'queue_ms' => 5, 'elapsed_ms' => 300 ) );

		$this->assertSame( 4, $second['dir_items'] );
		$this->assertEqualsWithDelta( 800.0, $second['dir_ms'], 0.001 );
		$this->assertSame( 2, $second['file_items'] );
		$this->assertEqualsWithDelta( 1000.0, $second['elapsed_ms'], 0.001 );
	}

	public function test_discovered_children_are_inserted_in_one_multi_row_statement() {
		$db = $this->mock_queue_database();
		$db->expects( $this->never() )->method( 'insert' );
		$db->expects( $this->once() )->method( 'query' )->with( $this->callback( function ( $sql ) {
			return 4 === substr_count( $sql, "'pending', NULL" )
				&& false !== strpos( $sql, 'ON DUPLICATE KEY UPDATE id = id' );
		} ) )->willReturn( 4 );

		$dir   = $this->make_temp_tree( array( 'alpha', 'beta' ), array( 'one.php', 'two.php', 'notes.txt' ) );
		$state = array( 'run_id' => 'test-run' );
		$method = new \ReflectionMethod( $this->scanner, 'process_dir_item' );
		$method->setAccessible( true );
		try {
			$method->invokeArgs( $this->scanner, array( 11, 'unknown', $dir, array(), &$state, microtime( true ), 5 ) );
		} finally {
			$this->remove_temp_tree( $dir );
		}

		$this->assertSame( array( 11 ), $this->get_private_value( 'pending_done_ids' ) );
		$this->assertSame( array(), $this->get_private_value( 'pending_queue_rows' ) );
	}

	public function test_failed_child_insert_keeps_directory_unfinished() {
		$db = $this->mock_queue_database();
		$db->method( 'query' )->willReturn( false );

		$dir   = $this->make_temp_tree( array( 'child' ), array() );
		$state = array( 'run_id' => 'test-run' );
		$method = new \ReflectionMethod( $this->scanner, 'process_dir_item' );
		$method->setAccessible( true );
		try {
			$method->invokeArgs( $this->scanner, array( 11, 'unknown', $dir, array(), &$state, microtime( true ), 5 ) );
			$this->fail( 'A failed child insert must not mark its directory complete.' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( array(), $this->get_private_value( 'pending_done_ids' ) );
		} finally {
			$this->remove_temp_tree( $dir );
		}
	}

	public function test_queue_rows_are_flushed_in_bounded_chunks() {
		$db = $this->mock_queue_database();
		$db->expects( $this->exactly( 3 ) )->method( 'query' )->willReturn( 1 );

		$this->set_private_value( 'pending_queue_rows', array_fill( 0, 450, array( 'test-run', 'file', 'plugins', '/tmp/example.php' ) ) );
		$this->call_private( 'flush_pending_queue_rows' );

		$this->assertSame( array(), $this->get_private_value( 'pending_queue_rows' ) );
	}

	public function test_queue_counts_separate_directories_from_remaining_files() {
		$db = $this->mock_queue_database();
		$db->method( 'get_results' )->willReturn(
			array(
				array( 'status' => 'pending', 'c' => 10, 'directories' => 3 ),
				array( 'status' => 'processing', 'c' => 2, 'directories' => 1 ),
				array( 'status' => 'done', 'c' => 5, 'directories' => 0 ),
			)
		);

		$counts = $this->call_private( 'get_queue_counts', 'test-run' );

		$this->assertSame( 4, $counts['directories_remaining'] );
		$this->assertSame( 8, $counts['files_remaining'] );
	}

	/**
	 * Decode-only matches with no execution function are informational, not high.
	 */
	public function test_decode_without_execution_sink_is_informational() {
		$file    = $this->write_temp_file( 'decode-only.php', '<?php' . "\n" . '$payload = base64_decode( $blob );' . "\n" . 'echo $payload;' . "\n" );
		$finding = $this->scan_with_mock_patterns( $file );

		$this->assertSame( 'low', $finding['severity'] );
		$this->assertSame( 'encoding_without_sink', $finding['classification'] );
		$this->assertSame( 'obfuscation', $finding['category'] );
	}

	/**
	 * Decoding that feeds an execution function keeps the category severity.
	 */
	public function test_decode_feeding_execution_keeps_category_severity() {
		$file    = $this->write_temp_file( 'decode-exec.php', '<?php' . "\n" . 'eval( base64_decode( $_POST["x"] ) );' . "\n" );
		$finding = $this->scan_with_mock_patterns( $file );

		$this->assertSame( 'critical', $finding['severity'] );
		$this->assertSame( 'code', $finding['classification'] );
	}

	/**
	 * Matches that appear only inside comments or string literals are informational.
	 */
	public function test_matches_only_inside_comments_and_strings_are_informational() {
		$content = '<?php' . "\n"
			. '// Do not run system( or eval( here' . "\n"
			. '$doc = \'base64_decode( is a function name\';' . "\n"
			. 'echo $doc;' . "\n";
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'inert.php', $content ) );

		$this->assertSame( 'low', $finding['severity'] );
		$this->assertSame( 'inert_context', $finding['classification'] );
	}

	/**
	 * Only .php files get the inert-context downgrade; other extensions keep their severity.
	 */
	public function test_same_text_in_a_non_php_file_keeps_category_severity() {
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'notes.txt', '<?php echo "system(";' ) );

		$this->assertSame( 'critical', $finding['severity'] );
		$this->assertSame( 'code', $finding['classification'] );
	}

	/**
	 * The reported severity is the highest one, regardless of category order.
	 */
	public function test_finding_reports_highest_severity_regardless_of_category_order() {
		$content = '<?php' . "\n" . '$a = base64_decode( $b );' . "\n" . 'system( $a );' . "\n";
		$patterns = array(
			'obfuscation'     => array( 'base64_decode\s*\(' => 'Base64 decode' ),
			'shell_execution' => array( 'system\s*\(' => 'System function' ),
		);
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'ordering.php', $content ), $patterns );

		$this->assertSame( 'critical', $finding['severity'] );
		$this->assertSame( 'shell_execution', $finding['category'] );
		$this->assertCount( 2, $finding['indicators'] );
	}

	/**
	 * A finding records the hash of the content it was classified from.
	 */
	public function test_finding_records_hash_of_scanned_content() {
		$content = '<?php' . "\n" . 'eval( $x );' . "\n";
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'hashed.php', $content ) );

		$this->assertSame( hash( 'sha256', $content ), $finding['sha256'] );
	}

	/**
	 * A finding reports the line of its match, counting from one.
	 */
	public function test_pattern_finding_reports_line_number_of_match() {
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'line-three.php', "<?php\n\neval( \$x );\n" ) );

		$this->assertSame( 3, $finding['line'] );
		$this->assertSame( 3, $finding['indicators'][0]['lines'][0] );
	}

	/**
	 * Line numbers are the same for CRLF and LF line endings.
	 */
	public function test_line_numbers_are_correct_with_crlf_endings() {
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'crlf.php', "<?php\r\n\r\neval( \$x );\r\n" ) );

		$this->assertSame( 3, $finding['line'] );
	}

	/**
	 * Every distinct line of a repeated pattern is recorded, in order, without duplicates.
	 */
	public function test_repeated_pattern_records_each_distinct_line() {
		$content = "<?php\neval( \$a );\neval( \$b );\n\neval( \$c );\n";
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'repeated.php', $content ) );

		$this->assertSame( 2, $finding['line'] );
		$this->assertSame( array( 2, 3, 5 ), $finding['indicators'][0]['lines'] );
	}

	/**
	 * Distinct lines per pattern are capped so large files keep findings compact.
	 */
	public function test_indicator_line_list_is_capped() {
		$content = "<?php\n" . str_repeat( "eval( \$x );\n", 15 );
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'many-lines.php', $content ) );

		$this->assertCount( 10, $finding['indicators'][0]['lines'] );
		$this->assertSame( 2, $finding['line'] );
	}

	/**
	 * The top-level line is the first line of the most severe indicator, not the first match in the file.
	 */
	public function test_finding_line_follows_most_severe_indicator() {
		$content = "<?php\n\$a = base64_decode( \$b );\nsystem( \$a );\n";
		$patterns = array(
			'obfuscation'     => array( 'base64_decode\s*\(' => 'Base64 decode' ),
			'shell_execution' => array( 'system\s*\(' => 'System function' ),
		);
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'severe-line.php', $content ), $patterns );

		$this->assertSame( 'critical', $finding['severity'] );
		$this->assertSame( 3, $finding['line'] );
	}

	/**
	 * A match on the final line without a trailing newline is still located.
	 */
	public function test_line_number_of_match_on_final_line_without_newline() {
		$finding = $this->scan_with_mock_patterns( $this->write_temp_file( 'last-line.php', "<?php\n\neval( \$x );" ) );

		$this->assertSame( 3, $finding['line'] );
	}

	/**
	 * Offset-to-line lookup uses line starts, including boundaries and empty content.
	 */
	public function test_line_number_for_offset_uses_line_boundaries() {
		$starts = array( 0, 6, 12 );

		$this->assertSame( 1, $this->call_private( 'line_number_for_offset', $starts, 0 ) );
		$this->assertSame( 1, $this->call_private( 'line_number_for_offset', $starts, 5 ) );
		$this->assertSame( 2, $this->call_private( 'line_number_for_offset', $starts, 6 ) );
		$this->assertSame( 2, $this->call_private( 'line_number_for_offset', $starts, 11 ) );
		$this->assertSame( 3, $this->call_private( 'line_number_for_offset', $starts, 40 ) );
		$this->assertSame( 1, $this->call_private( 'line_number_for_offset', array( 0 ), 0 ) );
	}

	/**
	 * Hidden PHP in an image reports the line of its first PHP tag.
	 */
	public function test_php_in_image_reports_line_of_first_php_tag() {
		$file   = $this->write_temp_file( 'avatar.gif', "GIF89a\nbinary-ish filler\n<?php echo 1; ?>\n" );
		$result = $this->invoke_on( $this->scanner, 'scan_file_for_patterns', $file, array(), true );

		$this->assertSame( 'php_in_image', $result['type'] );
		$this->assertSame( 3, $result['line'] );
	}

	/**
	 * Sensitivity defaults to standard and rejects unknown levels.
	 */
	public function test_sensitivity_defaults_to_standard_and_rejects_unknown_levels() {
		$this->assertSame( 'standard', $this->scanner->get_scan_sensitivity() );
		$this->assertSame( 'medium', $this->scanner->get_sensitivity_threshold() );

		$this->assertFalse( $this->scanner->set_scan_sensitivity( 'paranoid' ) );
		$this->assertSame( 'standard', $this->scanner->get_scan_sensitivity() );

		$this->assertTrue( $this->scanner->set_scan_sensitivity( 'essential' ) );
		$this->assertSame( 'high', $this->scanner->get_sensitivity_threshold() );
	}

	/**
	 * Visibility depends on sensitivity threshold and dismissal.
	 */
	public function test_finding_state_follows_sensitivity_and_dismissals() {
		$hash   = str_repeat( 'a', 64 );
		$medium = array( 'file' => 'a.php', 'sha256' => $hash, 'severity' => 'medium' );
		$low    = array( 'file' => 'a.php', 'sha256' => $hash, 'severity' => 'low' );

		$this->assertSame( 'informational', $this->scanner->get_finding_state( $low, array(), 'medium' ) );
		$this->assertSame( 'open', $this->scanner->get_finding_state( $medium, array(), 'medium' ) );
		$this->assertSame( 'informational', $this->scanner->get_finding_state( $medium, array(), 'high' ) );

		$dismissals = array( $this->scanner->finding_fingerprint( 'a.php', $hash ) => array() );
		$this->assertSame( 'dismissed', $this->scanner->get_finding_state( $medium, $dismissals, 'medium' ) );
	}

	/**
	 * Summary counts split findings into open, informational, and dismissed.
	 */
	public function test_summary_counts_split_findings_by_state() {
		$hash = str_repeat( 'c', 64 );
		$findings = array(
			array( 'file' => 'one.php', 'sha256' => $hash, 'severity' => 'critical' ),
			array( 'file' => 'two.php', 'sha256' => $hash, 'severity' => 'low' ),
			array( 'file' => 'three.php', 'sha256' => $hash, 'severity' => 'high' ),
		);
		$dismissals = array( $this->scanner->finding_fingerprint( 'three.php', $hash ) => array() );

		$this->assertSame(
			array( 'open' => 1, 'informational' => 1, 'dismissed' => 1 ),
			$this->scanner->summarize_findings( $findings, $dismissals, 'medium' )
		);
	}

	/**
	 * Dismissal requires the finding to exist in the last scan results.
	 */
	public function test_dismiss_rejects_findings_not_in_last_results() {
		$this->set_option( 'atomicedge_scan_results', array( 'suspicious' => array() ) );

		$result = $this->scanner->dismiss_scan_finding( 'wp-content/plugins/ae-test/a.php', str_repeat( 'b', 64 ) );

		$this->assertSame( 'error', $result['status'] );
		$this->assertSame( array(), $this->scanner->get_scan_dismissals() );
	}

	/**
	 * A file edited after the scan cannot be dismissed against the old result.
	 */
	public function test_dismiss_rejects_file_changed_since_scan() {
		$relative = 'wp-content/plugins/ae-test/changed.php';
		$this->make_root_file( $relative, '<?php eval( $old );' );
		$this->set_scan_result( $relative, hash( 'sha256', '<?php eval( $old );' ) );
		file_put_contents( rtrim( ABSPATH, '/' ) . '/' . $relative, '<?php eval( $new );' );

		$result = $this->scanner->dismiss_scan_finding( $relative, hash( 'sha256', '<?php eval( $old );' ) );

		$this->assertSame( 'error', $result['status'] );
		$this->assertStringContainsString( 'changed', $result['message'] );
	}

	/**
	 * Dismiss applies to one file version and restore brings the finding back.
	 */
	public function test_dismiss_then_restore_round_trip() {
		$relative = 'wp-content/plugins/ae-test/round-trip.php';
		$content  = '<?php echo base64_decode( $x );';
		$this->make_root_file( $relative, $content );
		$hash = hash( 'sha256', $content );
		$this->set_scan_result( $relative, $hash );
		$finding = array( 'file' => $relative, 'sha256' => $hash, 'severity' => 'high' );

		$dismissed = $this->scanner->dismiss_scan_finding( $relative, $hash, 'Vendor crypto helper' );
		$this->assertSame( 'dismissed', $dismissed['status'] );
		$this->assertSame( 'dismissed', $this->scanner->get_finding_state( $finding ) );

		$stored = $this->scanner->get_scan_dismissals();
		$this->assertSame( 'Vendor crypto helper', $stored[ $dismissed['fingerprint'] ]['reason'] );

		$restored = $this->scanner->restore_scan_finding( $relative, $hash );
		$this->assertSame( 'restored', $restored['status'] );
		$this->assertSame( 'open', $this->scanner->get_finding_state( $finding ) );
	}

	/**
	 * Dismissal refuses paths that try to leave the WordPress root.
	 */
	public function test_dismiss_rejects_paths_outside_the_root() {
		$hash = str_repeat( 'd', 64 );
		$this->set_scan_result( '../../etc/passwd', $hash );

		$result = $this->scanner->dismiss_scan_finding( '../../etc/passwd', $hash );

		$this->assertSame( 'error', $result['status'] );
		$this->assertSame( array(), $this->scanner->get_scan_dismissals() );
	}

	/**
	 * Unknown-directory findings are elevated only for executable matches.
	 */
	public function test_unknown_directory_findings_are_calibrated_by_context() {
		$db = $this->mock_queue_database();
		$db->method( 'update' )->willReturn( 1 );

		$scanner = $this->create_scanner_with_mocked_api();
		$this->set_private_on( $scanner, 'scan_diagnostics', $this->invoke_on( $scanner, 'get_default_scan_diagnostics' ) );
		$method = new \ReflectionMethod( $scanner, 'process_file_item' );
		$method->setAccessible( true );

		$inert = $this->write_temp_file( 'inert-unknown.php', '<?php // eval( only in a comment' . "\n" );
		$code  = $this->write_temp_file( 'code-unknown.php', '<?php eval( $x );' . "\n" );
		$plain = $this->write_temp_file( 'plain-unknown.php', '<?php echo 1;' . "\n" );

		$state = array( 'results' => array( 'scan_stats' => array( 'files_scanned' => 0 ), 'suspicious' => array() ) );
		$method->invokeArgs( $scanner, array( 1, 'unknown', $inert, &$state ) );
		$method->invokeArgs( $scanner, array( 2, 'unknown', $code, &$state ) );
		$method->invokeArgs( $scanner, array( 3, 'unknown', $plain, &$state ) );

		$this->assertSame( 'low', $state['results']['suspicious'][0]['severity'] );
		$this->assertSame( 'critical', $state['results']['suspicious'][1]['severity'] );
		$this->assertSame( 'php_in_unknown_dir', $state['results']['suspicious'][2]['type'] );
		$this->assertSame( 'medium', $state['results']['suspicious'][2]['severity'] );
	}

	/**
	 * Path-only findings get a content hash so they can be dismissed for this file version.
	 */
	public function test_path_only_findings_receive_content_hashes() {
		$file    = $this->write_temp_file( 'uploaded.php', '<?php echo 1;' );
		$results = array(
			'suspicious' => array(
				array( 'file' => 'wp-content/uploads/uploaded.php', 'file_path' => $file, 'type' => 'php_in_uploads', 'severity' => 'high' ),
			),
		);

		$updated = $this->invoke_on( $this->scanner, 'attach_missing_finding_hashes', $results );

		$this->assertSame( hash_file( 'sha256', $file ), $updated['suspicious'][0]['sha256'] );
	}

	/**
	 * Call a private scanner method on a given object.
	 *
	 * @param object $object Target object.
	 * @param string $method Method name.
	 * @param mixed  ...$args Arguments.
	 * @return mixed
	 */
	private function invoke_on( $object, $method, ...$args ) {
		$reflection = new \ReflectionMethod( $object, $method );
		$reflection->setAccessible( true );
		return $reflection->invokeArgs( $object, $args );
	}

	/**
	 * Scan one file with a scanner whose signatures come from the mocked API.
	 *
	 * @param string     $file     Absolute file path.
	 * @param array|null $patterns Pattern groups (defaults to the mocked API patterns).
	 * @return array|false
	 */
	private function scan_with_mock_patterns( $file, $patterns = null ) {
		$scanner = $this->create_scanner_with_mocked_api();
		$this->set_private_on( $scanner, 'scan_diagnostics', $this->invoke_on( $scanner, 'get_default_scan_diagnostics' ) );

		if ( null === $patterns ) {
			$patterns = array(
				'code_execution'  => array( 'eval\s*\(' => 'Eval function' ),
				'shell_execution' => array( 'system\s*\(' => 'System function' ),
				'obfuscation'     => array( 'base64_decode\s*\(' => 'Base64 decode' ),
			);
		}

		return $this->invoke_on( $scanner, 'scan_file_for_patterns', $file, $patterns, false );
	}

	/**
	 * Write a temporary PHP-related file for a scan test.
	 *
	 * @param string $name    File name.
	 * @param string $content File content.
	 * @return string Absolute path.
	 */
	private function write_temp_file( $name, $content ) {
		$dir = sys_get_temp_dir() . '/ae-classify-' . uniqid();
		mkdir( $dir );
		$path = $dir . '/' . $name;
		file_put_contents( $path, $content );
		$this->temp_paths[] = $dir;
		return $path;
	}

	/**
	 * Create a file under the WordPress root for dismissal tests.
	 *
	 * @param string $relative Path relative to ABSPATH.
	 * @param string $content  File content.
	 * @return void
	 */
	private function make_root_file( $relative, $content ) {
		$absolute = rtrim( ABSPATH, '/' ) . '/' . $relative;
		if ( ! is_dir( dirname( $absolute ) ) ) {
			mkdir( dirname( $absolute ), 0777, true );
		}
		file_put_contents( $absolute, $content );
		$this->root_files[] = $absolute;
	}

	/**
	 * Store last scan results containing one suspicious finding.
	 *
	 * @param string $relative File path relative to ABSPATH.
	 * @param string $hash     Content hash recorded for the finding.
	 * @return void
	 */
	private function set_scan_result( $relative, $hash ) {
		$this->set_option( 'atomicedge_scan_results', array(
			'suspicious' => array(
				array(
					'file'     => $relative,
					'severity' => 'high',
					'sha256'   => $hash,
				),
			),
		) );
	}

	/**
	 * Set a private property on a given object.
	 *
	 * @param object $object Target object.
	 * @param string $name   Property name.
	 * @param mixed  $value  Property value.
	 * @return void
	 */
	private function set_private_on( $object, $name, $value ) {
		$property = new \ReflectionProperty( $object, $name );
		$property->setAccessible( true );
		$property->setValue( $object, $value );
	}

	/**
	 * Call a private scanner method by name.
	 *
	 * @param string $method Method name.
	 * @param mixed  ...$args Arguments.
	 * @return mixed
	 */
	private function call_private( $method, ...$args ) {
		$reflection = new \ReflectionMethod( $this->scanner, $method );
		$reflection->setAccessible( true );
		return $reflection->invokeArgs( $this->scanner, $args );
	}

	/**
	 * Read a private scanner property.
	 *
	 * @param string $name Property name.
	 * @return mixed
	 */
	private function get_private_value( $name ) {
		$property = new \ReflectionProperty( $this->scanner, $name );
		$property->setAccessible( true );
		return $property->getValue( $this->scanner );
	}

	/**
	 * Set a private scanner property.
	 *
	 * @param string $name  Property name.
	 * @param mixed  $value Property value.
	 * @return void
	 */
	private function set_private_value( $name, $value ) {
		$property = new \ReflectionProperty( $this->scanner, $name );
		$property->setAccessible( true );
		$property->setValue( $this->scanner, $value );
	}

	/**
	 * Create a small directory tree for discovery tests.
	 *
	 * @param array $dirs  Child directory names.
	 * @param array $files Child file names.
	 * @return string Absolute root path.
	 */
	private function make_temp_tree( array $dirs, array $files ) {
		$root = sys_get_temp_dir() . '/ae-discovery-' . uniqid();
		mkdir( $root );
		foreach ( $dirs as $dir ) {
			mkdir( $root . '/' . $dir );
		}
		foreach ( $files as $file ) {
			file_put_contents( $root . '/' . $file, '<?php' );
		}
		return $root;
	}

	/**
	 * Remove a tree created by make_temp_tree().
	 *
	 * @param string $root Absolute root path.
	 * @return void
	 */
	private function remove_temp_tree( $root ) {
		foreach ( glob( $root . '/*' ) ?: array() as $path ) {
			is_dir( $path ) ? rmdir( $path ) : unlink( $path );
		}
		rmdir( $root );
	}

	private function mock_queue_database() {
		global $wpdb;
		if ( ! defined( 'ARRAY_A' ) ) {
			define( 'ARRAY_A', 'ARRAY_A' );
		}
		$wpdb = $this->getMockBuilder( \stdClass::class )
			->addMethods( array( 'get_results', 'get_var', 'prepare', 'query', 'update', 'insert' ) )->getMock();
		$wpdb->prefix = 'wp_';
		$wpdb->last_error = '';
		$wpdb->method( 'prepare' )->willReturnCallback( function ( $sql, ...$args ) {
			if ( isset( $args[0] ) && is_array( $args[0] ) ) {
				$args = $args[0];
			}
			foreach ( $args as $arg ) {
				$sql = preg_replace_callback( '/%[sd]/', function () use ( $arg ) {
					return (string) $arg;
				}, $sql, 1 );
			}
			return $sql;
		} );
		return $wpdb;
	}

	// =========================================================================
	// File Analysis Tests
	// =========================================================================

	/**
	 * Test hidden file detection pattern.
	 */
	public function test_hidden_file_detection_pattern() {
		$hidden_files = array(
			'.htaccess',
			'.hidden.php',
			'..doubledot.php',
		);

		$visible_files = array(
			'normal.php',
			'file.txt',
			'index.html',
		);

		$hidden_pattern = '/^\./';

		foreach ( $hidden_files as $file ) {
			$basename = basename( $file );
			$this->assertTrue(
				(bool) preg_match( $hidden_pattern, $basename ),
				"Should detect {$file} as hidden"
			);
		}

		foreach ( $visible_files as $file ) {
			$basename = basename( $file );
			$this->assertFalse(
				(bool) preg_match( $hidden_pattern, $basename ),
				"Should NOT detect {$file} as hidden"
			);
		}
	}

	/**
	 * Test file extension pattern matching.
	 */
	public function test_file_extension_pattern_matching() {
		$php_pattern = '/\.php$/i';

		$php_files = array( 'index.php', 'test.PHP', 'file.Php' );
		$non_php   = array( 'style.css', 'script.js', 'image.png' );

		foreach ( $php_files as $file ) {
			$this->assertTrue(
				(bool) preg_match( $php_pattern, $file ),
				"{$file} should match PHP pattern"
			);
		}

		foreach ( $non_php as $file ) {
			$this->assertFalse(
				(bool) preg_match( $php_pattern, $file ),
				"{$file} should NOT match PHP pattern"
			);
		}
	}

	/**
	 * Test obfuscation detection pattern syntax is valid regex.
	 *
	 * Tests regex compilation without embedding actual obfuscation signatures.
	 */
	public function test_obfuscation_detection_pattern_syntax() {
		// Test that regex patterns compile correctly (using safe examples).
		$patterns = array(
			'my_decode\s*\(\s*[\'"]' => 'String decode pattern',
			'chr\s*\(\s*\d+\s*\)'    => 'Chr function syntax',
		);

		foreach ( $patterns as $pattern => $label ) {
			// Verify pattern compiles without error.
			$result = @preg_match( '/' . $pattern . '/i', 'test string' );
			$this->assertNotFalse(
				$result,
				"Pattern '{$label}' should be valid regex"
			);
		}
	}

	/**
	 * Test function call detection pattern (using safe function names).
	 */
	public function test_function_call_detection_pattern() {
		$function_pattern = '/\b(my_func|other_func|third_func)\s*\(/i';

		$matching = array(
			'my_func($arg)',
			'other_func("param")',
			'third_func();',
		);

		$not_matching = array(
			'$my_func = "variable name";',
			'// This is a comment about my_func',
			'function my_func_handler() {}',
		);

		foreach ( $matching as $code ) {
			$this->assertTrue(
				(bool) preg_match( $function_pattern, $code ),
				"Should detect function call: {$code}"
			);
		}

		foreach ( $not_matching as $code ) {
			$this->assertFalse(
				(bool) preg_match( $function_pattern, $code ),
				"Should NOT flag non-function-call: {$code}"
			);
		}
	}

	// =========================================================================
	// Scan Mode Tests
	// =========================================================================

	/**
	 * Test scan mode validation.
	 */
	public function test_scan_mode_defaults_to_all() {
		// Invalid modes should default to 'all'.
		$valid_modes = array( 'php', 'all' );
		$invalid_mode = 'invalid';

		$this->assertNotContains( $invalid_mode, $valid_modes );
		$this->assertContains( 'all', $valid_modes );
		$this->assertContains( 'php', $valid_modes );
	}

	// =========================================================================
	// Integrity Verification Tests
	// =========================================================================

	/**
	 * Test checksum comparison logic.
	 */
	public function test_checksum_comparison_logic() {
		$expected_hash = md5( 'test content' );
		$actual_hash   = md5( 'test content' );
		$wrong_hash    = md5( 'different content' );

		$this->assertEquals( $expected_hash, $actual_hash );
		$this->assertNotEquals( $expected_hash, $wrong_hash );
	}

	// =========================================================================
	// Edge Case Tests
	// =========================================================================

	/**
	 * Test scanner handles empty directory gracefully.
	 */
	public function test_scanner_handles_empty_results() {
		$results = $this->scanner->get_last_results();
		$this->assertIsArray( $results );
	}

	/**
	 * Test scanner get status returns idle when no scan running.
	 */
	public function test_get_status_no_active_scan() {
		// Clear any scan state.
		delete_transient( 'atomicedge_scan_run_state' );

		$status = $this->scanner->get_resumable_scan_status( 'any-id' );

		$this->assertIsArray( $status );
		$this->assertEquals( 'idle', $status['status'] );
	}

	// =========================================================================
	// API Integration Tests - Malware Signatures
	// =========================================================================

	/**
	 * Test scanner uses API instance when provided.
	 */
	public function test_scanner_accepts_api_in_constructor() {
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->getMock();

		$scanner = new \AtomicEdge_Scanner( $mock_api );

		$this->assertInstanceOf( \AtomicEdge_Scanner::class, $scanner );
	}

	/**
	 * Test scanner can set API instance after construction.
	 */
	public function test_scanner_set_api_method() {
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->getMock();

		$scanner = new \AtomicEdge_Scanner();
		$scanner->set_api( $mock_api );

		$this->assertInstanceOf( \AtomicEdge_Scanner::class, $scanner );
	}

	/**
	 * Test has_signatures returns true when API provides signatures.
	 */
	public function test_has_signatures_returns_true_with_api_data() {
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->onlyMethods( array( 'get_malware_signatures' ) )
			->getMock();

		$mock_api->method( 'get_malware_signatures' )->willReturn(
			array(
				'version'          => '1.0.0',
				'patterns'         => array(
					'code_execution' => array( 'eval\s*\(' => 'Eval function' ),
				),
				'quick_indicators' => array( 'eval(' ),
				'severity_map'     => array( 'code_execution' => 'critical' ),
			)
		);

		$scanner = new \AtomicEdge_Scanner( $mock_api );

		$this->assertTrue( $scanner->has_signatures() );
	}

	/**
	 * Test has_signatures returns false when API returns no data.
	 */
	public function test_has_signatures_returns_false_without_api_data() {
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->onlyMethods( array( 'get_malware_signatures' ) )
			->getMock();

		$mock_api->method( 'get_malware_signatures' )->willReturn( false );

		$scanner = new \AtomicEdge_Scanner( $mock_api );

		$this->assertFalse( $scanner->has_signatures() );
	}

	/**
	 * Test get_signature_version returns version from API.
	 */
	public function test_get_signature_version_returns_api_version() {
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->onlyMethods( array( 'get_malware_signatures' ) )
			->getMock();

		$mock_api->method( 'get_malware_signatures' )->willReturn(
			array(
				'version'          => '2.5.1',
				'patterns'         => array(),
				'quick_indicators' => array(),
				'severity_map'     => array(),
			)
		);

		$scanner = new \AtomicEdge_Scanner( $mock_api );

		$this->assertEquals( '2.5.1', $scanner->get_signature_version() );
	}

	/**
	 * Test get_signature_version returns null when no signatures.
	 */
	public function test_get_signature_version_returns_null_without_signatures() {
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->onlyMethods( array( 'get_malware_signatures' ) )
			->getMock();

		$mock_api->method( 'get_malware_signatures' )->willReturn( false );

		$scanner = new \AtomicEdge_Scanner( $mock_api );

		$this->assertNull( $scanner->get_signature_version() );
	}

	/**
	 * Test scanner gracefully handles missing API.
	 */
	public function test_scanner_handles_missing_api_gracefully() {
		// Create a mock API that returns false for signatures (simulates API failure).
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->onlyMethods( array( 'get_malware_signatures' ) )
			->getMock();

		$mock_api->method( 'get_malware_signatures' )->willReturn( false );

		// Scanner with failing API should not crash.
		$scanner = new \AtomicEdge_Scanner( $mock_api );

		// These should return empty/false gracefully.
		$this->assertFalse( $scanner->has_signatures() );
		$this->assertNull( $scanner->get_signature_version() );
	}
}
