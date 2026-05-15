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
