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

	// =========================================================================
	// Pattern Detection Tests (Using Reflection)
	// =========================================================================

	/**
	 * Test dangerous pattern detection logic.
	 *
	 * We test the pattern matching logic directly since file scanning
	 * requires actual filesystem access.
	 */
	public function test_dangerous_patterns_regex_matches() {
		$dangerous_patterns = array(
			'base64_decode\s*\('     => 'Base64 decoding',
			'eval\s*\('              => 'Eval function',
			'gzinflate\s*\('         => 'Gzip inflate',
			'str_rot13\s*\('         => 'ROT13 encoding',
			'preg_replace.*\/e'      => 'Preg replace with eval modifier',
		);

		$test_cases = array(
			array(
				'content'  => '<?php base64_decode($encoded);',
				'pattern'  => 'base64_decode\s*\(',
				'expected' => true,
			),
			array(
				'content'  => '<?php eval( $_POST["code"] );',
				'pattern'  => 'eval\s*\(',
				'expected' => true,
			),
			array(
				'content'  => '<?php gzinflate(base64_decode($x));',
				'pattern'  => 'gzinflate\s*\(',
				'expected' => true,
			),
			array(
				'content'  => '<?php echo "Hello World";',
				'pattern'  => 'eval\s*\(',
				'expected' => false,
			),
			array(
				'content'  => '<?php // This is safe code',
				'pattern'  => 'base64_decode\s*\(',
				'expected' => false,
			),
		);

		foreach ( $test_cases as $case ) {
			$matches = preg_match( '/' . $case['pattern'] . '/i', $case['content'] );
			$this->assertEquals(
				$case['expected'],
				(bool) $matches,
				"Pattern '{$case['pattern']}' on '{$case['content']}' should " . ( $case['expected'] ? 'match' : 'not match' )
			);
		}
	}

	/**
	 * Test superglobal execution pattern detection.
	 */
	public function test_superglobal_execution_pattern_detection() {
		$pattern = '\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(';

		$dangerous_code = array(
			'$_GET["func"]($arg)',
			'$_POST["callback"]($data)',
			'$_REQUEST["cmd"]();',
			'$_COOKIE["fn"]($x)',
		);

		$safe_code = array(
			'$data = $_POST["field"];',
			'echo $_GET["name"];',
			'$value = sanitize_text_field($_REQUEST["input"]);',
		);

		foreach ( $dangerous_code as $code ) {
			$this->assertTrue(
				(bool) preg_match( '/' . $pattern . '/i', $code ),
				"Pattern should match dangerous code: {$code}"
			);
		}

		foreach ( $safe_code as $code ) {
			$this->assertFalse(
				(bool) preg_match( '/' . $pattern . '/i', $code ),
				"Pattern should NOT match safe code: {$code}"
			);
		}
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

		$result = $this->scanner->run_full_scan();

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

		$this->scanner->run_full_scan();

		// Check that results were saved.
		$saved_results = $this->get_option( 'atomicedge_scan_results' );
		$last_scan     = $this->get_option( 'atomicedge_last_scan' );

		$this->assertNotEmpty( $saved_results );
		$this->assertNotEmpty( $last_scan );
	}
}
