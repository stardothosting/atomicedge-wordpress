<?php
/**
 * Base Test Case for AtomicEdge Plugin
 *
 * Provides common setup/teardown and helper methods for all tests.
 *
 * @package AtomicEdge\Tests
 */

namespace AtomicEdge\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Yoast\PHPUnitPolyfills\TestCases\TestCase as PolyfillTestCase;

/**
 * Base test case class.
 */
abstract class TestCase extends PolyfillTestCase {

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();
		Monkey\setUp();

		// Reset global test options.
		global $_test_options, $_test_transients;
		$_test_options    = array();
		$_test_transients = array();

		// Re-setup default mocks (they get cleared by Monkey\setUp).
		setup_default_mocks();
	}

	/**
	 * Tear down after each test.
	 *
	 * @return void
	 */
	protected function tear_down() {
		Monkey\tearDown();
		parent::tear_down();
	}

	/**
	 * Set a test option value.
	 *
	 * @param string $key   Option key.
	 * @param mixed  $value Option value.
	 * @return void
	 */
	protected function set_option( string $key, $value ): void {
		global $_test_options;
		$_test_options[ $key ] = $value;
	}

	/**
	 * Get a test option value.
	 *
	 * @param string $key     Option key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	protected function get_option( string $key, $default = false ) {
		global $_test_options;
		return $_test_options[ $key ] ?? $default;
	}

	/**
	 * Set a test transient value.
	 *
	 * @param string $key   Transient key.
	 * @param mixed  $value Transient value.
	 * @return void
	 */
	protected function set_transient( string $key, $value ): void {
		global $_test_transients;
		$_test_transients[ $key ] = $value;
	}

	/**
	 * Get a test transient value.
	 *
	 * @param string $key Transient key.
	 * @return mixed|false
	 */
	protected function get_transient( string $key ) {
		global $_test_transients;
		return $_test_transients[ $key ] ?? false;
	}

	/**
	 * Clear all test transients.
	 *
	 * @return void
	 */
	protected function clear_transients(): void {
		global $_test_transients;
		$_test_transients = array();
	}

	/**
	 * Mock a successful HTTP response.
	 *
	 * @param array  $body Response body data.
	 * @param int    $code HTTP status code.
	 * @param string $method HTTP method to mock (wp_remote_post, wp_remote_get, wp_remote_request).
	 * @return void
	 */
	protected function mock_http_success( array $body, int $code = 200, string $method = 'wp_remote_post' ): void {
		$response = array(
			'response' => array( 'code' => $code ),
			'body'     => wp_json_encode( $body ),
		);

		Functions\when( $method )->justReturn( $response );
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( $code );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( $body ) );
	}

	/**
	 * Mock an HTTP error response.
	 *
	 * @param string $error_message Error message.
	 * @param string $method        HTTP method to mock.
	 * @return void
	 */
	protected function mock_http_error( string $error_message, string $method = 'wp_remote_post' ): void {
		$error = new \WP_Error( 'http_error', $error_message );
		Functions\when( $method )->justReturn( $error );
		Functions\when( 'is_wp_error' )->alias(
			function ( $thing ) {
				return $thing instanceof \WP_Error;
			}
		);
	}

	/**
	 * Create a fresh API instance for testing.
	 *
	 * @return \AtomicEdge_API
	 */
	protected function create_api_instance(): \AtomicEdge_API {
		return new \AtomicEdge_API();
	}

	/**
	 * Create a fresh Scanner instance for testing.
	 *
	 * @return \AtomicEdge_Scanner
	 */
	protected function create_scanner_instance(): \AtomicEdge_Scanner {
		return new \AtomicEdge_Scanner();
	}

	/**
	 * Create a Scanner instance with a mocked API that returns malware signatures.
	 *
	 * This is needed because the scanner now fetches signatures from the API,
	 * and tests that use run_full_scan need signatures to be available.
	 *
	 * @return \AtomicEdge_Scanner
	 */
	protected function create_scanner_with_mocked_api(): \AtomicEdge_Scanner {
		$mock_api = $this->getMockBuilder( \AtomicEdge_API::class )
			->disableOriginalConstructor()
			->onlyMethods( array( 'get_malware_signatures' ) )
			->getMock();

		$mock_api->method( 'get_malware_signatures' )->willReturn(
			array(
				'version'          => '1.0.0',
				'updated_at'       => gmdate( 'c' ),
				'patterns'         => array(
					'code_execution'  => array( 'eval\s*\(' => 'Eval function' ),
					'shell_execution' => array( 'system\s*\(' => 'System function' ),
					'obfuscation'     => array( 'base64_decode\s*\(' => 'Base64 decode' ),
				),
				'quick_indicators' => array( 'eval(', 'system(', 'base64_decode(' ),
				'severity_map'     => array(
					'code_execution'  => 'critical',
					'shell_execution' => 'critical',
					'obfuscation'     => 'high',
				),
			)
		);

		return new \AtomicEdge_Scanner( $mock_api );
	}

	/**
	 * Generate a valid test API key (64 hex characters).
	 *
	 * @return string
	 */
	protected function generate_test_api_key(): string {
		return bin2hex( random_bytes( 32 ) );
	}

	/**
	 * Assert that a JSON response contains expected keys.
	 *
	 * @param array $expected Expected keys.
	 * @param array $actual   Actual response data.
	 * @return void
	 */
	protected function assertResponseHasKeys( array $expected, array $actual ): void {
		foreach ( $expected as $key ) {
			$this->assertArrayHasKey( $key, $actual, "Response missing expected key: {$key}" );
		}
	}
}
