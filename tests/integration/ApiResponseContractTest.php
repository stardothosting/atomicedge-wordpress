<?php
/**
 * API Response Contract Tests
 *
 * These tests validate that the API class correctly handles the ACTUAL response
 * format from the AtomicEdge Laravel API. This is critical because:
 *
 * 1. The Laravel API returns: {"success": true, "data": {...actual_data...}}
 * 2. The WordPress plugin must extract the inner "data" for consumers
 * 3. JavaScript/AJAX handlers expect data at $result['data'], not $result['data']['data']
 *
 * LESSON LEARNED (2026-01-06):
 * Previous tests mocked wp_remote_request with incorrect response structures that
 * didn't match the real API. This allowed a double-nesting bug to ship where
 * $result['data'] contained {"success": true, "data": {...}} instead of just {...}.
 *
 * The fix: Test against the REAL response format from the Laravel API.
 *
 * @package AtomicEdge\Tests\Integration
 */

namespace AtomicEdge\Tests\Integration;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * API Response Contract Test Suite
 *
 * Validates that the plugin correctly handles the actual API response format.
 */
class ApiResponseContractTest extends TestCase {

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		Functions\when( 'home_url' )->justReturn( 'https://example.com' );
		Functions\when( 'wp_parse_args' )->alias(
			function ( $args, $defaults ) {
				return array_merge( $defaults, $args );
			}
		);
		Functions\when( 'add_query_arg' )->alias(
			function ( $args, $url ) {
				return $url . '?' . http_build_query( $args );
			}
		);
	}

	// =========================================================================
	// RESPONSE FORMAT CONTRACT TESTS
	// =========================================================================
	// These tests ensure the API class correctly unwraps the Laravel API response.
	// The Laravel API returns: {"success": true, "data": {...}}
	// The plugin must return: ["success" => true, "data" => [...]] where "data"
	// contains the INNER data, not the entire API response.
	// =========================================================================

	/**
	 * Test analytics response is correctly unwrapped from Laravel format.
	 *
	 * Real API returns: {"success": true, "data": {"period": "24h", "total_requests": 100, ...}}
	 * Plugin should return: ["success" => true, "data" => ["period" => "24h", "total_requests" => 100, ...]]
	 *
	 * NOT: ["success" => true, "data" => ["success" => true, "data" => [...]]]
	 */
	public function test_analytics_response_unwraps_data_correctly() {
		$this->setup_connected_api();

		// This is what the REAL Laravel API returns.
		$laravel_api_response = array(
			'success' => true,
			'data'    => array(
				'period'           => '24h',
				'total_requests'   => 1000,
				'unique_visitors'  => 500,
				'requests_blocked' => 50,
				'hourly_data'      => array(
					array( 'hour' => '2026-01-06T00:00:00Z', 'requests' => 10, 'blocked' => 1 ),
				),
			),
		);

		$this->mock_http_response( 200, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->get_analytics( '24h' );

		// Verify success.
		$this->assertTrue( $result['success'], 'API call should succeed' );

		// CRITICAL: Verify data is NOT double-nested.
		$this->assertArrayHasKey( 'data', $result );
		$this->assertArrayNotHasKey( 'success', $result['data'], 'Data should not contain nested success key' );

		// Verify we can access the actual data directly.
		$this->assertArrayHasKey( 'total_requests', $result['data'], 'Should have total_requests at data level' );
		$this->assertArrayHasKey( 'hourly_data', $result['data'], 'Should have hourly_data at data level' );
		$this->assertEquals( 1000, $result['data']['total_requests'] );
		$this->assertEquals( '24h', $result['data']['period'] );
	}

	/**
	 * Test WAF logs response is correctly unwrapped.
	 */
	public function test_waf_logs_response_unwraps_data_correctly() {
		$this->setup_connected_api();

		$laravel_api_response = array(
			'success' => true,
			'data'    => array(
				'logs'       => array(
					array( 'id' => 1, 'client_ip' => '1.2.3.4', 'uri' => '/test' ),
				),
				'pagination' => array(
					'page'        => 1,
					'per_page'    => 50,
					'total'       => 1,
					'total_pages' => 1,
				),
			),
		);

		$this->mock_http_response( 200, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->get_waf_logs();

		$this->assertTrue( $result['success'] );
		$this->assertArrayNotHasKey( 'success', $result['data'], 'Data should not be double-nested' );
		$this->assertArrayHasKey( 'logs', $result['data'] );
		$this->assertArrayHasKey( 'pagination', $result['data'] );
	}

	/**
	 * Test IP rules response is correctly unwrapped.
	 */
	public function test_ip_rules_response_unwraps_data_correctly() {
		$this->setup_connected_api();

		$laravel_api_response = array(
			'success' => true,
			'data'    => array(
				'whitelist' => array( '192.168.1.1' ),
				'blacklist' => array( '10.0.0.1' ),
			),
		);

		$this->mock_http_response( 200, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->get_ip_rules();

		$this->assertTrue( $result['success'] );
		$this->assertArrayNotHasKey( 'success', $result['data'] );
		$this->assertArrayHasKey( 'whitelist', $result['data'] );
		$this->assertArrayHasKey( 'blacklist', $result['data'] );
	}

	/**
	 * Test geo rules response is correctly unwrapped.
	 */
	public function test_geo_rules_response_unwraps_data_correctly() {
		$this->setup_connected_api();

		$laravel_api_response = array(
			'success' => true,
			'data'    => array(
				'enabled'   => true,
				'mode'      => 'blacklist',
				'countries' => array( 'CN', 'RU' ),
			),
		);

		$this->mock_http_response( 200, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->get_geo_rules();

		$this->assertTrue( $result['success'] );
		$this->assertArrayNotHasKey( 'success', $result['data'] );
		$this->assertArrayHasKey( 'enabled', $result['data'] );
		$this->assertTrue( $result['data']['enabled'] );
	}

	/**
	 * Test vulnerability check response is correctly unwrapped.
	 *
	 * This is critical because the vulnerability scanner depends on
	 * $response['data'] containing the actual scan results.
	 */
	public function test_vulnerability_check_response_unwraps_data_correctly() {
		$this->setup_connected_api();

		$laravel_api_response = array(
			'success' => true,
			'data'    => array(
				'checked_at'  => '2026-01-06T12:00:00Z',
				'wordpress'   => array(
					'version'         => '6.4.2',
					'vulnerabilities' => array(
						array(
							'id'       => 'vuln-123',
							'title'    => 'Test Vulnerability',
							'severity' => 'high',
						),
					),
				),
				'plugins'     => array(),
				'themes'      => array(),
				'summary'     => array(
					'total_vulnerabilities' => 1,
					'critical'              => 0,
					'high'                  => 1,
					'medium'                => 0,
					'low'                   => 0,
				),
				'attribution' => array(
					'provider' => 'Wordfence Intelligence',
				),
			),
		);

		$this->mock_http_response( 200, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->check_vulnerabilities(
			array(
				'wordpress_version' => '6.4.2',
				'plugins'           => array(),
				'themes'            => array(),
			)
		);

		$this->assertTrue( $result['success'] );
		$this->assertArrayNotHasKey( 'success', $result['data'], 'Vulnerability data should not be double-nested' );
		$this->assertArrayHasKey( 'checked_at', $result['data'] );
		$this->assertArrayHasKey( 'wordpress', $result['data'] );
		$this->assertArrayHasKey( 'summary', $result['data'] );
		$this->assertEquals( 1, $result['data']['summary']['total_vulnerabilities'] );
	}

	// =========================================================================
	// ERROR HANDLING CONTRACT TESTS
	// =========================================================================

	/**
	 * Test API-level error response is correctly handled.
	 *
	 * Laravel API returns: {"success": false, "error": "...", "message": "..."}
	 */
	public function test_api_error_response_is_handled_correctly() {
		$this->setup_connected_api();

		$laravel_api_response = array(
			'success' => false,
			'error'   => 'database_unavailable',
			'message' => 'The vulnerability database is currently unavailable.',
		);

		$this->mock_http_response( 200, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->check_vulnerabilities(
			array(
				'wordpress_version' => '6.4.2',
				'plugins'           => array(),
				'themes'            => array(),
			)
		);

		$this->assertFalse( $result['success'] );
		$this->assertArrayHasKey( 'error', $result );
	}

	/**
	 * Test HTTP error response is correctly handled.
	 */
	public function test_http_error_response_is_handled_correctly() {
		$this->setup_connected_api();

		$laravel_api_response = array(
			'success' => false,
			'error'   => 'validation_error',
			'message' => 'Invalid parameters.',
		);

		$this->mock_http_response( 422, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->get_analytics( '24h' );

		$this->assertFalse( $result['success'] );
		$this->assertArrayHasKey( 'error', $result );
		$this->assertArrayHasKey( 'code', $result );
		$this->assertEquals( 422, $result['code'] );
	}

	// =========================================================================
	// JAVASCRIPT AJAX SIMULATION TESTS
	// =========================================================================
	// These tests simulate what the JavaScript receives after AJAX processing.
	// =========================================================================

	/**
	 * Test that AJAX handler receives data in expected format.
	 *
	 * JavaScript expects: response.data.total_requests
	 * NOT: response.data.data.total_requests
	 */
	public function test_ajax_response_structure_for_analytics() {
		$this->setup_connected_api();

		$laravel_api_response = array(
			'success' => true,
			'data'    => array(
				'period'           => '24h',
				'total_requests'   => 1000,
				'unique_visitors'  => 500,
				'requests_blocked' => 50,
				'hourly_data'      => array(),
			),
		);

		$this->mock_http_response( 200, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->get_analytics( '24h' );

		// Simulate what wp_send_json_success($result['data']) would send.
		$ajax_response = array(
			'success' => true,
			'data'    => $result['data'],
		);

		// JavaScript checks: data.total_requests !== undefined.
		$this->assertArrayHasKey( 'total_requests', $ajax_response['data'] );

		// JavaScript uses: data.hourly_data for charts.
		$this->assertArrayHasKey( 'hourly_data', $ajax_response['data'] );

		// Make sure there's no double nesting.
		$this->assertArrayNotHasKey( 'success', $ajax_response['data'] );
		$this->assertArrayNotHasKey( 'data', $ajax_response['data'] );
	}

	/**
	 * Test that vulnerability results are in expected format for JS.
	 */
	public function test_ajax_response_structure_for_vulnerabilities() {
		$this->setup_connected_api();

		$laravel_api_response = array(
			'success' => true,
			'data'    => array(
				'checked_at'  => '2026-01-06T12:00:00Z',
				'summary'     => array(
					'total_vulnerabilities' => 5,
				),
				'attribution' => array(
					'provider' => 'Wordfence Intelligence',
				),
			),
		);

		$this->mock_http_response( 200, $laravel_api_response );

		$api    = $this->create_api_instance();
		$result = $api->check_vulnerabilities(
			array(
				'wordpress_version' => '6.4.2',
				'plugins'           => array(),
				'themes'            => array(),
			)
		);

		// This is what the vulnerability scanner passes to process_api_response().
		$api_data = $result['data'];

		// The scanner checks: isset($api_data['checked_at']).
		$this->assertArrayHasKey( 'checked_at', $api_data );

		// The scanner checks: isset($api_data['summary']).
		$this->assertArrayHasKey( 'summary', $api_data );

		// The scanner checks: isset($api_data['attribution']).
		$this->assertArrayHasKey( 'attribution', $api_data );
	}

	// =========================================================================
	// HELPER METHODS
	// =========================================================================

	/**
	 * Setup a connected API state with encrypted key.
	 *
	 * @return void
	 */
	private function setup_connected_api(): void {
		$api_key = $this->generate_test_api_key();

		// Create API instance to get access to encryption.
		$api = $this->create_api_instance();

		// Encrypt the key using reflection.
		$reflection     = new \ReflectionClass( $api );
		$encrypt_method = $reflection->getMethod( 'encrypt_api_key' );
		$encrypt_method->setAccessible( true );
		$encrypted = $encrypt_method->invoke( $api, $api_key );

		$this->set_option( 'atomicedge_api_key', $encrypted );
		$this->set_option( 'atomicedge_connected', true );
	}

	/**
	 * Mock HTTP response with Laravel API format.
	 *
	 * @param int   $status_code HTTP status code.
	 * @param array $body        Response body (will be JSON encoded).
	 */
	private function mock_http_response( int $status_code, array $body ): void {
		$json_body = wp_json_encode( $body );

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => $status_code ),
				'body'     => $json_body,
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( $status_code );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( $json_body );
	}
}
