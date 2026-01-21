<?php
/**
 * AtomicEdge CDN Tests
 *
 * Tests for CDN API methods and AJAX handlers.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * Class CdnTest
 *
 * @covers \AtomicEdge_API
 * @covers \AtomicEdge_Ajax
 */
class CdnTest extends TestCase {

	/**
	 * @var \AtomicEdge_API
	 */
	private $api;

	/**
	 * @var \AtomicEdge_Ajax
	 */
	private $ajax;

	/**
	 * Mock API response data.
	 *
	 * @var array
	 */
	private $mock_cdn_status;

	protected function set_up() {
		parent::set_up();

		$_POST = array();

		// Create real API instance for testing.
		$this->api = new \AtomicEdge_API();
		$this->ajax = new \AtomicEdge_Ajax( $this->api );

		// Mock CDN status response.
		$this->mock_cdn_status = array(
			'cdn_enabled'    => true,
			'cdn_prefix'     => 'abc12345',
			'cdn_url'        => 'https://abc12345.cdn.atomicedge.io',
			'cdn_site_type'  => 'wordpress',
			'last_purged_at' => '2026-01-20T10:00:00+00:00',
			'can_purge'      => true,
			'optimization'   => array(
				'brotli'             => true,
				'js_minification'    => false,
				'css_minification'   => false,
				'image_optimization' => false,
			),
			'bandwidth'      => array(
				'period' => 30,
				'total'  => 1073741824, // 1 GB
			),
		);
	}

	/**
	 * Test get_cdn_status returns cached response when available.
	 */
	public function test_get_cdn_status_returns_cached_response() {
		$cached_response = array(
			'success' => true,
			'data'    => $this->mock_cdn_status,
		);

		// Set transient cache.
		set_transient( 'atomicedge_cdn_status', $cached_response, 5 * MINUTE_IN_SECONDS );

		$result = $this->api->get_cdn_status();

		$this->assertTrue( $result['success'] );
		$this->assertSame( 'abc12345', $result['data']['cdn_prefix'] );
	}

	/**
	 * Test get_cdn_status makes API request when cache is empty.
	 */
	public function test_get_cdn_status_makes_api_request_without_cache() {
		// Ensure no cache.
		delete_transient( 'atomicedge_cdn_status' );

		// Mock connection state.
		update_option( 'atomicedge_connected', true );

		// Mock API key.
		$this->mock_api_key( 'test-api-key-12345' );

		// Mock API response.
		$this->mock_api_response( array(
			'success' => true,
			'data'    => $this->mock_cdn_status,
		) );

		$result = $this->api->get_cdn_status();

		$this->assertTrue( $result['success'] );
		$this->assertTrue( $result['data']['cdn_enabled'] );
	}

	/**
	 * Test get_cdn_status returns error when not connected.
	 */
	public function test_get_cdn_status_returns_error_when_not_connected() {
		// Ensure no cache.
		delete_transient( 'atomicedge_cdn_status' );

		// No API key set.
		delete_option( 'atomicedge_api_key' );

		$result = $this->api->get_cdn_status();

		$this->assertFalse( $result['success'] );
		$this->assertArrayHasKey( 'error', $result );
	}

	/**
	 * Test purge_cdn_cache makes API request and clears cache.
	 */
	public function test_purge_cdn_cache_clears_status_cache_on_success() {
		// Set up cached CDN status.
		set_transient( 'atomicedge_cdn_status', array( 'cached' => true ), 5 * MINUTE_IN_SECONDS );

		// Mock connection and API key.
		update_option( 'atomicedge_connected', true );
		$this->mock_api_key( 'test-api-key-12345' );

		// Mock successful purge response.
		$this->mock_api_response( array(
			'success'   => true,
			'message'   => 'Cache purge has been queued.',
			'purged_at' => '2026-01-20T12:00:00+00:00',
		) );

		$result = $this->api->purge_cdn_cache();

		$this->assertTrue( $result['success'] );

		// Verify cache was cleared.
		$this->assertFalse( get_transient( 'atomicedge_cdn_status' ) );
	}

	/**
	 * Test purge_cdn_cache returns error when CDN is disabled.
	 */
	public function test_purge_cdn_cache_returns_error_when_cdn_disabled() {
		// Mock connection and API key.
		update_option( 'atomicedge_connected', true );
		$this->mock_api_key( 'test-api-key-12345' );

		// Mock error response.
		$this->mock_api_response( array(
			'success' => false,
			'error'   => 'cdn_disabled',
			'message' => 'CDN is not enabled for this site.',
		), 400 );

		$result = $this->api->purge_cdn_cache();

		$this->assertFalse( $result['success'] );
	}

	/**
	 * Test purge_cdn_cache returns error on cooldown.
	 */
	public function test_purge_cdn_cache_returns_error_on_cooldown() {
		// Mock connection and API key.
		update_option( 'atomicedge_connected', true );
		$this->mock_api_key( 'test-api-key-12345' );

		// Mock cooldown response.
		$this->mock_api_response( array(
			'success'      => false,
			'error'        => 'cooldown_active',
			'message'      => 'Please wait 5 minutes between purge requests.',
			'can_purge_at' => '2026-01-20T12:05:00+00:00',
		), 429 );

		$result = $this->api->purge_cdn_cache();

		$this->assertFalse( $result['success'] );
	}

	/**
	 * Test update_cdn_settings sends correct data.
	 */
	public function test_update_cdn_settings_sends_settings() {
		// Mock connection and API key.
		update_option( 'atomicedge_connected', true );
		$this->mock_api_key( 'test-api-key-12345' );

		// Set up cached CDN status.
		set_transient( 'atomicedge_cdn_status', array( 'cached' => true ), 5 * MINUTE_IN_SECONDS );

		// Mock successful response.
		$this->mock_api_response( array(
			'success' => true,
			'message' => 'CDN settings updated successfully.',
		) );

		$settings = array(
			'brotli'             => true,
			'js_minification'    => true,
			'css_minification'   => false,
			'image_optimization' => true,
		);

		$result = $this->api->update_cdn_settings( $settings );

		$this->assertTrue( $result['success'] );

		// Verify cache was cleared.
		$this->assertFalse( get_transient( 'atomicedge_cdn_status' ) );
	}

	/**
	 * Test update_cdn_settings returns error on validation failure.
	 */
	public function test_update_cdn_settings_returns_validation_error() {
		// Mock connection and API key.
		update_option( 'atomicedge_connected', true );
		$this->mock_api_key( 'test-api-key-12345' );

		// Mock validation error response.
		$this->mock_api_response( array(
			'success' => false,
			'error'   => 'validation_error',
			'message' => 'Invalid parameters.',
			'errors'  => array(
				'brotli' => array( 'The brotli field must be true or false.' ),
			),
		), 422 );

		$settings = array( 'brotli' => 'invalid' );

		$result = $this->api->update_cdn_settings( $settings );

		$this->assertFalse( $result['success'] );
	}

	/**
	 * Test CDN status with disabled CDN.
	 */
	public function test_get_cdn_status_disabled() {
		$disabled_status = array(
			'cdn_enabled'   => false,
			'cdn_prefix'    => null,
			'cdn_url'       => null,
			'optimization'  => array(
				'brotli'             => true,
				'js_minification'    => false,
				'css_minification'   => false,
				'image_optimization' => false,
			),
			'bandwidth'     => array(
				'period' => 0,
				'total'  => 0,
			),
		);

		set_transient( 'atomicedge_cdn_status', array(
			'success' => true,
			'data'    => $disabled_status,
		), 5 * MINUTE_IN_SECONDS );

		$result = $this->api->get_cdn_status();

		$this->assertTrue( $result['success'] );
		$this->assertFalse( $result['data']['cdn_enabled'] );
		$this->assertNull( $result['data']['cdn_url'] );
	}

	/**
	 * Helper to mock API key.
	 *
	 * @param string $key The API key to mock.
	 */
	private function mock_api_key( $key ) {
		// Use the same encryption as the API class.
		$iv        = substr( NONCE_KEY, 0, 16 );
		$encrypted = openssl_encrypt(
			$key,
			'AES-256-CBC',
			hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY ),
			0,
			$iv
		);
		update_option( 'atomicedge_api_key', base64_encode( $encrypted ) );
	}

	/**
	 * Helper to mock API response.
	 *
	 * @param array $body     Response body.
	 * @param int   $code     HTTP status code.
	 */
	private function mock_api_response( $body, $code = 200 ) {
		Functions\when( 'wp_remote_request' )->justReturn( array(
			'response' => array( 'code' => $code ),
			'body'     => wp_json_encode( $body ),
		) );
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( $code );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( $body ) );
		Functions\when( 'is_wp_error' )->justReturn( false );
	}
}
