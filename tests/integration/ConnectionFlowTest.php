<?php
/**
 * AtomicEdge Integration Tests
 *
 * Tests that verify components work together correctly.
 * These tests simulate real-world usage scenarios.
 *
 * @package AtomicEdge\Tests\Integration
 */

namespace AtomicEdge\Tests\Integration;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * Integration Test Suite
 */
class ConnectionFlowTest extends TestCase {

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		// Mock home_url.
		Functions\when( 'home_url' )->justReturn( 'https://www.example.com' );

		// Mock wp_parse_args.
		Functions\when( 'wp_parse_args' )->alias(
			function ( $args, $defaults ) {
				return array_merge( $defaults, $args );
			}
		);
	}

	// =========================================================================
	// Full Connection Flow Tests
	// =========================================================================

	/**
	 * Test complete connection flow from API key to connected state.
	 */
	public function test_full_connection_flow() {
		global $wpdb;

		// Mock wpdb for cache clearing.
		$wpdb          = $this->getMockBuilder( \stdClass::class )
			->addMethods( array( 'query', 'prepare' ) )
			->getMock();
		$wpdb->options = 'wp_options';
		$wpdb->method( 'prepare' )->willReturn( 'DELETE QUERY' );
		$wpdb->method( 'query' )->willReturn( true );

		$api_key = $this->generate_test_api_key();

		// Mock successful API response.
		$site_data = array(
			'site' => array(
				'id'     => 123,
				'domain' => 'example.com',
			),
			'plan' => 'advanced',
			'features' => array(
				'waf'       => true,
				'analytics' => true,
			),
		);

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( $site_data ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( $site_data ) );

		// Create API and connect.
		$api    = new \AtomicEdge_API();
		$result = $api->connect( $api_key );

		// Verify connection succeeded.
		$this->assertTrue( $result['success'] );
		$this->assertTrue( $api->is_connected() );

		// Verify site data was stored.
		$stored_data = $this->get_option( 'atomicedge_site_data' );
		$this->assertEquals( $site_data, $stored_data );

		// Verify API key was encrypted and stored.
		$encrypted_key = $this->get_option( 'atomicedge_api_key' );
		$this->assertNotEmpty( $encrypted_key );
		$this->assertNotEquals( $api_key, $encrypted_key );

		// Verify we can retrieve the key.
		$this->assertEquals( $api_key, $api->get_api_key() );
	}

	/**
	 * Test connection failure doesn't change state.
	 */
	public function test_connection_failure_preserves_state() {
		$api_key = $this->generate_test_api_key();

		// Mock failed API response.
		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 401 ),
				'body'     => wp_json_encode( array( 'error' => 'Invalid API key' ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 401 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( array( 'error' => 'Invalid API key' ) ) );

		$api    = new \AtomicEdge_API();
		$result = $api->connect( $api_key );

		// Verify connection failed.
		$this->assertFalse( $result['success'] );
		$this->assertFalse( $api->is_connected() );

		// Verify no data was stored.
		$this->assertEmpty( $this->get_option( 'atomicedge_api_key' ) );
		$this->assertEmpty( $this->get_option( 'atomicedge_site_data' ) );
	}

	/**
	 * Test disconnection clears all data.
	 */
	public function test_disconnection_clears_all_data() {
		global $wpdb;

		// Mock wpdb.
		$wpdb          = $this->getMockBuilder( \stdClass::class )
			->addMethods( array( 'query', 'prepare' ) )
			->getMock();
		$wpdb->options = 'wp_options';
		$wpdb->method( 'prepare' )->willReturn( 'DELETE QUERY' );
		$wpdb->method( 'query' )->willReturn( true );

		// Set up connected state.
		$this->set_option( 'atomicedge_api_key', 'encrypted_key' );
		$this->set_option( 'atomicedge_connected', true );
		$this->set_option(
			'atomicedge_site_data',
			array(
				'id'     => 123,
				'domain' => 'example.com',
			)
		);

		// Disconnect.
		$api    = new \AtomicEdge_API();
		$result = $api->disconnect();

		// Verify disconnection succeeded.
		$this->assertTrue( $result['success'] );
		$this->assertFalse( $api->is_connected() );

		// Verify data was cleared.
		$this->assertFalse( $this->get_option( 'atomicedge_connected' ) );
	}

	// =========================================================================
	// API Request Flow Tests
	// =========================================================================

	/**
	 * Test API requests use cached data when available.
	 */
	public function test_api_requests_use_cache() {
		// Setup connected state.
		$api = $this->setup_connected_api();

		// Pre-populate cache.
		$cached_analytics = array(
			'success' => true,
			'data'    => array(
				'total_requests' => 5000,
				'blocked'        => 100,
			),
		);
		$this->set_transient( 'atomicedge_analytics_24h', $cached_analytics );

		// Mock should NOT be called since cache exists.
		Functions\when( 'wp_remote_request' )->alias(
			function () {
				$this->fail( 'API should not be called when cache exists' );
			}
		);

		$result = $api->get_analytics( '24h' );

		$this->assertEquals( $cached_analytics, $result );
	}

	/**
	 * Test API requests fetch fresh data when cache empty.
	 */
	public function test_api_requests_fetch_when_cache_empty() {
		// Define MINUTE_IN_SECONDS if not defined.
		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		// Setup connected state.
		$api = $this->setup_connected_api();

		$api_response = array(
			'total_requests' => 10000,
			'blocked'        => 500,
		);

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( $api_response ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( $api_response ) );
		Functions\when( 'add_query_arg' )->alias(
			function ( $args, $url ) {
				return $url . '?' . http_build_query( $args );
			}
		);

		$result = $api->get_analytics( '7d' );

		$this->assertTrue( $result['success'] );
		$this->assertEquals( $api_response, $result['data'] );
	}

	// =========================================================================
	// Scanner Integration Tests
	// =========================================================================

	/**
	 * Test scanner results are persisted and retrievable.
	 */
	public function test_scanner_results_persistence() {
		global $wp_version;
		$wp_version = '6.4';

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
		Functions\when( 'get_locale' )->justReturn( 'en_US' );
		Functions\when( 'is_wp_error' )->justReturn( false );
		Functions\when( 'wp_upload_dir' )->justReturn(
			array(
				'basedir' => '/tmp/wp-uploads',
				'baseurl' => 'http://example.com/wp-content/uploads',
			)
		);

		// Run scan.
		$scanner = new \AtomicEdge_Scanner();
		$results = $scanner->run_full_scan();

		// Verify results were saved.
		$saved_results = $scanner->get_last_results();
		$this->assertEquals( $results, $saved_results );

		// Verify timestamp was saved.
		$last_scan = $scanner->get_last_scan_time();
		$this->assertNotFalse( $last_scan );
	}

	// =========================================================================
	// Helper Methods
	// =========================================================================

	/**
	 * Setup a connected API instance.
	 *
	 * @return \AtomicEdge_API
	 */
	private function setup_connected_api(): \AtomicEdge_API {
		$api     = new \AtomicEdge_API();
		$api_key = $this->generate_test_api_key();

		// Use reflection to encrypt key.
		$reflection     = new \ReflectionClass( $api );
		$encrypt_method = $reflection->getMethod( 'encrypt_api_key' );
		$encrypt_method->setAccessible( true );
		$encrypted = $encrypt_method->invoke( $api, $api_key );

		$this->set_option( 'atomicedge_api_key', $encrypted );
		$this->set_option( 'atomicedge_connected', true );

		return $api;
	}
}
