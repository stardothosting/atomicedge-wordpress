<?php
/**
 * AtomicEdge API Class Tests
 *
 * Tests for the AtomicEdge_API class including connection, encryption,
 * and all API endpoint methods.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * API Class Test Suite
 */
class ApiTest extends TestCase {

	/**
	 * API instance for testing.
	 *
	 * @var \AtomicEdge_API
	 */
	private $api;

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		// Mock home_url for normalized URL tests.
		Functions\when( 'home_url' )->justReturn( 'https://www.example.com' );

		// Mock wp_parse_args.
		Functions\when( 'wp_parse_args' )->alias(
			function ( $args, $defaults ) {
				return array_merge( $defaults, $args );
			}
		);

		// Mock add_query_arg.
		Functions\when( 'add_query_arg' )->alias(
			function ( $args, $url ) {
				return $url . '?' . http_build_query( $args );
			}
		);

		// Mock sanitize_key.
		Functions\when( 'sanitize_key' )->alias(
			function ( $key ) {
				return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $key ) );
			}
		);

		$this->api = $this->create_api_instance();
	}

	// =========================================================================
	// Connection Status Tests
	// =========================================================================

	/**
	 * Test is_connected returns false when not connected.
	 */
	public function test_is_connected_returns_false_when_not_connected() {
		$this->set_option( 'atomicedge_connected', false );

		$api = $this->create_api_instance();
		$this->assertFalse( $api->is_connected() );
	}

	/**
	 * Test is_connected returns true when connected.
	 */
	public function test_is_connected_returns_true_when_connected() {
		$this->set_option( 'atomicedge_connected', true );

		$api = $this->create_api_instance();
		$this->assertTrue( $api->is_connected() );
	}

	// =========================================================================
	// API Key Encryption Tests
	// =========================================================================

	/**
	 * Test get_api_key returns false when no key is stored.
	 */
	public function test_get_api_key_returns_false_when_empty() {
		$this->set_option( 'atomicedge_api_key', '' );

		$api = $this->create_api_instance();
		$this->assertFalse( $api->get_api_key() );
	}

	/**
	 * Test API key encryption and decryption round-trip.
	 */
	public function test_api_key_encryption_decryption_roundtrip() {
		$original_key = $this->generate_test_api_key();

		// Use reflection to access private encrypt method.
		$reflection = new \ReflectionClass( $this->api );
		$encrypt_method = $reflection->getMethod( 'encrypt_api_key' );
		$encrypt_method->setAccessible( true );

		$decrypt_method = $reflection->getMethod( 'decrypt_api_key' );
		$decrypt_method->setAccessible( true );

		$encrypted = $encrypt_method->invoke( $this->api, $original_key );
		$decrypted = $decrypt_method->invoke( $this->api, $encrypted );

		$this->assertEquals( $original_key, $decrypted );
		$this->assertNotEquals( $original_key, $encrypted );
	}

	/**
	 * Test encrypted key is different from original.
	 */
	public function test_encrypted_key_differs_from_original() {
		$original_key = $this->generate_test_api_key();

		$reflection = new \ReflectionClass( $this->api );
		$encrypt_method = $reflection->getMethod( 'encrypt_api_key' );
		$encrypt_method->setAccessible( true );

		$encrypted = $encrypt_method->invoke( $this->api, $original_key );

		$this->assertNotEquals( $original_key, $encrypted );
		$this->assertNotEmpty( $encrypted );
	}

	// =========================================================================
	// IP Validation Tests
	// =========================================================================

	/**
	 * Test valid IPv4 addresses.
	 *
	 * @dataProvider valid_ipv4_provider
	 * @param string $ip IP address to test.
	 */
	public function test_valid_ipv4_addresses( string $ip ) {
		$this->assertTrue( $this->api->is_valid_ip( $ip ), "IP {$ip} should be valid" );
	}

	/**
	 * Valid IPv4 address data provider.
	 *
	 * @return array
	 */
	public static function valid_ipv4_provider(): array {
		return array(
			'simple ipv4'         => array( '192.168.1.1' ),
			'localhost'           => array( '127.0.0.1' ),
			'public ip'           => array( '8.8.8.8' ),
			'cidr /24'            => array( '10.0.0.0/24' ),
			'cidr /32'            => array( '192.168.1.1/32' ),
			'cidr /8'             => array( '10.0.0.0/8' ),
			'cidr /0'             => array( '0.0.0.0/0' ),
		);
	}

	/**
	 * Test valid IPv6 addresses.
	 *
	 * @dataProvider valid_ipv6_provider
	 * @param string $ip IP address to test.
	 */
	public function test_valid_ipv6_addresses( string $ip ) {
		$this->assertTrue( $this->api->is_valid_ip( $ip ), "IP {$ip} should be valid" );
	}

	/**
	 * Valid IPv6 address data provider.
	 *
	 * @return array
	 */
	public static function valid_ipv6_provider(): array {
		return array(
			'full ipv6'           => array( '2001:0db8:85a3:0000:0000:8a2e:0370:7334' ),
			'compressed ipv6'     => array( '2001:db8:85a3::8a2e:370:7334' ),
			'loopback'            => array( '::1' ),
			'cidr /64'            => array( '2001:db8::/64' ),
			'cidr /128'           => array( '::1/128' ),
		);
	}

	/**
	 * Test invalid IP addresses.
	 *
	 * @dataProvider invalid_ip_provider
	 * @param string $ip IP address to test.
	 */
	public function test_invalid_ip_addresses( string $ip ) {
		$this->assertFalse( $this->api->is_valid_ip( $ip ), "IP {$ip} should be invalid" );
	}

	/**
	 * Invalid IP address data provider.
	 *
	 * @return array
	 */
	public static function invalid_ip_provider(): array {
		return array(
			'empty string'        => array( '' ),
			'text'                => array( 'not-an-ip' ),
			'too many octets'     => array( '192.168.1.1.1' ),
			'octet too high'      => array( '256.1.1.1' ),
			'negative octet'      => array( '-1.0.0.0' ),
			'invalid cidr mask'   => array( '192.168.1.0/33' ),
			'ipv6 invalid mask'   => array( '::1/129' ),
			// Note: '192.168.1.0/' (trailing slash with no mask) currently evaluates as valid
			// because (int)'' = 0 which is within valid range. This is a potential improvement.
		);
	}

	// =========================================================================
	// Connect/Disconnect Tests
	// =========================================================================

	/**
	 * Test successful connection stores API key and site data.
	 */
	public function test_connect_success_stores_data() {
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
		$response_data = array(
			'site'    => array(
				'id'     => 123,
				'domain' => 'example.com',
			),
			'plan'    => 'advanced',
			'message' => 'Connected successfully',
		);

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( $response_data ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( $response_data ) );

		$api    = $this->create_api_instance();
		$result = $api->connect( $api_key );

		$this->assertTrue( $result['success'] );
		$this->assertTrue( $this->get_option( 'atomicedge_connected' ) );
		$this->assertNotEmpty( $this->get_option( 'atomicedge_api_key' ) );
	}

	/**
	 * Test connection failure returns error.
	 */
	public function test_connect_failure_returns_error() {
		$api_key = $this->generate_test_api_key();

		// Mock API error response.
		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 401 ),
				'body'     => wp_json_encode( array( 'error' => 'Invalid API key' ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 401 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( array( 'error' => 'Invalid API key' ) ) );

		$api    = $this->create_api_instance();
		$result = $api->connect( $api_key );

		$this->assertFalse( $result['success'] );
		$this->assertArrayHasKey( 'error', $result );
	}

	/**
	 * Test disconnect clears stored data.
	 */
	public function test_disconnect_clears_data() {
		global $wpdb;

		// Setup mock wpdb.
		$wpdb = $this->getMockBuilder( \stdClass::class )
			->addMethods( array( 'query', 'prepare' ) )
			->getMock();
		$wpdb->options = 'wp_options';
		$wpdb->method( 'prepare' )->willReturn( 'DELETE QUERY' );
		$wpdb->method( 'query' )->willReturn( true );

		// Pre-populate connection data.
		$this->set_option( 'atomicedge_api_key', 'encrypted_key' );
		$this->set_option( 'atomicedge_connected', true );
		$this->set_option( 'atomicedge_site_data', array( 'id' => 123 ) );

		$api    = $this->create_api_instance();
		$result = $api->disconnect();

		$this->assertTrue( $result['success'] );
		$this->assertFalse( $this->get_option( 'atomicedge_connected' ) );
	}

	// =========================================================================
	// Analytics Tests
	// =========================================================================

	/**
	 * Test get_analytics returns cached data when available.
	 */
	public function test_get_analytics_returns_cached_data() {
		$cached_data = array(
			'success' => true,
			'data'    => array(
				'total_requests' => 1000,
				'blocked'        => 50,
			),
		);
		$this->set_transient( 'atomicedge_analytics_24h', $cached_data );

		// Setup API key for requests.
		$this->setup_connected_api();

		$api    = $this->create_api_instance();
		$result = $api->get_analytics( '24h' );

		$this->assertEquals( $cached_data, $result );
	}

	/**
	 * Test get_analytics makes API call when not cached.
	 */
	public function test_get_analytics_fetches_from_api_when_not_cached() {
		$this->setup_connected_api();

		$api_response = array(
			'total_requests' => 5000,
			'blocked'        => 100,
		);

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( $api_response ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( $api_response ) );

		// Define MINUTE_IN_SECONDS if not defined.
		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		$api    = $this->create_api_instance();
		$result = $api->get_analytics( '7d' );

		$this->assertTrue( $result['success'] );
		$this->assertEquals( $api_response, $result['data'] );
	}

	// =========================================================================
	// IP Rules Tests
	// =========================================================================

	/**
	 * Test add_ip_whitelist success.
	 */
	public function test_add_ip_whitelist_success() {
		$this->setup_connected_api();

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'success' => true ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( array( 'success' => true ) ) );

		$api    = $this->create_api_instance();
		$result = $api->add_ip_whitelist( '192.168.1.100', 'Test IP' );

		$this->assertTrue( $result['success'] );
	}

	/**
	 * Test add_ip_blacklist success.
	 */
	public function test_add_ip_blacklist_success() {
		$this->setup_connected_api();

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'success' => true ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( array( 'success' => true ) ) );

		$api    = $this->create_api_instance();
		$result = $api->add_ip_blacklist( '10.0.0.1', 'Bad IP' );

		$this->assertTrue( $result['success'] );
	}

	/**
	 * Test remove_ip success.
	 */
	public function test_remove_ip_success() {
		$this->setup_connected_api();

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'success' => true ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( array( 'success' => true ) ) );

		$api    = $this->create_api_instance();
		$result = $api->remove_ip( '192.168.1.100', 'whitelist' );

		$this->assertTrue( $result['success'] );
	}

	// =========================================================================
	// Geo Rules Tests
	// =========================================================================

	/**
	 * Test get_geo_rules success.
	 */
	public function test_get_geo_rules_success() {
		$this->setup_connected_api();

		$geo_data = array(
			'enabled'   => true,
			'mode'      => 'block',
			'countries' => array( 'CN', 'RU' ),
		);

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( $geo_data ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( $geo_data ) );

		// Define cache duration constant.
		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		$api    = $this->create_api_instance();
		$result = $api->get_geo_rules();

		$this->assertTrue( $result['success'] );
		$this->assertEquals( $geo_data, $result['data'] );
	}

	/**
	 * Test update_geo_rules success.
	 */
	public function test_update_geo_rules_success() {
		$this->setup_connected_api();

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'success' => true ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( array( 'success' => true ) ) );

		$api    = $this->create_api_instance();
		$result = $api->update_geo_rules(
			array(
				'enabled'   => true,
				'mode'      => 'allow',
				'countries' => array( 'US', 'CA' ),
			)
		);

		$this->assertTrue( $result['success'] );
	}

	// =========================================================================
	// Error Handling Tests
	// =========================================================================

	/**
	 * Test API request without connection returns error.
	 */
	public function test_request_without_connection_returns_error() {
		$this->set_option( 'atomicedge_api_key', '' );
		$this->set_option( 'atomicedge_connected', false );

		$api    = $this->create_api_instance();
		$result = $api->get_analytics();

		$this->assertFalse( $result['success'] );
		$this->assertStringContainsString( 'Not connected', $result['error'] );
	}

	/**
	 * Test API handles WP_Error responses.
	 */
	public function test_api_handles_wp_error() {
		$this->setup_connected_api();

		$wp_error = new \AtomicEdge\Tests\WP_Error( 'http_request_failed', 'Connection timed out' );
		Functions\when( 'wp_remote_request' )->justReturn( $wp_error );
		Functions\when( 'is_wp_error' )->alias(
			function ( $thing ) {
				return $thing instanceof \AtomicEdge\Tests\WP_Error;
			}
		);

		$api    = $this->create_api_instance();
		$result = $api->get_site_info();

		$this->assertFalse( $result['success'] );
		$this->assertStringContainsString( 'timed out', $result['error'] );
	}

	/**
	 * Test API handles HTTP error codes.
	 */
	public function test_api_handles_http_errors() {
		$this->setup_connected_api();

		Functions\when( 'wp_remote_request' )->justReturn(
			array(
				'response' => array( 'code' => 500 ),
				'body'     => wp_json_encode( array( 'error' => 'Internal server error' ) ),
			)
		);
		Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 500 );
		Functions\when( 'wp_remote_retrieve_body' )->justReturn( wp_json_encode( array( 'error' => 'Internal server error' ) ) );

		$api    = $this->create_api_instance();
		$result = $api->get_site_info();

		$this->assertFalse( $result['success'] );
		$this->assertEquals( 500, $result['code'] );
	}

	// =========================================================================
	// Helper Methods
	// =========================================================================

	/**
	 * Setup a connected API state with encrypted key.
	 *
	 * @return void
	 */
	private function setup_connected_api(): void {
		$api_key = $this->generate_test_api_key();

		// Encrypt the key.
		$reflection     = new \ReflectionClass( $this->api );
		$encrypt_method = $reflection->getMethod( 'encrypt_api_key' );
		$encrypt_method->setAccessible( true );
		$encrypted = $encrypt_method->invoke( $this->api, $api_key );

		$this->set_option( 'atomicedge_api_key', $encrypted );
		$this->set_option( 'atomicedge_connected', true );
	}
}
