<?php
/**
 * AtomicEdge AJAX Handler Tests
 *
 * Tests for the AtomicEdge_Ajax class including all AJAX endpoints,
 * security validations, and input sanitization.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * AJAX Handler Test Suite
 */
class AjaxTest extends TestCase {

	/**
	 * AJAX handler instance.
	 *
	 * @var \AtomicEdge_Ajax
	 */
	private $ajax;

	/**
	 * Mock API instance.
	 *
	 * @var \AtomicEdge_API|\PHPUnit\Framework\MockObject\MockObject
	 */
	private $mock_api;

	/**
	 * Captured JSON response.
	 *
	 * @var array|null
	 */
	private $json_response = null;

	/**
	 * JSON response type (success/error).
	 *
	 * @var string|null
	 */
	private $json_response_type = null;

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		// Reset request globals to avoid state leakage across tests.
		$_POST    = array();
		$_GET     = array();
		$_REQUEST = array();

		// Reset response capture.
		$this->json_response      = null;
		$this->json_response_type = null;

		// Create mock API.
		$this->mock_api = $this->createMock( \AtomicEdge_API::class );

		// Mock wp_send_json_success to capture output.
		Functions\when( 'wp_send_json_success' )->alias(
			function ( $data = null ) {
				$this->json_response      = $data;
				$this->json_response_type = 'success';
				// Throw exception to halt execution (simulating exit).
				throw new \AtomicEdge\Tests\AjaxExitException( 'success' );
			}
		);

		// Mock wp_send_json_error to capture output.
		Functions\when( 'wp_send_json_error' )->alias(
			function ( $data = null ) {
				$this->json_response      = $data;
				$this->json_response_type = 'error';
				throw new \AtomicEdge\Tests\AjaxExitException( 'error' );
			}
		);

		// Mock sanitize_key.
		Functions\when( 'sanitize_key' )->alias(
			function ( $key ) {
				return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $key ) );
			}
		);

		// Create AJAX handler with mock API.
		$this->ajax = new \AtomicEdge_Ajax( $this->mock_api );
	}

	// =========================================================================
	// Security Validation Tests
	// =========================================================================

	/**
	 * Test AJAX handler rejects invalid nonce.
	 */
	public function test_ajax_rejects_invalid_nonce() {
		// Override check_ajax_referer to fail.
		Functions\when( 'check_ajax_referer' )->alias(
			function () {
				// Trigger the JSON error path.
				$this->json_response      = array( 'message' => 'Security check failed.' );
				$this->json_response_type = 'error';
				throw new \AtomicEdge\Tests\AjaxExitException( 'error' );
			}
		);

		try {
			$this->ajax->ajax_get_analytics();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
	}

	/**
	 * Test AJAX handler rejects unauthorized users.
	 */
	public function test_ajax_rejects_unauthorized_users() {
		// Override current_user_can to return false.
		Functions\when( 'current_user_can' )->justReturn( false );

		// Mock check_ajax_referer to pass but then fail on capability check.
		Functions\when( 'check_ajax_referer' )->justReturn( true );

		// We need to re-create the handler to pick up the new mock.
		$this->ajax = new \AtomicEdge_Ajax( $this->mock_api );

		// The verify_ajax_request method should call wp_send_json_error.
		// We need to test this by invoking an AJAX method.
		try {
			$this->ajax->ajax_get_analytics();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'permission', $this->json_response['message'] ?? '' );
	}

	// =========================================================================
	// Analytics AJAX Tests
	// =========================================================================

	/**
	 * Test get_analytics success response.
	 */
	public function test_ajax_get_analytics_success() {
		$_POST['period'] = '7d';

		$analytics_data = array(
			'total_requests' => 10000,
			'blocked'        => 500,
		);

		$this->mock_api->method( 'get_analytics' )
			->with( '7d' )
			->willReturn(
				array(
					'success' => true,
					'data'    => $analytics_data,
				)
			);

		try {
			$this->ajax->ajax_get_analytics();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertEquals( $analytics_data, $this->json_response );
	}

	/**
	 * Test get_analytics with invalid period defaults to 24h.
	 */
	public function test_ajax_get_analytics_invalid_period_defaults() {
		$_POST['period'] = 'invalid';

		$this->mock_api->expects( $this->once() )
			->method( 'get_analytics' )
			->with( '24h' ) // Should default to 24h.
			->willReturn(
				array(
					'success' => true,
					'data'    => array(),
				)
			);

		try {
			$this->ajax->ajax_get_analytics();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}
	}

	/**
	 * Test get_analytics error response.
	 */
	public function test_ajax_get_analytics_error() {
		$_POST['period'] = '24h';

		$this->mock_api->method( 'get_analytics' )
			->willReturn(
				array(
					'success' => false,
					'error'   => 'API unavailable',
				)
			);

		try {
			$this->ajax->ajax_get_analytics();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertEquals( 'API unavailable', $this->json_response['message'] );
	}

	// =========================================================================
	// WAF Logs AJAX Tests
	// =========================================================================

	/**
	 * Test get_waf_logs with default parameters.
	 */
	public function test_ajax_get_waf_logs_defaults() {
		$waf_logs = array(
			'logs'  => array(),
			'total' => 0,
		);

		$this->mock_api->expects( $this->once() )
			->method( 'get_waf_logs' )
			->with(
				$this->callback(
					function ( $args ) {
						return $args['page'] === 1 && $args['per_page'] === 50;
					}
				)
			)
			->willReturn(
				array(
					'success' => true,
					'data'    => $waf_logs,
				)
			);

		try {
			$this->ajax->ajax_get_waf_logs();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	/**
	 * Test get_waf_logs with pagination.
	 */
	public function test_ajax_get_waf_logs_with_pagination() {
		$_POST['page']     = 3;
		$_POST['per_page'] = 25;
		$_POST['search']   = 'blocked';

		$this->mock_api->expects( $this->once() )
			->method( 'get_waf_logs' )
			->with(
				$this->callback(
					function ( $args ) {
						return $args['page'] === 3
							&& $args['per_page'] === 25
							&& $args['search'] === 'blocked';
					}
				)
			)
			->willReturn(
				array(
					'success' => true,
					'data'    => array(),
				)
			);

		try {
			$this->ajax->ajax_get_waf_logs();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}
	}

	/**
	 * Test get_waf_logs enforces per_page maximum.
	 */
	public function test_ajax_get_waf_logs_enforces_per_page_max() {
		$_POST['per_page'] = 500; // Over limit.

		$this->mock_api->expects( $this->once() )
			->method( 'get_waf_logs' )
			->with(
				$this->callback(
					function ( $args ) {
						return $args['per_page'] === 50; // Should be capped.
					}
				)
			)
			->willReturn(
				array(
					'success' => true,
					'data'    => array(),
				)
			);

		try {
			$this->ajax->ajax_get_waf_logs();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}
	}

	// =========================================================================
	// IP Rules AJAX Tests
	// =========================================================================

	/**
	 * Test add_ip_whitelist validates empty IP.
	 */
	public function test_ajax_add_ip_whitelist_rejects_empty_ip() {
		$_POST['ip'] = '';

		try {
			$this->ajax->ajax_add_ip_whitelist();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'enter an IP', $this->json_response['message'] );
	}

	/**
	 * Test add_ip_whitelist validates IP format.
	 */
	public function test_ajax_add_ip_whitelist_rejects_invalid_ip() {
		$_POST['ip'] = 'not-an-ip';

		$this->mock_api->method( 'is_valid_ip' )
			->with( 'not-an-ip' )
			->willReturn( false );

		try {
			$this->ajax->ajax_add_ip_whitelist();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Invalid IP', $this->json_response['message'] );
	}

	/**
	 * Test add_ip_whitelist success.
	 */
	public function test_ajax_add_ip_whitelist_success() {
		$_POST['ip']          = '192.168.1.100';
		$_POST['description'] = 'Test IP';

		$this->mock_api->method( 'is_valid_ip' )
			->willReturn( true );

		$this->mock_api->method( 'add_ip_whitelist' )
			->with( '192.168.1.100', 'Test IP' )
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_add_ip_whitelist();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	/**
	 * Test add_ip_blacklist success.
	 */
	public function test_ajax_add_ip_blacklist_success() {
		$_POST['ip']          = '10.0.0.1';
		$_POST['description'] = 'Blocked IP';

		$this->mock_api->method( 'is_valid_ip' )
			->willReturn( true );

		$this->mock_api->method( 'add_ip_blacklist' )
			->with( '10.0.0.1', 'Blocked IP' )
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_add_ip_blacklist();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	/**
	 * Test remove_ip validates list type.
	 */
	public function test_ajax_remove_ip_validates_list_type() {
		$_POST['ip']   = '192.168.1.1';
		$_POST['type'] = 'invalid-type';

		try {
			$this->ajax->ajax_remove_ip();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Invalid list type', $this->json_response['message'] );
	}

	/**
	 * Test remove_ip success.
	 */
	public function test_ajax_remove_ip_success() {
		$_POST['ip']   = '192.168.1.100';
		$_POST['type'] = 'whitelist';

		$this->mock_api->method( 'remove_ip' )
			->with( '192.168.1.100', 'whitelist' )
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_remove_ip();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	// =========================================================================
	// Geo Rules AJAX Tests
	// =========================================================================

	/**
	 * Test get_geo_rules success.
	 */
	public function test_ajax_get_geo_rules_success() {
		$geo_data = array(
			'enabled'   => true,
			'mode'      => 'blacklist',
			'countries' => array( 'CN', 'RU' ),
		);

		$this->mock_api->method( 'get_geo_rules' )
			->willReturn(
				array(
					'success' => true,
					'data'    => $geo_data,
				)
			);

		try {
			$this->ajax->ajax_get_geo_rules();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertEquals( $geo_data, $this->json_response );
	}

	/**
	 * Test update_geo_rules validates and sanitizes input.
	 */
	public function test_ajax_update_geo_rules_sanitizes_input() {
		$_POST['enabled']   = 'true';
		$_POST['mode']      = 'whitelist';
		$_POST['countries'] = array( 'US', 'CA', 'invalid', 'uk' ); // Mix of valid/invalid.

		$this->mock_api->expects( $this->once() )
			->method( 'update_geo_rules' )
			->with(
				$this->callback(
					function ( $rules ) {
						// Should filter out invalid country codes.
						return $rules['enabled'] === true
							&& $rules['mode'] === 'whitelist'
							&& in_array( 'US', $rules['countries'], true )
							&& in_array( 'CA', $rules['countries'], true )
							&& ! in_array( 'invalid', $rules['countries'], true );
					}
				)
			)
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_update_geo_rules();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}
	}

	/**
	 * Test update_geo_rules defaults invalid mode.
	 */
	public function test_ajax_update_geo_rules_defaults_invalid_mode() {
		$_POST['enabled']   = 'true';
		$_POST['mode']      = 'invalid-mode';
		$_POST['countries'] = array( 'US' );

		$this->mock_api->expects( $this->once() )
			->method( 'update_geo_rules' )
			->with(
				$this->callback(
					function ( $rules ) {
						return $rules['mode'] === 'blacklist'; // Should default.
					}
				)
			)
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_update_geo_rules();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}
	}

	// =========================================================================
	// Cache AJAX Tests
	// =========================================================================

	/**
	 * Test clear_cache calls API method.
	 */
	public function test_ajax_clear_cache_success() {
		$this->mock_api->expects( $this->once() )
			->method( 'clear_cache' );

		try {
			$this->ajax->ajax_clear_cache();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}
}

// Custom exception for simulating AJAX exit.
namespace AtomicEdge\Tests;

/**
 * Exception to simulate wp_send_json exit behavior.
 */
class AjaxExitException extends \Exception {
}
