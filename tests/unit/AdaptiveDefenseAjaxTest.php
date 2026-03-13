<?php
/**
 * Adaptive Defense AJAX Handler Tests
 *
 * Tests for all Adaptive Defense AJAX endpoints including:
 * - Block IP (success, validation, API error, parameter pass-through)
 * - Unblock IP (success, validation, API error)
 * - Delete actor profile (success, validation, API error)
 * - Dismiss threat detection (success, validation, API error)
 * - Get threat detection detail (success, validation, API error, response contract)
 * - Get actor profiles (success, pagination, filters)
 * - Get threat detections (success, status filter)
 * - Get adaptive defense overview (success, API error)
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use AtomicEdge\Tests\AjaxExitException;
use Brain\Monkey\Functions;

/**
 * Adaptive Defense AJAX Handler Test Suite
 */
class AdaptiveDefenseAjaxTest extends TestCase {

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

		// Provide a valid nonce by default for AJAX handlers.
		$_POST['nonce'] = 'valid-nonce';

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
				throw new AjaxExitException( 'success' );
			}
		);

		// Mock wp_send_json_error to capture output.
		Functions\when( 'wp_send_json_error' )->alias(
			function ( $data = null ) {
				$this->json_response      = $data;
				$this->json_response_type = 'error';
				throw new AjaxExitException( 'error' );
			}
		);

		// Mock sanitize_key.
		Functions\when( 'sanitize_key' )->alias(
			function ( $key ) {
				return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $key ) );
			}
		);

		// Mock nonce verification and capability checks by default.
		Functions\when( 'wp_verify_nonce' )->justReturn( true );
		Functions\when( 'current_user_can' )->justReturn( true );

		// Create AJAX handler with mock API.
		$this->ajax = new \AtomicEdge_Ajax( $this->mock_api );
	}

	// =========================================================================
	// Block IP Tests
	// =========================================================================

	/**
	 * Test block IP success with default duration.
	 */
	public function test_ajax_block_ip_success() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->expects( $this->once() )
			->method( 'block_ip' )
			->with( '192.168.1.100', false, '' )
			->willReturn( array(
				'success' => true,
				'data'    => array( 'blocked_at' => '2026-03-01T12:00:00Z' ),
			) );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'message', $this->json_response );
		$this->assertStringContainsString( '192.168.1.100', $this->json_response['message'] );
		$this->assertStringContainsString( 'blocked', $this->json_response['message'] );
	}

	/**
	 * Test block IP with permanent flag and reason.
	 */
	public function test_ajax_block_ip_with_custom_parameters() {
		$_POST['ip']        = '10.0.0.1';
		$_POST['permanent'] = 'true';
		$_POST['reason']    = 'Suspicious activity detected';

		$this->mock_api->expects( $this->once() )
			->method( 'block_ip' )
			->with( '10.0.0.1', true, 'Suspicious activity detected' )
			->willReturn( array(
				'success' => true,
				'data'    => array(),
			) );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringContainsString( '10.0.0.1', $this->json_response['message'] );
	}

	/**
	 * Test block IP requires IP address.
	 */
	public function test_ajax_block_ip_requires_ip() {
		// No IP in POST.

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'IP address is required', $this->json_response['message'] );
	}

	/**
	 * Test block IP requires non-empty IP address.
	 */
	public function test_ajax_block_ip_requires_nonempty_ip() {
		$_POST['ip'] = '';

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'IP address is required', $this->json_response['message'] );
	}

	/**
	 * Test block IP API error is propagated.
	 */
	public function test_ajax_block_ip_api_error() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->method( 'block_ip' )
			->willReturn( array(
				'success' => false,
				'error'   => 'IP address is already blocked.',
			) );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'already blocked', $this->json_response['message'] );
	}

	/**
	 * Test block IP API error without error message falls back to generic.
	 */
	public function test_ajax_block_ip_api_error_fallback_message() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->method( 'block_ip' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to block', $this->json_response['message'] );
	}

	/**
	 * Test block IP with permanent=false (string) is treated as non-permanent.
	 */
	public function test_ajax_block_ip_permanent_false_string() {
		$_POST['ip']        = '10.0.0.1';
		$_POST['permanent'] = 'false';

		$this->mock_api->expects( $this->once() )
			->method( 'block_ip' )
			->with( '10.0.0.1', false, '' )
			->willReturn( array( 'success' => true, 'data' => array() ) );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	/**
	 * Test block IP response includes data payload.
	 */
	public function test_ajax_block_ip_response_includes_data() {
		$_POST['ip'] = '10.0.0.1';

		$block_data = array(
			'blocked_at'       => '2026-03-01T12:00:00Z',
			'block_expires_at' => '2026-03-02T12:00:00Z',
			'is_blocked'       => true,
		);

		$this->mock_api->method( 'block_ip' )
			->willReturn( array(
				'success' => true,
				'data'    => $block_data,
			) );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'data', $this->json_response );
		$this->assertEquals( $block_data, $this->json_response['data'] );
	}

	// =========================================================================
	// Unblock IP Tests
	// =========================================================================

	/**
	 * Test unblock IP success.
	 */
	public function test_ajax_unblock_ip_success() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->expects( $this->once() )
			->method( 'unblock_ip' )
			->with( '192.168.1.100' )
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'message', $this->json_response );
		$this->assertStringContainsString( '192.168.1.100', $this->json_response['message'] );
		$this->assertStringContainsString( 'unblocked', $this->json_response['message'] );
	}

	/**
	 * Test unblock IP requires IP address.
	 */
	public function test_ajax_unblock_ip_requires_ip() {
		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'IP address is required', $this->json_response['message'] );
	}

	/**
	 * Test unblock IP requires non-empty IP address.
	 */
	public function test_ajax_unblock_ip_requires_nonempty_ip() {
		$_POST['ip'] = '';

		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'IP address is required', $this->json_response['message'] );
	}

	/**
	 * Test unblock IP API error.
	 */
	public function test_ajax_unblock_ip_api_error() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->method( 'unblock_ip' )
			->willReturn( array(
				'success' => false,
				'error'   => 'IP is not currently blocked.',
			) );

		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'not currently blocked', $this->json_response['message'] );
	}

	/**
	 * Test unblock IP API error without error message falls back to generic.
	 */
	public function test_ajax_unblock_ip_api_error_fallback_message() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->method( 'unblock_ip' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to unblock', $this->json_response['message'] );
	}

	// =========================================================================
	// Delete Actor Profile Tests
	// =========================================================================

	/**
	 * Test delete actor profile success.
	 */
	public function test_ajax_delete_actor_success() {
		$_POST['actor_id'] = '42';

		$this->mock_api->expects( $this->once() )
			->method( 'delete_actor_profile' )
			->with( 42 )
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_delete_actor();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringContainsString( 'deleted', $this->json_response['message'] );
	}

	/**
	 * Test delete actor profile requires actor_id.
	 */
	public function test_ajax_delete_actor_requires_id() {
		try {
			$this->ajax->ajax_delete_actor();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Actor ID is required', $this->json_response['message'] );
	}

	/**
	 * Test delete actor profile with empty actor_id.
	 */
	public function test_ajax_delete_actor_rejects_empty_id() {
		$_POST['actor_id'] = '';

		try {
			$this->ajax->ajax_delete_actor();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Actor ID is required', $this->json_response['message'] );
	}

	/**
	 * Test delete actor profile API error.
	 */
	public function test_ajax_delete_actor_api_error() {
		$_POST['actor_id'] = '42';

		$this->mock_api->method( 'delete_actor_profile' )
			->willReturn( array(
				'success' => false,
				'error'   => 'Actor profile not found.',
			) );

		try {
			$this->ajax->ajax_delete_actor();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'not found', $this->json_response['message'] );
	}

	/**
	 * Test delete actor profile API error fallback message.
	 */
	public function test_ajax_delete_actor_api_error_fallback_message() {
		$_POST['actor_id'] = '42';

		$this->mock_api->method( 'delete_actor_profile' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_delete_actor();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to delete', $this->json_response['message'] );
	}

	/**
	 * Test delete actor passes actor_id as integer (absint).
	 */
	public function test_ajax_delete_actor_casts_id_to_int() {
		$_POST['actor_id'] = '99';

		$this->mock_api->expects( $this->once() )
			->method( 'delete_actor_profile' )
			->with( 99 ) // Should be integer, not string.
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_delete_actor();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	// =========================================================================
	// Dismiss Threat Detection Tests
	// =========================================================================

	/**
	 * Test dismiss detection success.
	 */
	public function test_ajax_dismiss_detection_success() {
		$_POST['detection_id'] = '15';

		$this->mock_api->expects( $this->once() )
			->method( 'dismiss_threat_detection' )
			->with( 15 )
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringContainsString( 'dismissed', $this->json_response['message'] );
	}

	/**
	 * Test dismiss detection requires detection_id.
	 */
	public function test_ajax_dismiss_detection_requires_id() {
		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Detection ID is required', $this->json_response['message'] );
	}

	/**
	 * Test dismiss detection with empty detection_id.
	 */
	public function test_ajax_dismiss_detection_rejects_empty_id() {
		$_POST['detection_id'] = '';

		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Detection ID is required', $this->json_response['message'] );
	}

	/**
	 * Test dismiss detection API error.
	 */
	public function test_ajax_dismiss_detection_api_error() {
		$_POST['detection_id'] = '15';

		$this->mock_api->method( 'dismiss_threat_detection' )
			->willReturn( array(
				'success' => false,
				'error'   => 'Detection already dismissed.',
			) );

		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'already dismissed', $this->json_response['message'] );
	}

	/**
	 * Test dismiss detection API error fallback message.
	 */
	public function test_ajax_dismiss_detection_api_error_fallback_message() {
		$_POST['detection_id'] = '15';

		$this->mock_api->method( 'dismiss_threat_detection' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to dismiss', $this->json_response['message'] );
	}

	/**
	 * Test dismiss detection casts detection_id to integer.
	 */
	public function test_ajax_dismiss_detection_casts_id_to_int() {
		$_POST['detection_id'] = '77';

		$this->mock_api->expects( $this->once() )
			->method( 'dismiss_threat_detection' )
			->with( 77 )
			->willReturn( array( 'success' => true ) );

		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	// =========================================================================
	// Get Threat Detection Detail Tests
	// =========================================================================

	/**
	 * Test get detection detail success.
	 */
	public function test_ajax_get_threat_detection_detail_success() {
		$_POST['detection_id'] = '7';

		$detail_data = array(
			'id'             => 7,
			'ip'             => '192.168.1.100',
			'ip_address'     => '192.168.1.100',
			'score'          => 85,
			'threat_level'   => 'critical',
			'key_indicators' => array( 'High WAF hit rate', 'Suspicious patterns' ),
			'status'         => 'pending_review',
			'detected_at'    => '2026-02-05T11:30:05+00:00',
			'created_at'     => '2026-02-05T11:30:05+00:00',
			'actor'          => array(
				'ip'               => '192.168.1.100',
				'ip_address'       => '192.168.1.100',
				'total_waf_hits'   => 150,
				'waf_hits'         => 150,
				'total_requests'   => 500,
				'total_4xx_errors' => 30,
				'error_4xx'        => 30,
				'total_5xx_errors' => 5,
				'error_5xx'        => 5,
				'first_seen'       => '2026-02-01T08:00:00Z',
				'first_seen_at'    => '2026-02-01T08:00:00Z',
				'last_seen'        => '2026-02-05T11:00:00Z',
				'last_seen_at'     => '2026-02-05T11:00:00Z',
			),
		);

		$this->mock_api->expects( $this->once() )
			->method( 'get_threat_detection_detail' )
			->with( 7 )
			->willReturn( array(
				'success' => true,
				'data'    => $detail_data,
			) );

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertEquals( 7, $this->json_response['id'] );
		$this->assertEquals( '192.168.1.100', $this->json_response['ip'] );
		$this->assertEquals( 85, $this->json_response['score'] );
		$this->assertArrayHasKey( 'actor', $this->json_response );
	}

	/**
	 * Test get detection detail requires detection_id.
	 */
	public function test_ajax_get_threat_detection_detail_requires_id() {
		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Detection ID is required', $this->json_response['message'] );
	}

	/**
	 * Test get detection detail with empty detection_id.
	 */
	public function test_ajax_get_threat_detection_detail_rejects_empty_id() {
		$_POST['detection_id'] = '';

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Detection ID is required', $this->json_response['message'] );
	}

	/**
	 * Test get detection detail API error.
	 */
	public function test_ajax_get_threat_detection_detail_api_error() {
		$_POST['detection_id'] = '999';

		$this->mock_api->method( 'get_threat_detection_detail' )
			->willReturn( array(
				'success' => false,
				'error'   => 'Detection not found.',
			) );

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'not found', $this->json_response['message'] );
	}

	/**
	 * Test get detection detail API error fallback message.
	 */
	public function test_ajax_get_threat_detection_detail_api_error_fallback() {
		$_POST['detection_id'] = '999';

		$this->mock_api->method( 'get_threat_detection_detail' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to fetch detection', $this->json_response['message'] );
	}

	/**
	 * Test detection detail response contains fields expected by JS renderDetectionDetail().
	 *
	 * This is a contract test that verifies the response structure matches the field names
	 * used in adaptive-defense.js renderDetectionDetail() after the fix for blank data.
	 *
	 * The JS uses fallback chains like: detection.detected_at || detection.created_at
	 * This test ensures the API returns the expected fields in the response.
	 */
	public function test_detection_detail_response_contract_matches_js_field_names() {
		$_POST['detection_id'] = '7';

		$detail_data = array(
			// Primary fields the JS checks first.
			'detected_at'    => '2026-02-05T11:30:05+00:00',
			'ip'             => '192.168.1.100',
			'score'          => 85,
			'threat_level'   => 'critical',
			'key_indicators' => array( 'High WAF hit rate' ),
			'status'         => 'pending_review',
			'created_at'     => '2026-02-05T11:30:05+00:00',
			'actor'          => array(
				'ip'               => '192.168.1.100',
				'total_waf_hits'   => 150,
				'total_requests'   => 500,
				'total_4xx_errors' => 30,
				'total_5xx_errors' => 5,
				'first_seen'       => '2026-02-01T08:00:00Z',
				'last_seen'        => '2026-02-05T11:00:00Z',
			),
		);

		$this->mock_api->method( 'get_threat_detection_detail' )
			->willReturn( array(
				'success' => true,
				'data'    => $detail_data,
			) );

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );

		// Verify detection-level fields used by renderDetectionDetail().
		$this->assertArrayHasKey( 'detected_at', $this->json_response, 'JS uses: detection.detected_at || detection.created_at' );
		$this->assertArrayHasKey( 'created_at', $this->json_response, 'JS fallback: detection.created_at' );
		$this->assertArrayHasKey( 'score', $this->json_response, 'JS uses: detection.score' );
		$this->assertArrayHasKey( 'threat_level', $this->json_response, 'JS uses: detection.threat_level' );
		$this->assertArrayHasKey( 'status', $this->json_response, 'JS uses: detection.status' );
		$this->assertArrayHasKey( 'key_indicators', $this->json_response, 'JS uses: detection.key_indicators' );

		// Verify actor sub-object fields.
		$actor = $this->json_response['actor'];
		$this->assertArrayHasKey( 'ip', $actor, 'JS uses: actor.ip || actor.ip_address' );
		$this->assertArrayHasKey( 'total_waf_hits', $actor, 'JS uses: actor.total_waf_hits || actor.waf_hits' );
		$this->assertArrayHasKey( 'total_requests', $actor, 'JS uses: actor.total_requests' );
		$this->assertArrayHasKey( 'total_4xx_errors', $actor, 'JS uses: actor.total_4xx_errors || actor.error_4xx' );
		$this->assertArrayHasKey( 'total_5xx_errors', $actor, 'JS uses: actor.total_5xx_errors || actor.error_5xx' );
		$this->assertArrayHasKey( 'first_seen', $actor, 'JS uses: actor.first_seen || actor.first_seen_at' );
		$this->assertArrayHasKey( 'last_seen', $actor, 'JS uses: actor.last_seen || actor.last_seen_at' );
	}

	/**
	 * Test detection detail response with fallback field names still works.
	 *
	 * The API might return only the secondary/fallback field names. The JS uses
	 * fallback chains (e.g., detected_at || created_at), so the AJAX layer just
	 * passes through whatever the API returns.
	 */
	public function test_detection_detail_passes_through_fallback_field_names() {
		$_POST['detection_id'] = '7';

		// Response using only fallback/alternative field names.
		$detail_data = array(
			'created_at'     => '2026-02-05T11:30:05+00:00',
			'ip_address'     => '192.168.1.100',
			'score'          => 85,
			'threat_level'   => 'high',
			'key_indicators' => array(),
			'status'         => 'auto_blocked',
			'actor'          => array(
				'ip_address'    => '192.168.1.100',
				'waf_hits'      => 100,
				'total_requests' => 300,
				'error_4xx'     => 20,
				'error_5xx'     => 2,
				'first_seen_at' => '2026-02-01T08:00:00Z',
				'last_seen_at'  => '2026-02-05T11:00:00Z',
			),
		);

		$this->mock_api->method( 'get_threat_detection_detail' )
			->willReturn( array(
				'success' => true,
				'data'    => $detail_data,
			) );

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );

		// AJAX handler is a passthrough: it sends whatever the API returns.
		$this->assertArrayHasKey( 'created_at', $this->json_response );
		$actor = $this->json_response['actor'];
		$this->assertArrayHasKey( 'ip_address', $actor );
		$this->assertArrayHasKey( 'waf_hits', $actor );
		$this->assertArrayHasKey( 'error_4xx', $actor );
		$this->assertArrayHasKey( 'error_5xx', $actor );
		$this->assertArrayHasKey( 'first_seen_at', $actor );
		$this->assertArrayHasKey( 'last_seen_at', $actor );
	}

	// =========================================================================
	// Get Actor Profiles Tests
	// =========================================================================

	/**
	 * Test get actor profiles success with defaults.
	 */
	public function test_ajax_get_actor_profiles_success() {
		$actors_data = array(
			'actors'     => array(
				array(
					'id'             => 1,
					'ip'             => '192.168.1.50',
					'total_requests' => 100,
					'total_waf_hits' => 10,
					'is_blocked'     => false,
				),
			),
			'pagination' => array(
				'page'        => 1,
				'per_page'    => 25,
				'total'       => 1,
				'total_pages' => 1,
			),
		);

		$this->mock_api->expects( $this->once() )
			->method( 'get_actor_profiles' )
			->with( $this->callback( function ( $args ) {
				return $args['page'] === 1
					&& $args['per_page'] === 25
					&& $args['filter'] === 'all';
			} ) )
			->willReturn( array(
				'success' => true,
				'data'    => $actors_data,
			) );

		try {
			$this->ajax->ajax_get_actor_profiles();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'actors', $this->json_response );
		$this->assertArrayHasKey( 'pagination', $this->json_response );
	}

	/**
	 * Test get actor profiles with custom pagination and filter.
	 */
	public function test_ajax_get_actor_profiles_with_pagination_and_filter() {
		$_POST['page']     = '3';
		$_POST['per_page'] = '10';
		$_POST['filter']   = 'blocked';
		$_POST['search']   = '192.168';

		$this->mock_api->expects( $this->once() )
			->method( 'get_actor_profiles' )
			->with( $this->callback( function ( $args ) {
				return $args['page'] === 3
					&& $args['per_page'] === 10
					&& $args['filter'] === 'blocked'
					&& $args['search'] === '192.168';
			} ) )
			->willReturn( array(
				'success' => true,
				'data'    => array( 'actors' => array(), 'pagination' => array() ),
			) );

		try {
			$this->ajax->ajax_get_actor_profiles();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	/**
	 * Test get actor profiles API error.
	 */
	public function test_ajax_get_actor_profiles_api_error() {
		$this->mock_api->method( 'get_actor_profiles' )
			->willReturn( array(
				'success' => false,
				'error'   => 'Service unavailable.',
			) );

		try {
			$this->ajax->ajax_get_actor_profiles();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Service unavailable', $this->json_response['message'] );
	}

	/**
	 * Test get actor profiles API error fallback message.
	 */
	public function test_ajax_get_actor_profiles_api_error_fallback() {
		$this->mock_api->method( 'get_actor_profiles' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_get_actor_profiles();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to fetch actor profiles', $this->json_response['message'] );
	}

	// =========================================================================
	// Get Threat Detections Tests
	// =========================================================================

	/**
	 * Test get threat detections success with defaults.
	 */
	public function test_ajax_get_threat_detections_success() {
		$detections_data = array(
			'detections' => array(
				array(
					'id'           => 7,
					'ip'           => '10.0.0.1',
					'score'        => 92,
					'threat_level' => 'critical',
					'status'       => 'pending_review',
				),
			),
			'pagination' => array(
				'page'        => 1,
				'per_page'    => 25,
				'total'       => 1,
				'total_pages' => 1,
			),
		);

		$this->mock_api->expects( $this->once() )
			->method( 'get_threat_detections' )
			->with( $this->callback( function ( $args ) {
				return $args['page'] === 1
					&& $args['per_page'] === 25
					&& $args['status'] === 'all';
			} ) )
			->willReturn( array(
				'success' => true,
				'data'    => $detections_data,
			) );

		try {
			$this->ajax->ajax_get_threat_detections();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'detections', $this->json_response );
		$this->assertArrayHasKey( 'pagination', $this->json_response );
	}

	/**
	 * Test get threat detections with status filter.
	 */
	public function test_ajax_get_threat_detections_with_status_filter() {
		$_POST['status'] = 'pending_review';
		$_POST['page']   = '2';

		$this->mock_api->expects( $this->once() )
			->method( 'get_threat_detections' )
			->with( $this->callback( function ( $args ) {
				return $args['status'] === 'pending_review'
					&& $args['page'] === 2;
			} ) )
			->willReturn( array(
				'success' => true,
				'data'    => array( 'detections' => array(), 'pagination' => array() ),
			) );

		try {
			$this->ajax->ajax_get_threat_detections();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	/**
	 * Test get threat detections API error.
	 */
	public function test_ajax_get_threat_detections_api_error() {
		$this->mock_api->method( 'get_threat_detections' )
			->willReturn( array(
				'success' => false,
				'error'   => 'Unauthorized.',
			) );

		try {
			$this->ajax->ajax_get_threat_detections();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Unauthorized', $this->json_response['message'] );
	}

	/**
	 * Test get threat detections API error fallback message.
	 */
	public function test_ajax_get_threat_detections_api_error_fallback() {
		$this->mock_api->method( 'get_threat_detections' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_get_threat_detections();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to fetch threat detections', $this->json_response['message'] );
	}

	// =========================================================================
	// Get Adaptive Defense Overview Tests
	// =========================================================================

	/**
	 * Test get adaptive defense overview success.
	 */
	public function test_ajax_get_adaptive_defense_success() {
		$ad_data = array(
			'enabled'     => true,
			'mode'        => 'auto_enforce',
			'sensitivity' => 'medium',
			'stats'       => array(
				'total_actors'     => 30,
				'blocked_actors'   => 5,
				'total_detections' => 25,
				'ai_budget_used'   => 40,
				'ai_budget_total'  => 200,
			),
		);

		$this->mock_api->expects( $this->once() )
			->method( 'get_adaptive_defense' )
			->willReturn( array(
				'success' => true,
				'data'    => $ad_data,
			) );

		try {
			$this->ajax->ajax_get_adaptive_defense();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertEquals( true, $this->json_response['enabled'] );
		$this->assertEquals( 'auto_enforce', $this->json_response['mode'] );
		$this->assertArrayHasKey( 'stats', $this->json_response );
	}

	/**
	 * Test get adaptive defense API error.
	 */
	public function test_ajax_get_adaptive_defense_api_error() {
		$this->mock_api->method( 'get_adaptive_defense' )
			->willReturn( array(
				'success' => false,
				'error'   => 'Feature not enabled for this site.',
			) );

		try {
			$this->ajax->ajax_get_adaptive_defense();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'not enabled', $this->json_response['message'] );
	}

	/**
	 * Test get adaptive defense API error fallback message.
	 */
	public function test_ajax_get_adaptive_defense_api_error_fallback() {
		$this->mock_api->method( 'get_adaptive_defense' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_get_adaptive_defense();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to fetch Adaptive Defense', $this->json_response['message'] );
	}

	// =========================================================================
	// Security Validation Tests (AD-specific)
	// =========================================================================

	/**
	 * Test block IP handler rejects invalid nonce.
	 */
	public function test_ajax_block_ip_rejects_invalid_nonce() {
		Functions\when( 'wp_verify_nonce' )->justReturn( false );
		$_POST['ip'] = '10.0.0.1';

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Security check failed', $this->json_response['message'] );
	}

	/**
	 * Test unblock IP handler rejects unauthorized user.
	 */
	public function test_ajax_unblock_ip_rejects_unauthorized_user() {
		Functions\when( 'current_user_can' )->justReturn( false );
		$_POST['ip'] = '10.0.0.1';

		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'permission', $this->json_response['message'] );
	}

	/**
	 * Test dismiss detection rejects invalid nonce.
	 */
	public function test_ajax_dismiss_detection_rejects_invalid_nonce() {
		Functions\when( 'wp_verify_nonce' )->justReturn( false );
		$_POST['detection_id'] = '7';

		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Security check failed', $this->json_response['message'] );
	}

	/**
	 * Test delete actor rejects unauthorized user.
	 */
	public function test_ajax_delete_actor_rejects_unauthorized_user() {
		Functions\when( 'current_user_can' )->justReturn( false );
		$_POST['actor_id'] = '42';

		try {
			$this->ajax->ajax_delete_actor();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'permission', $this->json_response['message'] );
	}

	// =========================================================================
	// Extend Block Tests
	// =========================================================================

	/**
	 * Test extend block success.
	 */
	public function test_ajax_extend_block_success() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->expects( $this->once() )
			->method( 'extend_block' )
			->with( '192.168.1.100' )
			->willReturn( array(
				'success' => true,
				'data'    => array(
					'block_expires_at' => '2026-03-05T12:00:00Z',
				),
			) );

		try {
			$this->ajax->ajax_extend_block();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'message', $this->json_response );
		$this->assertStringContainsString( '192.168.1.100', $this->json_response['message'] );
		$this->assertStringContainsString( 'extended', $this->json_response['message'] );
		$this->assertArrayHasKey( 'data', $this->json_response );
	}

	/**
	 * Test extend block requires IP address.
	 */
	public function test_ajax_extend_block_requires_ip() {
		// No IP in POST.

		try {
			$this->ajax->ajax_extend_block();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'IP address is required', $this->json_response['message'] );
	}

	/**
	 * Test extend block requires non-empty IP address.
	 */
	public function test_ajax_extend_block_requires_nonempty_ip() {
		$_POST['ip'] = '';

		try {
			$this->ajax->ajax_extend_block();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'IP address is required', $this->json_response['message'] );
	}

	/**
	 * Test extend block API error is propagated (e.g. max_duration_exceeded).
	 */
	public function test_ajax_extend_block_api_error_max_duration() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->method( 'extend_block' )
			->willReturn( array(
				'success' => false,
				'error'   => 'Block already reaches the maximum duration of 3 days.',
			) );

		try {
			$this->ajax->ajax_extend_block();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'maximum duration', $this->json_response['message'] );
	}

	/**
	 * Test extend block API error falls back to generic message.
	 */
	public function test_ajax_extend_block_api_error_fallback_message() {
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->method( 'extend_block' )
			->willReturn( array( 'success' => false ) );

		try {
			$this->ajax->ajax_extend_block();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Failed to extend block', $this->json_response['message'] );
	}

	/**
	 * Test extend block does not send duration params — server decides.
	 */
	public function test_ajax_extend_block_does_not_send_duration() {
		$_POST['ip']             = '10.0.0.1';
		$_POST['duration_hours'] = '720';
		$_POST['days']           = '30';

		// extend_block() is called with only $ip — no duration args.
		$this->mock_api->expects( $this->once() )
			->method( 'extend_block' )
			->with( '10.0.0.1' )
			->willReturn( array(
				'success' => true,
				'data'    => array(),
			) );

		try {
			$this->ajax->ajax_extend_block();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
	}

	// =========================================================================
	// Make Permanent Tests
	// =========================================================================

	/**
	 * Test make permanent success.
	 */
	public function test_ajax_make_permanent_success() {
		$_POST['ip'] = '10.0.0.1';

		$this->mock_api->expects( $this->once() )
			->method( 'make_permanent' )
			->with( '10.0.0.1' )
			->willReturn( array(
				'success' => true,
				'data'    => array( 'ip' => '10.0.0.1', 'is_permanent' => true ),
			) );

		try {
			$this->ajax->ajax_make_permanent();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringContainsString( '10.0.0.1', $this->json_response['message'] );
		$this->assertStringContainsString( 'permanent', $this->json_response['message'] );
	}

	/**
	 * Test make permanent rejects empty IP.
	 */
	public function test_ajax_make_permanent_rejects_empty_ip() {
		$_POST['ip'] = '';

		try {
			$this->ajax->ajax_make_permanent();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'IP', $this->json_response['message'] );
	}

	/**
	 * Test make permanent passes through error_code from API for plan_limit.
	 *
	 * When the API returns a 403 with error='plan_limit' and a message,
	 * the AJAX handler must include error_code='plan_limit' in the JSON
	 * response so JS can show specific upgrade messaging.
	 */
	public function test_ajax_make_permanent_passes_plan_limit_error_code() {
		$_POST['ip'] = '10.0.0.1';

		$this->mock_api->expects( $this->once() )
			->method( 'make_permanent' )
			->with( '10.0.0.1' )
			->willReturn( array(
				'success'    => false,
				'error'      => 'Permanent blocks require a Pro plan or above.',
				'error_code' => 'plan_limit',
				'code'       => 403,
			) );

		try {
			$this->ajax->ajax_make_permanent();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertArrayHasKey( 'error_code', $this->json_response );
		$this->assertEquals( 'plan_limit', $this->json_response['error_code'] );
		$this->assertStringContainsString( 'Pro plan', $this->json_response['message'] );
	}

	/**
	 * Test make permanent API failure without error_code omits it.
	 */
	public function test_ajax_make_permanent_api_error_without_error_code() {
		$_POST['ip'] = '10.0.0.1';

		$this->mock_api->expects( $this->once() )
			->method( 'make_permanent' )
			->with( '10.0.0.1' )
			->willReturn( array(
				'success' => false,
				'error'   => 'Something went wrong.',
			) );

		try {
			$this->ajax->ajax_make_permanent();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertArrayNotHasKey( 'error_code', $this->json_response );
		$this->assertEquals( 'Something went wrong.', $this->json_response['message'] );
	}

	// =========================================================================
	// Nonce Refresh Tests
	// =========================================================================

	/**
	 * Test nonce failure response includes nonce_error flag.
	 *
	 * When the nonce check fails, the response must include nonce_error: true
	 * so the JS client can distinguish expired nonces from other errors and
	 * auto-retry with a fresh nonce.
	 *
	 * Incident 2026-03-09: "Security check failed" with no recovery mechanism
	 * when nonce expired between WAF log load and Block IP click.
	 */
	public function test_nonce_failure_includes_nonce_error_flag() {
		// Override the default mock to make nonce verification fail.
		Functions\when( 'wp_verify_nonce' )->justReturn( false );

		$_POST['nonce'] = 'expired-nonce';
		$_POST['ip']    = '192.168.1.100';

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertArrayHasKey( 'nonce_error', $this->json_response );
		$this->assertTrue( $this->json_response['nonce_error'] );
		$this->assertStringContainsString( 'Security check failed', $this->json_response['message'] );
	}

	/**
	 * Test nonce failure for missing nonce also includes nonce_error flag.
	 */
	public function test_missing_nonce_includes_nonce_error_flag() {
		unset( $_POST['nonce'] );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertArrayHasKey( 'nonce_error', $this->json_response );
		$this->assertTrue( $this->json_response['nonce_error'] );
	}

	/**
	 * Test nonce refresh returns a fresh nonce for authorized users.
	 */
	public function test_ajax_refresh_nonce_success() {
		Functions\when( 'current_user_can' )->justReturn( true );
		Functions\when( 'wp_create_nonce' )->justReturn( 'fresh-nonce-token' );

		try {
			$this->ajax->ajax_refresh_nonce();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'nonce', $this->json_response );
		$this->assertEquals( 'fresh-nonce-token', $this->json_response['nonce'] );
	}

	/**
	 * Test nonce refresh rejects unauthorized users.
	 */
	public function test_ajax_refresh_nonce_unauthorized() {
		Functions\when( 'current_user_can' )->justReturn( false );

		try {
			$this->ajax->ajax_refresh_nonce();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'Unauthorized', $this->json_response['message'] );
	}

	/**
	 * Test nonce refresh action is registered in init_hooks.
	 */
	public function test_nonce_refresh_action_is_registered() {
		$source = file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-atomicedge-ajax.php' );

		$this->assertStringContainsString(
			'wp_ajax_atomicedge_refresh_nonce',
			$source,
			'The wp_ajax_atomicedge_refresh_nonce action must be registered in init_hooks()'
		);

		$this->assertStringContainsString(
			'ajax_refresh_nonce',
			$source,
			'The ajax_refresh_nonce method must exist in AtomicEdge_Ajax'
		);
	}

	/**
	 * Test capability check failure does NOT include nonce_error flag.
	 *
	 * Only nonce failures should trigger the auto-retry mechanism.
	 * Capability failures are a different class of error.
	 */
	public function test_capability_failure_does_not_include_nonce_error_flag() {
		// Nonce passes, but capability check fails.
		Functions\when( 'wp_verify_nonce' )->justReturn( true );
		Functions\when( 'current_user_can' )->justReturn( false );

		$_POST['nonce'] = 'valid-nonce';
		$_POST['ip']    = '192.168.1.100';

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertArrayNotHasKey( 'nonce_error', $this->json_response );
		$this->assertStringContainsString( 'permission', $this->json_response['message'] );
	}
}
