<?php
/**
 * Dev Mode Adaptive Defense Tests
 *
 * Verifies that the Adaptive Defense features work correctly in Development Mode,
 * including:
 * - Simulation methods return correct data structures
 * - AJAX handlers intercept and return simulated data in dev mode
 * - Detection detail data matches the JS field expectations
 * - Filtering and pagination work on simulated data
 * - Toggle/duplicate detail row prevention (template structural test)
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use AtomicEdge\Tests\AjaxExitException;
use Brain\Monkey\Functions;

/**
 * Dev Mode Adaptive Defense Test Suite
 */
class DevModeAdaptiveDefenseTest extends TestCase {

	/**
	 * AJAX handler instance.
	 *
	 * @var \AtomicEdge_Ajax
	 */
	private $ajax;

	/**
	 * Mock API instance (should NOT be called in dev mode).
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

		$_POST    = array();
		$_GET     = array();
		$_REQUEST = array();
		$_POST['nonce'] = 'valid-nonce';

		$this->json_response      = null;
		$this->json_response_type = null;

		$this->mock_api = $this->createMock( \AtomicEdge_API::class );

		Functions\when( 'wp_send_json_success' )->alias(
			function ( $data = null ) {
				$this->json_response      = $data;
				$this->json_response_type = 'success';
				throw new AjaxExitException( 'success' );
			}
		);

		Functions\when( 'wp_send_json_error' )->alias(
			function ( $data = null ) {
				$this->json_response      = $data;
				$this->json_response_type = 'error';
				throw new AjaxExitException( 'error' );
			}
		);

		Functions\when( 'sanitize_key' )->alias(
			function ( $key ) {
				return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $key ) );
			}
		);

		Functions\when( 'wp_verify_nonce' )->justReturn( true );
		Functions\when( 'current_user_can' )->justReturn( true );

		$this->ajax = new \AtomicEdge_Ajax( $this->mock_api );
	}

	/**
	 * Enable dev mode by mocking AtomicEdge_Dev_Mode::is_enabled().
	 *
	 * Uses ATOMICEDGE_DEV_MODE constant + local environment.
	 *
	 * @return void
	 */
	private function enable_dev_mode() {
		Functions\when( 'get_site_url' )->justReturn( 'http://shift8.local' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		// Force the dev mode constant.
		if ( ! defined( 'ATOMICEDGE_DEV_MODE' ) ) {
			define( 'ATOMICEDGE_DEV_MODE', true );
		}
	}

	// =========================================================================
	// Simulation Method Tests — Data Structure Validation
	// =========================================================================

	/**
	 * Test that get_simulated_adaptive_defense returns a complete overview.
	 */
	public function test_simulated_adaptive_defense_returns_overview_data() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_adaptive_defense();

		$this->assertIsArray( $data );
		$this->assertArrayHasKey( 'stats', $data );
		$this->assertArrayHasKey( 'settings', $data );
		$this->assertArrayHasKey( 'high_risk_actors', $data );

		// Stats structure.
		$stats = $data['stats'];
		$this->assertArrayHasKey( 'total_actors', $stats );
		$this->assertArrayHasKey( 'blocked_ips', $stats );
		$this->assertArrayHasKey( 'pending_detections', $stats );
		$this->assertArrayHasKey( 'high_threat_count', $stats );
		$this->assertIsInt( $stats['total_actors'] );
		$this->assertIsInt( $stats['blocked_ips'] );
		$this->assertIsInt( $stats['pending_detections'] );
		$this->assertIsInt( $stats['high_threat_count'] );

		// Settings structure.
		$settings = $data['settings'];
		$this->assertArrayHasKey( 'enabled', $settings );
		$this->assertArrayHasKey( 'mode', $settings );
		$this->assertTrue( $settings['enabled'] );
		$this->assertContains( $settings['mode'], array( 'monitor', 'auto_enforce' ) );

		// High risk actors must be a non-empty array.
		$this->assertIsArray( $data['high_risk_actors'] );
		$this->assertNotEmpty( $data['high_risk_actors'] );
	}

	/**
	 * Test that simulated actor profiles have required fields for JS rendering.
	 */
	public function test_simulated_actor_profiles_have_required_fields() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_actor_profiles();

		$this->assertArrayHasKey( 'actors', $data );
		$this->assertArrayHasKey( 'pagination', $data );
		$this->assertNotEmpty( $data['actors'] );

		$required_fields = array(
			'id', 'ip', 'ip_address', 'country_code', 'country_flag_emoji', 'total_requests',
			'total_waf_hits', 'total_waf_events', 'first_seen', 'first_seen_at',
			'last_seen', 'last_seen_at',
		);

		foreach ( $data['actors'] as $actor ) {
			foreach ( $required_fields as $field ) {
				$this->assertArrayHasKey( $field, $actor, "Actor missing required field: $field" );
			}
			// Both field name variants must have the same value.
			$this->assertEquals( $actor['ip'], $actor['ip_address'] );
			$this->assertEquals( $actor['total_waf_hits'], $actor['total_waf_events'] );
			$this->assertEquals( $actor['first_seen'], $actor['first_seen_at'] );
			$this->assertEquals( $actor['last_seen'], $actor['last_seen_at'] );
		}
	}

	/**
	 * Test that simulated threat detections have required fields for JS rendering.
	 */
	public function test_simulated_threat_detections_have_required_fields() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_threat_detections();

		$this->assertArrayHasKey( 'detections', $data );
		$this->assertArrayHasKey( 'pagination', $data );
		$this->assertNotEmpty( $data['detections'] );

		$required_detection_fields = array(
			'id', 'score', 'confidence', 'threat_level', 'status',
			'ip_address', 'country_code', 'country_flag_emoji',
			'created_at', 'detected_at', 'reasons',
			'key_indicators', 'actor',
		);

		foreach ( $data['detections'] as $detection ) {
			foreach ( $required_detection_fields as $field ) {
				$this->assertArrayHasKey( $field, $detection, "Detection missing required field: $field" );
			}

			// Actor must also have required fields.
			$actor = $detection['actor'];
			$this->assertArrayHasKey( 'ip', $actor );
			$this->assertArrayHasKey( 'ip_address', $actor );
			$this->assertArrayHasKey( 'country_code', $actor );
			$this->assertArrayHasKey( 'country_flag_emoji', $actor );
			$this->assertArrayHasKey( 'total_requests', $actor );
			$this->assertArrayHasKey( 'total_waf_hits', $actor );
			$this->assertArrayHasKey( 'first_seen', $actor );
			$this->assertArrayHasKey( 'last_seen', $actor );
		}
	}

	/**
	 * Test detection detail returns the expected nested structure for JS.
	 *
	 * The JS expects: { detection: {..., actor: {...}}, actor: {...} }
	 */
	public function test_simulated_detection_detail_has_correct_structure() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_threat_detection_detail( 2001 );

		$this->assertIsArray( $data );
		$this->assertArrayHasKey( 'detection', $data );
		$this->assertArrayHasKey( 'actor', $data );

		// Detection.
		$detection = $data['detection'];
		$this->assertEquals( 2001, $detection['id'] );
		$this->assertArrayHasKey( 'score', $detection );
		$this->assertArrayHasKey( 'confidence', $detection );
		$this->assertArrayHasKey( 'status', $detection );
		$this->assertArrayHasKey( 'detected_at', $detection );
		$this->assertArrayHasKey( 'reasons', $detection );

		// Actor (both top-level and nested inside detection).
		$this->assertArrayHasKey( 'actor', $detection );
		$this->assertIsArray( $data['actor'] );
		$this->assertArrayHasKey( 'ip', $data['actor'] );
		$this->assertArrayHasKey( 'total_requests', $data['actor'] );
	}

	/**
	 * Test detection detail fallback for unknown detection ID.
	 */
	public function test_simulated_detection_detail_fallback_for_unknown_id() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_threat_detection_detail( 99999 );

		// Should fall back to first detection, not return null.
		$this->assertIsArray( $data );
		$this->assertArrayHasKey( 'detection', $data );
		$this->assertArrayHasKey( 'actor', $data );
	}

	/**
	 * Test that all 5 simulated detection IDs return distinct data.
	 */
	public function test_simulated_detection_detail_returns_correct_detection_by_id() {
		$this->enable_dev_mode();

		$ids = array( 2001, 2002, 2003, 2004, 2005 );
		foreach ( $ids as $id ) {
			$data = \AtomicEdge_Dev_Mode::get_simulated_threat_detection_detail( $id );
			$this->assertNotNull( $data, "Detection detail should exist for ID $id" );
			$this->assertEquals( $id, $data['detection']['id'], "Detection ID mismatch for $id" );
		}
	}

	/**
	 * Test simulated detections include varied statuses.
	 */
	public function test_simulated_detections_have_varied_statuses() {
		$this->enable_dev_mode();
		$data     = \AtomicEdge_Dev_Mode::get_simulated_threat_detections();
		$statuses = array_column( $data['detections'], 'status' );

		$this->assertContains( 'auto_blocked', $statuses );
		$this->assertContains( 'pending_review', $statuses );
		$this->assertContains( 'dismissed', $statuses );
	}

	/**
	 * Test that detection detail includes AI analysis for at least one detection.
	 */
	public function test_at_least_one_detection_has_ai_analysis() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_threat_detections();

		$has_ai = false;
		foreach ( $data['detections'] as $detection ) {
			if ( ! empty( $detection['ai_analysis'] ) ) {
				$has_ai = true;
				break;
			}
		}

		$this->assertTrue( $has_ai, 'At least one simulated detection should have ai_analysis' );
	}

	// =========================================================================
	// Filtering and Pagination Tests
	// =========================================================================

	/**
	 * Test detection status filtering.
	 */
	public function test_simulated_detections_filter_by_status() {
		$this->enable_dev_mode();

		$data = \AtomicEdge_Dev_Mode::get_simulated_threat_detections( array( 'status' => 'pending_review' ) );
		$this->assertNotEmpty( $data['detections'] );
		foreach ( $data['detections'] as $d ) {
			$this->assertEquals( 'pending_review', $d['status'] );
		}
	}

	/**
	 * Test detection 'all' filter returns all detections.
	 */
	public function test_simulated_detections_all_filter_returns_all() {
		$this->enable_dev_mode();

		$all      = \AtomicEdge_Dev_Mode::get_simulated_threat_detections( array( 'status' => 'all' ) );
		$no_filter = \AtomicEdge_Dev_Mode::get_simulated_threat_detections();

		$this->assertEquals( count( $all['detections'] ), count( $no_filter['detections'] ) );
	}

	/**
	 * Test that pagination metadata is consistent.
	 */
	public function test_simulated_detections_pagination_structure() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_threat_detections( array( 'per_page' => 2, 'page' => 1 ) );

		$this->assertCount( 2, $data['detections'] );
		$this->assertEquals( 1, $data['pagination']['current_page'] );
		$this->assertEquals( 2, $data['pagination']['per_page'] );
		$this->assertGreaterThanOrEqual( 3, $data['pagination']['total_pages'] );
	}

	/**
	 * Test actor profiles pagination.
	 */
	public function test_simulated_actor_profiles_pagination() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_actor_profiles( array( 'per_page' => 2, 'page' => 1 ) );

		$this->assertCount( 2, $data['actors'] );
		$this->assertEquals( 1, $data['pagination']['current_page'] );
	}

	/**
	 * Test actor profiles search filter.
	 */
	public function test_simulated_actor_profiles_search_filter() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_actor_profiles( array( 'search' => '45.33.32' ) );

		$this->assertNotEmpty( $data['actors'] );
		foreach ( $data['actors'] as $actor ) {
			$this->assertStringContainsString( '45.33.32', $actor['ip'] );
		}
	}

	/**
	 * Test actor profiles blocked filter.
	 */
	public function test_simulated_actor_profiles_blocked_filter() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::get_simulated_actor_profiles( array( 'filter' => 'blocked' ) );

		foreach ( $data['actors'] as $actor ) {
			$this->assertTrue( $actor['is_blocked'], 'Blocked filter should only return blocked actors' );
		}
	}

	/**
	 * Test simulate_block_ip returns correct structure.
	 */
	public function test_simulate_block_ip_returns_block_data() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::simulate_block_ip( '10.0.0.1' );

		$this->assertArrayHasKey( 'ip', $data );
		$this->assertEquals( '10.0.0.1', $data['ip'] );
		$this->assertTrue( $data['is_blocked'] );
		$this->assertArrayHasKey( 'blocked_at', $data );
		$this->assertArrayHasKey( 'block_expires_at', $data );
	}

	/**
	 * Test simulate_extend_block returns correct structure.
	 */
	public function test_simulate_extend_block_returns_block_data() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::simulate_extend_block( '10.0.0.1' );

		$this->assertArrayHasKey( 'ip', $data );
		$this->assertEquals( '10.0.0.1', $data['ip'] );
		$this->assertTrue( $data['is_blocked'] );
		$this->assertArrayHasKey( 'block_expires_at', $data );
	}

	/**
	 * Test simulate_dismiss_detection returns correct structure.
	 */
	public function test_simulate_dismiss_detection_returns_success_data() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::simulate_dismiss_detection( 2001 );

		$this->assertArrayHasKey( 'id', $data );
		$this->assertEquals( 2001, $data['id'] );
		$this->assertEquals( 'dismissed', $data['status'] );
	}

	/**
	 * Test simulate_delete_actor returns correct structure.
	 */
	public function test_simulate_delete_actor_returns_success_data() {
		$this->enable_dev_mode();
		$data = \AtomicEdge_Dev_Mode::simulate_delete_actor( 1001 );

		$this->assertArrayHasKey( 'id', $data );
		$this->assertEquals( 1001, $data['id'] );
	}

	// =========================================================================
	// AJAX Handler Dev Mode Interception Tests
	// =========================================================================

	/**
	 * Test that AJAX get_adaptive_defense returns simulated data in dev mode.
	 */
	public function test_ajax_get_adaptive_defense_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();

		// API should NOT be called in dev mode.
		$this->mock_api->expects( $this->never() )->method( 'get_adaptive_defense' );

		try {
			$this->ajax->ajax_get_adaptive_defense();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'stats', $this->json_response );
		$this->assertArrayHasKey( 'settings', $this->json_response );
		$this->assertArrayHasKey( 'high_risk_actors', $this->json_response );
	}

	/**
	 * Test that AJAX get_actor_profiles returns simulated data in dev mode.
	 */
	public function test_ajax_get_actor_profiles_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['page']     = '1';
		$_POST['per_page'] = '25';
		$_POST['filter']   = 'all';

		$this->mock_api->expects( $this->never() )->method( 'get_actor_profiles' );

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
	 * Test that AJAX get_threat_detections returns simulated data in dev mode.
	 */
	public function test_ajax_get_threat_detections_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['page']     = '1';
		$_POST['per_page'] = '25';
		$_POST['status']   = 'all';

		$this->mock_api->expects( $this->never() )->method( 'get_threat_detections' );

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
	 * Test that AJAX get_threat_detection_detail returns simulated data in dev mode.
	 */
	public function test_ajax_get_threat_detection_detail_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['detection_id'] = '2001';

		$this->mock_api->expects( $this->never() )->method( 'get_threat_detection_detail' );

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'detection', $this->json_response );
		$this->assertArrayHasKey( 'actor', $this->json_response );
	}

	/**
	 * Test detection detail in dev mode has populated score, confidence, status.
	 *
	 * This is the core regression test for the "all dashes" bug.
	 */
	public function test_ajax_detection_detail_dev_mode_has_populated_fields() {
		$this->enable_dev_mode();
		$_POST['detection_id'] = '2001';

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );

		$detection = $this->json_response['detection'];
		$actor     = $this->json_response['actor'];

		// Detection fields that were showing "—" in the bug.
		$this->assertNotEmpty( $detection['score'] );
		$this->assertNotEmpty( $detection['confidence'] );
		$this->assertNotEmpty( $detection['status'] );
		$this->assertNotEmpty( $detection['detected_at'] );

		// Actor fields that were showing "—" in the bug.
		$this->assertNotEmpty( $actor['ip'] );
		$this->assertNotEmpty( $actor['ip_address'] );
		$this->assertGreaterThan( 0, $actor['total_requests'] );
		$this->assertNotEmpty( $actor['first_seen'] );
		$this->assertNotEmpty( $actor['last_seen'] );
	}

	/**
	 * Test that AJAX block_ip returns simulated success in dev mode.
	 */
	public function test_ajax_block_ip_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->expects( $this->never() )->method( 'block_ip' );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'message', $this->json_response );
		$this->assertStringContainsString( 'Dev Mode', $this->json_response['message'] );
	}

	/**
	 * Test that AJAX unblock_ip returns simulated success in dev mode.
	 */
	public function test_ajax_unblock_ip_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->expects( $this->never() )->method( 'unblock_ip' );

		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringContainsString( 'Dev Mode', $this->json_response['message'] );
	}

	/**
	 * Test that AJAX extend_block returns simulated success in dev mode.
	 */
	public function test_ajax_extend_block_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['ip'] = '192.168.1.100';

		$this->mock_api->expects( $this->never() )->method( 'extend_block' );

		try {
			$this->ajax->ajax_extend_block();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'message', $this->json_response );
		$this->assertStringContainsString( 'Dev Mode', $this->json_response['message'] );
		$this->assertStringContainsString( '192.168.1.100', $this->json_response['message'] );
		$this->assertArrayHasKey( 'data', $this->json_response );
	}

	/**
	 * Test that AJAX dismiss_detection returns simulated success in dev mode.
	 */
	public function test_ajax_dismiss_detection_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['detection_id'] = '2001';

		$this->mock_api->expects( $this->never() )->method( 'dismiss_threat_detection' );

		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringContainsString( 'Dev Mode', $this->json_response['message'] );
	}

	/**
	 * Test that AJAX delete_actor returns simulated success in dev mode.
	 */
	public function test_ajax_delete_actor_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['actor_id'] = '1001';

		$this->mock_api->expects( $this->never() )->method( 'delete_actor_profile' );

		try {
			$this->ajax->ajax_delete_actor();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringContainsString( 'Dev Mode', $this->json_response['message'] );
	}

	// =========================================================================
	// Dev Mode Bypassed When API Key Is Configured (Bug Fix 2026-03-04)
	// =========================================================================

	/**
	 * Test that dev mode simulation is BYPASSED when an API key is configured.
	 *
	 * This is the regression test for the bug where dev mode intercepted all AD
	 * AJAX handlers on .local domains even when the user had a working API key.
	 * The original check used `is_connected()` (checks `atomicedge_connected`
	 * option) which is only set during the connect() flow — not when an API key
	 * is configured manually. Result: blocking an IP returned simulated success
	 * but never actually called the API.
	 *
	 * Fix: should_use_dev_mode() checks for API key instead of the
	 * `atomicedge_connected` option (which may not be set even with a
	 * working API key on .local domains).
	 */
	public function test_ajax_block_ip_calls_real_api_when_connected_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['ip'] = '192.168.1.100';

		// Simulate configured API key — dev mode should be bypassed.
		$this->mock_api->method( 'get_api_key' )->willReturn( 'abc123def456' );

		// The real API block_ip SHOULD be called.
		$this->mock_api->expects( $this->once() )
			->method( 'block_ip' )
			->with( '192.168.1.100', $this->anything(), $this->anything() )
			->willReturn( array(
				'success' => true,
				'data'    => array( 'message' => 'IP blocked successfully' ),
			) );

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		// Should NOT contain "Dev Mode" — real API was called.
		$this->assertStringNotContainsString( 'Dev Mode', $this->json_response['message'] ?? '' );
	}

	/**
	 * Test that get_adaptive_defense calls real API when connected in dev mode.
	 */
	public function test_ajax_get_adaptive_defense_calls_real_api_when_connected() {
		$this->enable_dev_mode();

		$this->mock_api->method( 'get_api_key' )->willReturn( 'abc123def456' );

		$this->mock_api->expects( $this->once() )
			->method( 'get_adaptive_defense' )
			->willReturn( array(
				'success' => true,
				'data'    => array(
					'stats'           => array( 'total_actors' => 5 ),
					'settings'        => array( 'mode' => 'monitor' ),
					'high_risk_actors' => array(),
				),
			) );

		try {
			$this->ajax->ajax_get_adaptive_defense();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertEquals( 5, $this->json_response['stats']['total_actors'] );
	}

	/**
	 * Test that get_actor_profiles calls real API when connected in dev mode.
	 */
	public function test_ajax_get_actor_profiles_calls_real_api_when_connected() {
		$this->enable_dev_mode();
		$_POST['page']     = '1';
		$_POST['per_page'] = '25';
		$_POST['filter']   = 'all';

		$this->mock_api->method( 'get_api_key' )->willReturn( 'abc123def456' );

		$this->mock_api->expects( $this->once() )
			->method( 'get_actor_profiles' )
			->willReturn( array(
				'success' => true,
				'data'    => array(
					'actors'     => array( array( 'ip' => '1.2.3.4', 'total_requests' => 100 ) ),
					'pagination' => array( 'total' => 1 ),
				),
			) );

		try {
			$this->ajax->ajax_get_actor_profiles();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertEquals( '1.2.3.4', $this->json_response['actors'][0]['ip'] );
	}

	/**
	 * Test that unblock_ip calls real API when connected in dev mode.
	 */
	public function test_ajax_unblock_ip_calls_real_api_when_connected() {
		$this->enable_dev_mode();
		$_POST['ip'] = '10.0.0.1';

		$this->mock_api->method( 'get_api_key' )->willReturn( 'abc123def456' );

		$this->mock_api->expects( $this->once() )
			->method( 'unblock_ip' )
			->with( '10.0.0.1' )
			->willReturn( array(
				'success' => true,
				'data'    => array( 'message' => 'IP unblocked' ),
			) );

		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringNotContainsString( 'Dev Mode', $this->json_response['message'] ?? '' );
	}

	/**
	 * Test that dismiss_detection calls real API when connected in dev mode.
	 */
	public function test_ajax_dismiss_detection_calls_real_api_when_connected() {
		$this->enable_dev_mode();
		$_POST['detection_id'] = '2001';

		$this->mock_api->method( 'get_api_key' )->willReturn( 'abc123def456' );

		$this->mock_api->expects( $this->once() )
			->method( 'dismiss_threat_detection' )
			->with( 2001 )
			->willReturn( array(
				'success' => true,
				'data'    => array( 'message' => 'Detection dismissed' ),
			) );

		try {
			$this->ajax->ajax_dismiss_detection();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertStringNotContainsString( 'Dev Mode', $this->json_response['message'] ?? '' );
	}

	// =========================================================================
	// AJAX Handler Validation Still Works in Dev Mode
	// =========================================================================

	/**
	 * Test that AJAX detection_detail still validates detection_id even in dev mode.
	 */
	public function test_ajax_detection_detail_validates_id_in_dev_mode() {
		$this->enable_dev_mode();
		// Omit detection_id.

		try {
			$this->ajax->ajax_get_threat_detection_detail();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'required', strtolower( $this->json_response['message'] ) );
	}

	/**
	 * Test that AJAX block_ip still validates IP even in dev mode.
	 */
	public function test_ajax_block_ip_validates_ip_in_dev_mode() {
		$this->enable_dev_mode();
		// Omit IP.

		try {
			$this->ajax->ajax_block_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
		$this->assertStringContainsString( 'required', strtolower( $this->json_response['message'] ) );
	}

	/**
	 * Test that AJAX unblock_ip still validates IP even in dev mode.
	 */
	public function test_ajax_unblock_ip_validates_ip_in_dev_mode() {
		$this->enable_dev_mode();
		// Omit IP.

		try {
			$this->ajax->ajax_unblock_ip();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'error', $this->json_response_type );
	}

	// =========================================================================
	// Template Structural Tests
	// =========================================================================

	/**
	 * Test that the detection detail template uses <template> element, not <div>.
	 *
	 * This is a guard test: <tr> inside <div> is invalid HTML and causes the browser
	 * to strip the outer <tr>, breaking the toggle mechanism (duplicate rows on click).
	 */
	public function test_detection_detail_template_uses_html5_template_element() {
		$file = ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/adaptive-defense-detections-tab.php';
		$this->assertFileExists( $file );

		$content = file_get_contents( $file );

		// Must use <template>, NOT <div> for the detail template.
		$this->assertStringContainsString(
			'<template id="atomicedge-ad-detection-detail-template">',
			$content,
			'Detection detail template MUST use <template> element. '
			. 'Using <div> causes browsers to strip <tr>/<td> elements, '
			. 'breaking the toggle and causing duplicate detail rows on each click.'
		);

		// Must NOT use <div> for the template.
		$this->assertStringNotContainsString(
			'<div id="atomicedge-ad-detection-detail-template"',
			$content,
			'Detection detail template must NOT use <div> wrapper.'
		);
	}

	/**
	 * Test that the JS uses template.content for cloning, not jQuery find('tr').
	 *
	 * Guard test: jQuery find('tr') on <template> won't work. Must use
	 * document.getElementById(...).content.querySelector(...).
	 */
	public function test_js_uses_template_content_for_cloning() {
		$file = ATOMICEDGE_PLUGIN_DIR . 'admin/js/adaptive-defense.js';
		$this->assertFileExists( $file );

		$content = file_get_contents( $file );

		// Must use native template.content approach.
		$this->assertStringContainsString(
			'templateEl.content.querySelector',
			$content,
			'JS must use templateEl.content.querySelector() to clone from <template> element.'
		);

		// Must NOT use the old jQuery find('tr') on the template.
		$this->assertStringNotContainsString(
			"('#atomicedge-ad-detection-detail-template').find('tr')",
			$content,
			'JS must NOT use jQuery find(tr) on the template — it does not work with <template> elements.'
		);
	}

	/**
	 * Test that the detail template contains the atomicedge-ad-detail-row class.
	 *
	 * This class is required for the toggle mechanism to detect existing detail rows.
	 */
	public function test_detection_detail_template_has_detail_row_class() {
		$file = ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/adaptive-defense-detections-tab.php';
		$content = file_get_contents( $file );

		$this->assertStringContainsString(
			'atomicedge-ad-detail-row',
			$content,
			'Template must contain atomicedge-ad-detail-row class for toggle detection.'
		);
	}

	// =========================================================================
	// JS Field Contract Tests — Ensures JS selectors match template classes
	// =========================================================================

	/**
	 * Test that all CSS classes used by renderDetectionDetail exist in the template.
	 */
	public function test_js_detail_selectors_exist_in_template() {
		$template_file = ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/adaptive-defense-detections-tab.php';
		$template      = file_get_contents( $template_file );

		// These are the CSS classes that renderDetectionDetail() uses to populate data.
		$required_classes = array(
			'atomicedge-ad-detail-score',
			'atomicedge-ad-detail-confidence',
			'atomicedge-ad-detail-status',
			'atomicedge-ad-detail-detected-at',
			'atomicedge-ad-detail-ip',
			'atomicedge-ad-detail-requests',
			'atomicedge-ad-detail-waf-hits',
			'atomicedge-ad-detail-errors',
			'atomicedge-ad-detail-first-seen',
			'atomicedge-ad-detail-last-seen',
			'atomicedge-ad-detail-reasons',
			'atomicedge-ad-detail-ai-section',
			'atomicedge-ad-detail-ai-content',
			'atomicedge-ad-detail-loading',
			'atomicedge-ad-detail-content',
		);

		foreach ( $required_classes as $class ) {
			$this->assertStringContainsString(
				$class,
				$template,
				"Template missing CSS class '$class' used by renderDetectionDetail() in JS."
			);
		}
	}

	/**
	 * Test that the dev mode has all required methods for AD.
	 */
	public function test_dev_mode_has_all_ad_methods() {
		$required_methods = array(
			'get_simulated_adaptive_defense',
			'get_simulated_actor_profiles',
			'get_simulated_threat_detections',
			'get_simulated_threat_detection_detail',
			'simulate_block_ip',
			'simulate_unblock_ip',
			'simulate_extend_block',
			'simulate_dismiss_detection',
			'simulate_delete_actor',
		);

		foreach ( $required_methods as $method ) {
			$this->assertTrue(
				method_exists( 'AtomicEdge_Dev_Mode', $method ),
				"AtomicEdge_Dev_Mode::$method() must exist for Adaptive Defense dev mode support."
			);
		}
	}

	// =========================================================================
	// AJAX Handler Dev Mode Interception — Status Filter Passthrough
	// =========================================================================

	/**
	 * Test that detection status filter is passed through in dev mode.
	 */
	public function test_ajax_detections_filter_by_status_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['status'] = 'pending_review';

		try {
			$this->ajax->ajax_get_threat_detections();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		foreach ( $this->json_response['detections'] as $d ) {
			$this->assertEquals( 'pending_review', $d['status'] );
		}
	}

	/**
	 * Test that actor profiles search is passed through in dev mode.
	 */
	public function test_ajax_actor_profiles_search_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['search'] = '45.33';

		try {
			$this->ajax->ajax_get_actor_profiles();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertNotEmpty( $this->json_response['actors'] );
		foreach ( $this->json_response['actors'] as $actor ) {
			$this->assertStringContainsString( '45.33', $actor['ip'] );
		}
	}

	// =========================================================================
	// Blacklist AJAX Dev Mode — WAF logs blacklist button in dev mode
	// =========================================================================

	/**
	 * Test that AJAX add_ip_blacklist returns simulated success in dev mode.
	 *
	 * The WAF logs "Blacklist" button uses the atomicedge_add_ip_blacklist action.
	 * In dev mode, it must return a simulated success without calling the real API.
	 */
	public function test_ajax_add_ip_blacklist_returns_simulated_in_dev_mode() {
		$this->enable_dev_mode();
		$_POST['ip']          = '10.20.30.40';
		$_POST['description'] = 'Added from WordPress on 2026-03-13 12:00 UTC';

		$this->mock_api->method( 'is_valid_ip' )->willReturn( true );
		$this->mock_api->expects( $this->never() )->method( 'add_ip_blacklist' );

		try {
			$this->ajax->ajax_add_ip_blacklist();
		} catch ( AjaxExitException $e ) {
			// Expected.
		}

		$this->assertEquals( 'success', $this->json_response_type );
		$this->assertArrayHasKey( 'message', $this->json_response );
		$this->assertStringContainsString( 'Dev Mode', $this->json_response['message'] );
		$this->assertStringContainsString( '10.20.30.40', $this->json_response['message'] );
	}
}
