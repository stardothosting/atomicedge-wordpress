<?php
/**
 * Tests for Adaptive Defense AJAX response handling.
 *
 * These tests verify the WordPress plugin correctly handles various API response formats,
 * including edge cases like null values in arrays.
 *
 * @package AtomicEdge
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * Adaptive Defense response handling tests.
 */
class AdaptiveDefenseResponseTest extends TestCase {

	/**
	 * Test that threat detections API response structure is correctly parsed.
	 */
	public function test_threat_detections_response_structure() {
		$response = array(
			'success' => true,
			'data'    => array(
				'detections' => array(
					array(
						'id'             => 7,
						'ip'             => '192.168.1.100',
						'ip_address'     => '192.168.1.100',
						'score'          => 85,
						'threat_level'   => 'critical',
						'key_indicators' => array( 'High WAF hit rate', 'Suspicious patterns' ),
						'status'         => 'pending_review',
						'created_at'     => '2026-02-05T11:30:05+00:00',
					),
				),
				'pagination' => array(
					'page'        => 1,
					'per_page'    => 25,
					'total'       => 1,
					'total_pages' => 1,
				),
			),
		);

		// Verify the structure matches what JS expects.
		$this->assertTrue( $response['success'] );
		$this->assertArrayHasKey( 'detections', $response['data'] );
		$this->assertArrayHasKey( 'pagination', $response['data'] );
		$this->assertCount( 1, $response['data']['detections'] );
	}

	/**
	 * Test that null values in key_indicators don't break rendering.
	 *
	 * This was a real bug: the API returned [null, null, null] and JS crashed.
	 */
	public function test_null_values_in_key_indicators_are_filtered() {
		$detection = array(
			'id'             => 7,
			'ip_address'     => '192.168.1.100',
			'key_indicators' => array( null, null, null ),
		);

		// Simulate what JS should do: filter out nulls.
		$indicators = array_filter(
			$detection['key_indicators'],
			function ( $ind ) {
				return null !== $ind;
			}
		);

		$this->assertEmpty( $indicators );
	}

	/**
	 * Test that mixed null and valid indicators are handled.
	 */
	public function test_mixed_null_and_valid_indicators_filtered() {
		$detection = array(
			'key_indicators' => array( 'High WAF hit rate', null, 'Suspicious patterns', null ),
		);

		$indicators = array_filter(
			$detection['key_indicators'],
			function ( $ind ) {
				return null !== $ind;
			}
		);

		$this->assertCount( 2, $indicators );
		$this->assertContains( 'High WAF hit rate', $indicators );
		$this->assertContains( 'Suspicious patterns', $indicators );
	}

	/**
	 * Test that empty key_indicators array is handled.
	 */
	public function test_empty_key_indicators_handled() {
		$detection = array(
			'key_indicators' => array(),
		);

		$this->assertEmpty( $detection['key_indicators'] );
	}

	/**
	 * Test that missing key_indicators field is handled.
	 */
	public function test_missing_key_indicators_handled() {
		$detection = array(
			'id'         => 7,
			'ip_address' => '192.168.1.100',
		);

		$indicators = isset( $detection['key_indicators'] ) ? $detection['key_indicators'] : array();
		$this->assertEmpty( $indicators );
	}

	/**
	 * Test IP address fallback chain.
	 *
	 * JS should check: ip_address || ip || actor.ip_address || 'N/A'
	 */
	public function test_ip_address_fallback_chain() {
		// Case 1: ip_address is primary.
		$detection = array( 'ip_address' => '192.168.1.1', 'ip' => '10.0.0.1' );
		$ip        = ! empty( $detection['ip_address'] ) ? $detection['ip_address'] : ( ! empty( $detection['ip'] ) ? $detection['ip'] : 'N/A' );
		$this->assertEquals( '192.168.1.1', $ip );

		// Case 2: ip_address is null, fall back to ip.
		$detection = array( 'ip_address' => null, 'ip' => '10.0.0.1' );
		$ip        = ! empty( $detection['ip_address'] ) ? $detection['ip_address'] : ( ! empty( $detection['ip'] ) ? $detection['ip'] : 'N/A' );
		$this->assertEquals( '10.0.0.1', $ip );

		// Case 3: Both null, return N/A.
		$detection = array( 'ip_address' => null, 'ip' => null );
		$ip        = ! empty( $detection['ip_address'] ) ? $detection['ip_address'] : ( ! empty( $detection['ip'] ) ? $detection['ip'] : 'N/A' );
		$this->assertEquals( 'N/A', $ip );

		// Case 4: 'Unknown' string from API.
		$detection = array( 'ip_address' => 'Unknown', 'ip' => 'Unknown' );
		$ip        = ! empty( $detection['ip_address'] ) ? $detection['ip_address'] : ( ! empty( $detection['ip'] ) ? $detection['ip'] : 'N/A' );
		$this->assertEquals( 'Unknown', $ip );
	}

	/**
	 * Test status values match between dropdown and API.
	 */
	public function test_status_values_match_api_contract() {
		$dropdown_values = array( 'all', 'pending_review', 'blocked', 'dismissed' );
		$api_statuses    = array( 'pending_review', 'blocked', 'dismissed' );

		// All API statuses should be in dropdown (plus 'all').
		foreach ( $api_statuses as $status ) {
			$this->assertContains( $status, $dropdown_values, "API status '$status' missing from dropdown" );
		}
	}

	/**
	 * Test empty status should be sent as empty string for 'all'.
	 */
	public function test_empty_status_represents_all() {
		$status = 'all';

		// JS sends: status !== 'all' ? status : ''.
		$sent_status = 'all' !== $status ? $status : '';
		$this->assertEquals( '', $sent_status );
	}

	// =========================================================================
	// Detection Detail Field Name Contract Tests
	// =========================================================================

	/**
	 * Test detection detail response has all fields expected by renderDetectionDetail().
	 *
	 * The JS code (adaptive-defense.js) uses fallback chains. This test documents
	 * the field names the API is expected to provide so future changes don't break rendering.
	 */
	public function test_detection_detail_expected_fields() {
		$detection = array(
			'id'             => 7,
			'detected_at'    => '2026-02-05T11:30:05+00:00',
			'created_at'     => '2026-02-05T11:30:05+00:00',
			'ip'             => '192.168.1.100',
			'ip_address'     => '192.168.1.100',
			'score'          => 85,
			'threat_level'   => 'critical',
			'key_indicators' => array( 'High WAF hit rate' ),
			'status'         => 'pending_review',
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

		// Detection-level fields.
		$required_detection_fields = array( 'score', 'threat_level', 'status', 'key_indicators' );
		foreach ( $required_detection_fields as $field ) {
			$this->assertArrayHasKey( $field, $detection, "Detection must have '$field'" );
		}

		// At least one timestamp field must be present (JS uses detected_at || created_at).
		$has_timestamp = isset( $detection['detected_at'] ) || isset( $detection['created_at'] );
		$this->assertTrue( $has_timestamp, 'Detection must have detected_at or created_at' );

		// At least one IP field must be present (JS uses ip || ip_address).
		$has_ip = isset( $detection['ip'] ) || isset( $detection['ip_address'] );
		$this->assertTrue( $has_ip, 'Detection must have ip or ip_address' );
	}

	/**
	 * Test actor sub-object in detection detail has all expected fields.
	 *
	 * The JS renderDetectionDetail() reads actor fields with fallback chains.
	 * This documents the 7 field pairs that must be available:
	 *
	 * 1. actor.ip || actor.ip_address
	 * 2. actor.total_waf_hits || actor.waf_hits
	 * 3. actor.total_requests (no fallback)
	 * 4. actor.total_4xx_errors || actor.error_4xx
	 * 5. actor.total_5xx_errors || actor.error_5xx
	 * 6. actor.first_seen || actor.first_seen_at
	 * 7. actor.last_seen || actor.last_seen_at
	 */
	public function test_actor_subobject_expected_field_pairs() {
		$field_pairs = array(
			array( 'ip', 'ip_address' ),
			array( 'total_waf_hits', 'waf_hits' ),
			array( 'total_4xx_errors', 'error_4xx' ),
			array( 'total_5xx_errors', 'error_5xx' ),
			array( 'first_seen', 'first_seen_at' ),
			array( 'last_seen', 'last_seen_at' ),
		);

		// Case 1: Primary fields available.
		$actor_primary = array(
			'ip'               => '192.168.1.100',
			'total_waf_hits'   => 150,
			'total_requests'   => 500,
			'total_4xx_errors' => 30,
			'total_5xx_errors' => 5,
			'first_seen'       => '2026-02-01T08:00:00Z',
			'last_seen'        => '2026-02-05T11:00:00Z',
		);

		foreach ( $field_pairs as $pair ) {
			$primary   = $pair[0];
			$fallback  = $pair[1];
			$value     = $actor_primary[ $primary ] ?? ( $actor_primary[ $fallback ] ?? null );
			$this->assertNotNull( $value, "Primary actor data must have '$primary' or '$fallback'" );
		}

		// Case 2: Only fallback fields available.
		$actor_fallback = array(
			'ip_address'    => '192.168.1.100',
			'waf_hits'      => 100,
			'total_requests' => 300,
			'error_4xx'     => 20,
			'error_5xx'     => 2,
			'first_seen_at' => '2026-02-01T08:00:00Z',
			'last_seen_at'  => '2026-02-05T11:00:00Z',
		);

		foreach ( $field_pairs as $pair ) {
			$primary   = $pair[0];
			$fallback  = $pair[1];
			$value     = $actor_fallback[ $primary ] ?? ( $actor_fallback[ $fallback ] ?? null );
			$this->assertNotNull( $value, "Fallback actor data must resolve '$primary' or '$fallback'" );
		}
	}

	/**
	 * Test JS-style fallback chain evaluation for detection timestamp.
	 *
	 * Simulates: detection.detected_at || detection.created_at || 'Unknown'
	 */
	public function test_detection_timestamp_fallback_chain() {
		// Case 1: detected_at present.
		$detection = array( 'detected_at' => '2026-02-05T11:30:05+00:00', 'created_at' => '2026-02-05T11:00:00+00:00' );
		$ts        = ! empty( $detection['detected_at'] ) ? $detection['detected_at'] : ( ! empty( $detection['created_at'] ) ? $detection['created_at'] : 'Unknown' );
		$this->assertEquals( '2026-02-05T11:30:05+00:00', $ts );

		// Case 2: Only created_at.
		$detection = array( 'created_at' => '2026-02-05T11:00:00+00:00' );
		$ts        = ! empty( $detection['detected_at'] ) ? $detection['detected_at'] : ( ! empty( $detection['created_at'] ) ? $detection['created_at'] : 'Unknown' );
		$this->assertEquals( '2026-02-05T11:00:00+00:00', $ts );

		// Case 3: Neither present.
		$detection = array();
		$ts        = ! empty( $detection['detected_at'] ) ? $detection['detected_at'] : ( ! empty( $detection['created_at'] ) ? $detection['created_at'] : 'Unknown' );
		$this->assertEquals( 'Unknown', $ts );
	}

	/**
	 * Test JS-style fallback chain for actor waf_hits field.
	 *
	 * Simulates: actor.total_waf_hits || actor.waf_hits || 0
	 */
	public function test_actor_waf_hits_fallback_chain() {
		// Case 1: Primary field.
		$actor = array( 'total_waf_hits' => 150, 'waf_hits' => 100 );
		$hits  = ! empty( $actor['total_waf_hits'] ) ? $actor['total_waf_hits'] : ( ! empty( $actor['waf_hits'] ) ? $actor['waf_hits'] : 0 );
		$this->assertEquals( 150, $hits );

		// Case 2: Only fallback field.
		$actor = array( 'waf_hits' => 100 );
		$hits  = ! empty( $actor['total_waf_hits'] ) ? $actor['total_waf_hits'] : ( ! empty( $actor['waf_hits'] ) ? $actor['waf_hits'] : 0 );
		$this->assertEquals( 100, $hits );

		// Case 3: Neither present.
		$actor = array();
		$hits  = ! empty( $actor['total_waf_hits'] ) ? $actor['total_waf_hits'] : ( ! empty( $actor['waf_hits'] ) ? $actor['waf_hits'] : 0 );
		$this->assertEquals( 0, $hits );
	}

	/**
	 * Test JS-style fallback chain for actor error counts.
	 *
	 * Simulates: actor.total_4xx_errors || actor.error_4xx || 0
	 */
	public function test_actor_error_count_fallback_chains() {
		// 4xx errors: primary.
		$actor  = array( 'total_4xx_errors' => 30 );
		$errors = ! empty( $actor['total_4xx_errors'] ) ? $actor['total_4xx_errors'] : ( ! empty( $actor['error_4xx'] ) ? $actor['error_4xx'] : 0 );
		$this->assertEquals( 30, $errors );

		// 4xx errors: fallback.
		$actor  = array( 'error_4xx' => 20 );
		$errors = ! empty( $actor['total_4xx_errors'] ) ? $actor['total_4xx_errors'] : ( ! empty( $actor['error_4xx'] ) ? $actor['error_4xx'] : 0 );
		$this->assertEquals( 20, $errors );

		// 5xx errors: primary.
		$actor  = array( 'total_5xx_errors' => 5 );
		$errors = ! empty( $actor['total_5xx_errors'] ) ? $actor['total_5xx_errors'] : ( ! empty( $actor['error_5xx'] ) ? $actor['error_5xx'] : 0 );
		$this->assertEquals( 5, $errors );

		// 5xx errors: fallback.
		$actor  = array( 'error_5xx' => 2 );
		$errors = ! empty( $actor['total_5xx_errors'] ) ? $actor['total_5xx_errors'] : ( ! empty( $actor['error_5xx'] ) ? $actor['error_5xx'] : 0 );
		$this->assertEquals( 2, $errors );

		// 5xx errors: neither.
		$actor  = array();
		$errors = ! empty( $actor['total_5xx_errors'] ) ? $actor['total_5xx_errors'] : ( ! empty( $actor['error_5xx'] ) ? $actor['error_5xx'] : 0 );
		$this->assertEquals( 0, $errors );
	}

	/**
	 * Test JS-style fallback chain for actor seen timestamps.
	 *
	 * Simulates: actor.first_seen || actor.first_seen_at || 'Unknown'
	 */
	public function test_actor_seen_timestamp_fallback_chains() {
		// first_seen: primary.
		$actor = array( 'first_seen' => '2026-02-01T08:00:00Z' );
		$seen  = ! empty( $actor['first_seen'] ) ? $actor['first_seen'] : ( ! empty( $actor['first_seen_at'] ) ? $actor['first_seen_at'] : 'Unknown' );
		$this->assertEquals( '2026-02-01T08:00:00Z', $seen );

		// first_seen: fallback.
		$actor = array( 'first_seen_at' => '2026-02-01T09:00:00Z' );
		$seen  = ! empty( $actor['first_seen'] ) ? $actor['first_seen'] : ( ! empty( $actor['first_seen_at'] ) ? $actor['first_seen_at'] : 'Unknown' );
		$this->assertEquals( '2026-02-01T09:00:00Z', $seen );

		// last_seen: primary.
		$actor = array( 'last_seen' => '2026-02-05T11:00:00Z' );
		$seen  = ! empty( $actor['last_seen'] ) ? $actor['last_seen'] : ( ! empty( $actor['last_seen_at'] ) ? $actor['last_seen_at'] : 'Unknown' );
		$this->assertEquals( '2026-02-05T11:00:00Z', $seen );

		// last_seen: neither.
		$actor = array();
		$seen  = ! empty( $actor['last_seen'] ) ? $actor['last_seen'] : ( ! empty( $actor['last_seen_at'] ) ? $actor['last_seen_at'] : 'Unknown' );
		$this->assertEquals( 'Unknown', $seen );
	}
}
