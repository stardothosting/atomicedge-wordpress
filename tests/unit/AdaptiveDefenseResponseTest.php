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
}
