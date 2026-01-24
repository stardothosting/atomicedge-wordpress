<?php
/**
 * AtomicEdge Development Mode
 *
 * Provides simulated API responses for local development environments.
 * This allows testing all plugin features without a real AtomicEdge connection.
 *
 * @package AtomicEdge
 * @since   2.0.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_Dev_Mode
 *
 * Development mode utilities for local testing.
 */
class AtomicEdge_Dev_Mode {

	/**
	 * Local domain patterns that trigger dev mode.
	 *
	 * @var array
	 */
	private static $local_patterns = array(
		'.local',
		'.test',
		'.localhost',
		'.dev',
		'.ddev.site',
		'localhost',
		'127.0.0.1',
		'::1',
	);

	/**
	 * Check if the current site is a local/development environment.
	 *
	 * @return bool
	 */
	public static function is_local_environment() {
		$host = wp_parse_url( get_site_url(), PHP_URL_HOST );

		if ( empty( $host ) ) {
			return false;
		}

		// Check against known local patterns.
		foreach ( self::$local_patterns as $pattern ) {
			if ( $host === $pattern || substr( $host, -strlen( $pattern ) ) === $pattern ) {
				return true;
			}
		}

		// Check for private IP ranges.
		if ( filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false &&
			filter_var( $host, FILTER_VALIDATE_IP ) !== false ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if development mode is enabled.
	 *
	 * Dev mode is enabled when:
	 * 1. Site is in a local environment, AND
	 * 2. The dev mode option is enabled (or defaults to enabled for local)
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		if ( ! self::is_local_environment() ) {
			return false;
		}

		// Default to enabled for local environments, can be disabled via option.
		return get_option( 'atomicedge_dev_mode', true );
	}

	/**
	 * Get simulated site data for development.
	 *
	 * @return array
	 */
	public static function get_simulated_site_data() {
		$host = wp_parse_url( get_site_url(), PHP_URL_HOST );
		$prefix = str_replace( array( '.', '-' ), '', $host );

		return array(
			'connected'   => true,
			'site_id'     => 999,
			'domain'      => $host,
			'plan_tier'   => 'enterprise', // Give full features in dev mode.
			'waf_enabled' => true,
			'cdn_enabled' => true,
			'cdn_prefix'  => $prefix,
			'cdn_url'     => $prefix . '.cdn.shift8web.ca',
			'features'    => array(
				'waf_protection'    => true,
				'analytics'         => true,
				'ip_access_control' => true,
				'geo_blocking'      => true,
				'cdn'               => true,
				'minification'      => true,
			),
			'dev_mode'    => true,
		);
	}

	/**
	 * Get the effective site data (real or simulated).
	 *
	 * @return array
	 */
	public static function get_effective_site_data() {
		$stored_data = get_option( 'atomicedge_site_data', array() );

		// If connected with real data, use that.
		if ( ! empty( $stored_data['connected'] ) && empty( $stored_data['dev_mode'] ) ) {
			return $stored_data;
		}

		// If dev mode is enabled, return simulated data.
		if ( self::is_enabled() ) {
			return self::get_simulated_site_data();
		}

		return $stored_data;
	}

	/**
	 * Check if effectively connected (real or dev mode).
	 *
	 * @return bool
	 */
	public static function is_effectively_connected() {
		if ( get_option( 'atomicedge_connected', false ) ) {
			return true;
		}

		return self::is_enabled();
	}

	/**
	 * Check if CDN is effectively enabled (real or dev mode).
	 *
	 * @return bool
	 */
	public static function is_cdn_effectively_enabled() {
		$site_data = self::get_effective_site_data();
		return ! empty( $site_data['cdn_enabled'] );
	}

	/**
	 * Get a dev mode notice for admin display.
	 *
	 * @return string HTML notice or empty string.
	 */
	public static function get_admin_notice() {
		if ( ! self::is_enabled() ) {
			return '';
		}

		return sprintf(
			'<div class="atomicedge-notice atomicedge-notice-info" style="margin-bottom: 15px;">
				<span class="dashicons dashicons-info"></span>
				<div>
					<p><strong>%s</strong></p>
					<p>%s</p>
				</div>
			</div>',
			esc_html__( 'Development Mode Active', 'atomic-edge-security' ),
			esc_html__( 'You are viewing simulated data for local development. All features are available for testing. Connect to AtomicEdge on a production site for real functionality.', 'atomic-edge-security' )
		);
	}

	/**
	 * Simulate an API response for development.
	 *
	 * @param string $endpoint The API endpoint.
	 * @param array  $data     Request data.
	 * @return array Simulated response.
	 */
	public static function simulate_api_response( $endpoint, $data = array() ) {
		switch ( $endpoint ) {
			case '/connect':
				return array(
					'success' => true,
					'data'    => self::get_simulated_site_data(),
				);

			case '/cdn/status':
				return array(
					'success' => true,
					'data'    => array(
						'cdn_enabled'  => true,
						'cdn_prefix'   => self::get_simulated_site_data()['cdn_prefix'],
						'cdn_url'      => self::get_simulated_site_data()['cdn_url'],
						'optimization' => array(
							'brotli'             => true,
							'image_optimization' => false,
						),
					),
				);

			case '/cdn/purge':
				return array(
					'success' => true,
					'data'    => array(
						'message'   => __( '[Dev Mode] Cache purge simulated.', 'atomic-edge-security' ),
						'purged_at' => gmdate( 'c' ),
					),
				);

			case '/analytics':
				return array(
					'success' => true,
					'data'    => self::get_simulated_analytics(),
				);

			case '/waf/logs':
				return array(
					'success' => true,
					'data'    => self::get_simulated_waf_logs(),
				);

			default:
				return array(
					'success' => true,
					'data'    => array(
						'dev_mode' => true,
						'message'  => __( 'Simulated response for development.', 'atomic-edge-security' ),
					),
				);
		}
	}

	/**
	 * Get simulated analytics data.
	 *
	 * @return array
	 */
	private static function get_simulated_analytics() {
		$data = array(
			'requests'        => array(),
			'bandwidth'       => array(),
			'blocked'         => array(),
			'cache_hit_ratio' => 0.85,
			'total_requests'  => 0,
			'total_blocked'   => 0,
		);

		// Generate 24 hours of fake data.
		$now = time();
		for ( $i = 23; $i >= 0; $i-- ) {
			$timestamp          = gmdate( 'Y-m-d H:00:00', $now - ( $i * 3600 ) );
			$requests           = wp_rand( 100, 500 );
			$blocked            = wp_rand( 5, 30 );
			$data['requests'][] = array(
				'timestamp' => $timestamp,
				'count'     => $requests,
			);
			$data['bandwidth'][] = array(
				'timestamp' => $timestamp,
				'bytes'     => $requests * wp_rand( 5000, 20000 ),
			);
			$data['blocked'][] = array(
				'timestamp' => $timestamp,
				'count'     => $blocked,
			);
			$data['total_requests'] += $requests;
			$data['total_blocked']  += $blocked;
		}

		return $data;
	}

	/**
	 * Get simulated WAF logs.
	 *
	 * @return array
	 */
	private static function get_simulated_waf_logs() {
		$rules = array(
			'SQL Injection Attempt',
			'XSS Attack Detected',
			'Path Traversal Attempt',
			'Remote File Inclusion',
			'Rate Limit Exceeded',
		);

		$ips = array(
			'192.168.1.' . wp_rand( 1, 255 ),
			'10.0.0.' . wp_rand( 1, 255 ),
			'172.16.0.' . wp_rand( 1, 255 ),
		);

		$logs = array();
		for ( $i = 0; $i < 10; $i++ ) {
			$logs[] = array(
				'id'         => 'dev-' . wp_rand( 10000, 99999 ),
				'timestamp'  => gmdate( 'c', time() - wp_rand( 0, 86400 ) ),
				'client_ip'  => $ips[ array_rand( $ips ) ],
				'rule'       => $rules[ array_rand( $rules ) ],
				'uri'        => '/wp-admin/admin-ajax.php',
				'action'     => 'blocked',
				'user_agent' => 'Mozilla/5.0 (Dev Mode Simulator)',
			);
		}

		return array(
			'logs'  => $logs,
			'total' => count( $logs ),
		);
	}
}
