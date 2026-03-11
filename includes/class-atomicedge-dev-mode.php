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
	 * Convert an ISO 3166-1 alpha-2 country code to a flag emoji.
	 *
	 * Uses Unicode Regional Indicator Symbols — same approach as
	 * ActorProfile::getCountryFlagEmojiAttribute() on the Laravel side.
	 *
	 * @param string|null $country_code Two-letter code (e.g. 'US').
	 * @return string Flag emoji or empty string.
	 */
	public static function country_code_to_flag( $country_code ) {
		if ( empty( $country_code ) || strlen( $country_code ) !== 2 ) {
			return '';
		}
		$code = strtoupper( $country_code );
		$base = 0x1F1E6 - ord( 'A' );
		// mb_chr requires PHP 7.2+ (WordPress 5.x minimum).
		return mb_chr( $base + ord( $code[0] ) ) . mb_chr( $base + ord( $code[1] ) );
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

	// =========================================================================
	// Adaptive Defense Simulated Data
	// =========================================================================

	/**
	 * Get simulated Adaptive Defense overview data.
	 *
	 * @return array
	 */
	public static function get_simulated_adaptive_defense() {
		return array(
			'settings'         => array(
				'enabled'     => true,
				'mode'        => 'auto_enforce',
				'sensitivity' => 'balanced',
			),
			'threat_level'     => 'medium',
			'stats'            => array(
				'total_actors'       => 25,
				'blocked_ips'        => 3,
				'pending_detections' => 5,
				'high_threat_count'  => 2,
				'ai_budget_used'     => 35,
				'ai_budget_total'    => 200,
			),
			'high_risk_actors' => self::get_simulated_high_risk_actors(),
		);
	}

	/**
	 * Get simulated high-risk actors for the status tab.
	 *
	 * @return array
	 */
	private static function get_simulated_high_risk_actors() {
		return array(
			array(
				'id'                  => 1001,
				'ip'                  => '45.33.32.156',
				'ip_address'          => '45.33.32.156',
				'country_code'        => 'US',
				'country_flag_emoji'  => self::country_code_to_flag( 'US' ),
				'total_requests'  => 1523,
				'total_waf_hits'  => 89,
				'total_waf_events' => 89,
				'threat_score'    => 92,
				'is_blocked'      => true,
				'first_seen'      => gmdate( 'c', time() - 86400 * 3 ),
				'first_seen_at'   => gmdate( 'c', time() - 86400 * 3 ),
				'last_seen'       => gmdate( 'c', time() - 3600 ),
				'last_seen_at'    => gmdate( 'c', time() - 3600 ),
			),
			array(
				'id'                  => 1002,
				'ip'                  => '103.235.46.39',
				'ip_address'          => '103.235.46.39',
				'country_code'        => 'CN',
				'country_flag_emoji'  => self::country_code_to_flag( 'CN' ),
				'total_requests'  => 856,
				'total_waf_hits'  => 45,
				'total_waf_events' => 45,
				'threat_score'    => 78,
				'is_blocked'      => false,
				'first_seen'      => gmdate( 'c', time() - 86400 * 5 ),
				'first_seen_at'   => gmdate( 'c', time() - 86400 * 5 ),
				'last_seen'       => gmdate( 'c', time() - 7200 ),
				'last_seen_at'    => gmdate( 'c', time() - 7200 ),
			),
		);
	}

	/**
	 * Get simulated actor profiles (paginated).
	 *
	 * @param array $args Query arguments (page, per_page, filter, search).
	 * @return array
	 */
	public static function get_simulated_actor_profiles( $args = array() ) {
		$actors = array(
			array(
				'id'               => 1001,
				'ip'               => '45.33.32.156',
				'ip_address'       => '45.33.32.156',
				'country_code'     => 'US',
				'country_flag_emoji' => self::country_code_to_flag( 'US' ),
				'total_requests'   => 1523,
				'total_waf_hits'   => 89,
				'total_waf_events' => 89,
				'total_4xx_errors' => 34,
				'total_5xx_errors' => 2,
				'error_4xx'        => 34,
				'error_5xx'        => 2,
				'threat_score'     => 92,
				'is_blocked'       => true,
				'blocked_at'       => gmdate( 'c', time() - 7200 ),
				'block_expires_at' => gmdate( 'c', time() + 86400 ),
				'first_seen'       => gmdate( 'c', time() - 86400 * 3 ),
				'first_seen_at'    => gmdate( 'c', time() - 86400 * 3 ),
				'last_seen'        => gmdate( 'c', time() - 3600 ),
				'last_seen_at'     => gmdate( 'c', time() - 3600 ),
				'updated_at'       => gmdate( 'c', time() - 3600 ),
				'user_agents'      => array( 'python-requests/2.28.1', 'curl/7.88.1' ),
			),
			array(
				'id'               => 1002,
				'ip'               => '103.235.46.39',
				'ip_address'       => '103.235.46.39',
				'country_code'     => 'CN',
				'country_flag_emoji' => self::country_code_to_flag( 'CN' ),
				'total_requests'   => 856,
				'total_waf_hits'   => 45,
				'total_waf_events' => 45,
				'total_4xx_errors' => 12,
				'total_5xx_errors' => 0,
				'error_4xx'        => 12,
				'error_5xx'        => 0,
				'threat_score'     => 78,
				'is_blocked'       => false,
				'first_seen'       => gmdate( 'c', time() - 86400 * 5 ),
				'first_seen_at'    => gmdate( 'c', time() - 86400 * 5 ),
				'last_seen'        => gmdate( 'c', time() - 7200 ),
				'last_seen_at'     => gmdate( 'c', time() - 7200 ),
				'updated_at'       => gmdate( 'c', time() - 7200 ),
				'user_agents'      => array( 'Mozilla/5.0 (compatible; Googlebot/2.1)' ),
			),
			array(
				'id'               => 1003,
				'ip'               => '198.51.100.42',
				'ip_address'       => '198.51.100.42',
				'country_code'     => 'DE',
				'country_flag_emoji' => self::country_code_to_flag( 'DE' ),
				'total_requests'   => 324,
				'total_waf_hits'   => 8,
				'total_waf_events' => 8,
				'total_4xx_errors' => 3,
				'total_5xx_errors' => 0,
				'error_4xx'        => 3,
				'error_5xx'        => 0,
				'threat_score'     => 35,
				'is_blocked'       => false,
				'first_seen'       => gmdate( 'c', time() - 86400 * 7 ),
				'first_seen_at'    => gmdate( 'c', time() - 86400 * 7 ),
				'last_seen'        => gmdate( 'c', time() - 14400 ),
				'last_seen_at'     => gmdate( 'c', time() - 14400 ),
				'updated_at'       => gmdate( 'c', time() - 14400 ),
				'user_agents'      => array( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' ),
			),
			array(
				'id'               => 1004,
				'ip'               => '203.0.113.88',
				'ip_address'       => '203.0.113.88',
				'country_code'     => 'RU',
				'country_flag_emoji' => self::country_code_to_flag( 'RU' ),
				'total_requests'   => 2100,
				'total_waf_hits'   => 156,
				'total_waf_events' => 156,
				'total_4xx_errors' => 78,
				'total_5xx_errors' => 5,
				'error_4xx'        => 78,
				'error_5xx'        => 5,
				'threat_score'     => 95,
				'is_blocked'       => true,
				'blocked_at'       => gmdate( 'c', time() - 3600 ),
				'block_expires_at' => null,
				'first_seen'       => gmdate( 'c', time() - 86400 * 2 ),
				'first_seen_at'    => gmdate( 'c', time() - 86400 * 2 ),
				'last_seen'        => gmdate( 'c', time() - 1800 ),
				'last_seen_at'     => gmdate( 'c', time() - 1800 ),
				'updated_at'       => gmdate( 'c', time() - 1800 ),
				'user_agents'      => array( 'sqlmap/1.7', 'nikto/2.1.6' ),
			),
			array(
				'id'               => 1005,
				'ip'               => '192.0.2.200',
				'ip_address'       => '192.0.2.200',
				'country_code'     => 'BR',
				'country_flag_emoji' => self::country_code_to_flag( 'BR' ),
				'total_requests'   => 98,
				'total_waf_hits'   => 3,
				'total_waf_events' => 3,
				'total_4xx_errors' => 1,
				'total_5xx_errors' => 0,
				'error_4xx'        => 1,
				'error_5xx'        => 0,
				'threat_score'     => 15,
				'is_blocked'       => false,
				'first_seen'       => gmdate( 'c', time() - 86400 * 10 ),
				'first_seen_at'    => gmdate( 'c', time() - 86400 * 10 ),
				'last_seen'        => gmdate( 'c', time() - 43200 ),
				'last_seen_at'     => gmdate( 'c', time() - 43200 ),
				'updated_at'       => gmdate( 'c', time() - 43200 ),
				'user_agents'      => array( 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' ),
			),
		);

		// Apply filter.
		$filter = isset( $args['filter'] ) ? $args['filter'] : 'all';
		if ( 'blocked' === $filter ) {
			$actors = array_values( array_filter( $actors, function ( $a ) {
				return ! empty( $a['is_blocked'] );
			} ) );
		} elseif ( 'high_risk' === $filter ) {
			$actors = array_values( array_filter( $actors, function ( $a ) {
				return ( $a['threat_score'] ?? 0 ) >= 70;
			} ) );
		}

		// Apply search.
		if ( ! empty( $args['search'] ) ) {
			$search = $args['search'];
			$actors = array_values( array_filter( $actors, function ( $a ) use ( $search ) {
				return stripos( $a['ip'], $search ) !== false;
			} ) );
		}

		$total = count( $actors );
		$page  = isset( $args['page'] ) ? max( 1, (int) $args['page'] ) : 1;
		$per   = isset( $args['per_page'] ) ? max( 1, (int) $args['per_page'] ) : 25;
		$slice = array_slice( $actors, ( $page - 1 ) * $per, $per );

		return array(
			'actors'     => $slice,
			'pagination' => array(
				'current_page' => $page,
				'per_page'     => $per,
				'total'        => $total,
				'total_pages'  => max( 1, (int) ceil( $total / $per ) ),
			),
		);
	}

	/**
	 * Get simulated threat detections (paginated).
	 *
	 * @param array $args Query arguments (page, per_page, status).
	 * @return array
	 */
	public static function get_simulated_threat_detections( $args = array() ) {
		$detections = array(
			array(
				'id'              => 2001,
				'score'           => 92,
				'confidence'      => 0.87,
				'threat_level'    => 'critical',
				'status'          => 'auto_blocked',
				'ip_address'      => '45.33.32.156',
				'country_code'    => 'US',
				'country_flag_emoji' => self::country_code_to_flag( 'US' ),
				'created_at'      => gmdate( 'c', time() - 7200 ),
				'detected_at'     => gmdate( 'c', time() - 7200 ),
				'reasons'         => array( 'SQL injection patterns', 'High WAF hit rate', 'Known malicious user agent' ),
				'key_indicators'  => array( 'SQL injection patterns', 'High WAF hit rate', 'Known malicious user agent' ),
				'reasons_summary' => array( 'SQL injection patterns', 'High WAF hit rate' ),
				'actor'           => array(
					'id'               => 1001,
					'ip'               => '45.33.32.156',
					'ip_address'       => '45.33.32.156',
					'country_code'     => 'US',
					'country_flag_emoji' => self::country_code_to_flag( 'US' ),
					'total_requests'   => 1523,
					'total_waf_hits'   => 89,
					'waf_hits'         => 89,
					'total_4xx_errors' => 34,
					'total_5xx_errors' => 2,
					'error_4xx'        => 34,
					'error_5xx'        => 2,
					'first_seen'       => gmdate( 'c', time() - 86400 * 3 ),
					'first_seen_at'    => gmdate( 'c', time() - 86400 * 3 ),
					'last_seen'        => gmdate( 'c', time() - 3600 ),
					'last_seen_at'     => gmdate( 'c', time() - 3600 ),
					'updated_at'       => gmdate( 'c', time() - 3600 ),
				),
			),
			array(
				'id'              => 2002,
				'score'           => 78,
				'confidence'      => 0.72,
				'threat_level'    => 'high',
				'status'          => 'pending_review',
				'ip_address'      => '103.235.46.39',
				'country_code'    => 'CN',
				'country_flag_emoji' => self::country_code_to_flag( 'CN' ),
				'created_at'      => gmdate( 'c', time() - 14400 ),
				'detected_at'     => gmdate( 'c', time() - 14400 ),
				'reasons'         => array( 'Directory traversal attempts', 'Suspicious user agent rotation' ),
				'key_indicators'  => array( 'Directory traversal attempts', 'Suspicious user agent rotation' ),
				'reasons_summary' => array( 'Directory traversal attempts' ),
				'actor'           => array(
					'id'               => 1002,
					'ip'               => '103.235.46.39',
					'ip_address'       => '103.235.46.39',
					'country_code'     => 'CN',
					'country_flag_emoji' => self::country_code_to_flag( 'CN' ),
					'total_requests'   => 856,
					'total_waf_hits'   => 45,
					'waf_hits'         => 45,
					'total_4xx_errors' => 12,
					'total_5xx_errors' => 0,
					'error_4xx'        => 12,
					'error_5xx'        => 0,
					'first_seen'       => gmdate( 'c', time() - 86400 * 5 ),
					'first_seen_at'    => gmdate( 'c', time() - 86400 * 5 ),
					'last_seen'        => gmdate( 'c', time() - 7200 ),
					'last_seen_at'     => gmdate( 'c', time() - 7200 ),
					'updated_at'       => gmdate( 'c', time() - 7200 ),
				),
			),
			array(
				'id'              => 2003,
				'score'           => 95,
				'confidence'      => 0.91,
				'threat_level'    => 'critical',
				'status'          => 'user_blocked',
				'ip_address'      => '203.0.113.88',
				'country_code'    => 'RU',
				'country_flag_emoji' => self::country_code_to_flag( 'RU' ),
				'created_at'      => gmdate( 'c', time() - 3600 ),
				'detected_at'     => gmdate( 'c', time() - 3600 ),
				'reasons'         => array( 'Automated SQL injection tool', 'Nikto scan detected', 'Extremely high WAF events' ),
				'key_indicators'  => array( 'Automated SQL injection tool', 'Nikto scan detected', 'Extremely high WAF events' ),
				'reasons_summary' => array( 'Automated SQL injection tool', 'Nikto scan detected' ),
				'ai_analysis'     => 'This IP exhibits classic automated attack tool behavior. The sqlmap user agent combined with high-frequency WAF triggers indicates an active SQL injection campaign. Immediate blocking recommended.',
				'actor'           => array(
					'id'               => 1004,
					'ip'               => '203.0.113.88',
					'ip_address'       => '203.0.113.88',
					'country_code'     => 'RU',
					'country_flag_emoji' => self::country_code_to_flag( 'RU' ),
					'total_requests'   => 2100,
					'total_waf_hits'   => 156,
					'waf_hits'         => 156,
					'total_4xx_errors' => 78,
					'total_5xx_errors' => 5,
					'error_4xx'        => 78,
					'error_5xx'        => 5,
					'first_seen'       => gmdate( 'c', time() - 86400 * 2 ),
					'first_seen_at'    => gmdate( 'c', time() - 86400 * 2 ),
					'last_seen'        => gmdate( 'c', time() - 1800 ),
					'last_seen_at'     => gmdate( 'c', time() - 1800 ),
					'updated_at'       => gmdate( 'c', time() - 1800 ),
				),
			),
			array(
				'id'              => 2004,
				'score'           => 55,
				'confidence'      => 0.60,
				'threat_level'    => 'medium',
				'status'          => 'pending_review',
				'ip_address'      => '198.51.100.42',
				'country_code'    => 'DE',
				'country_flag_emoji' => self::country_code_to_flag( 'DE' ),
				'created_at'      => gmdate( 'c', time() - 28800 ),
				'detected_at'     => gmdate( 'c', time() - 28800 ),
				'reasons'         => array( 'Elevated error rate', 'Minor WAF triggers' ),
				'key_indicators'  => array( 'Elevated error rate', 'Minor WAF triggers' ),
				'reasons_summary' => array( 'Elevated error rate' ),
				'actor'           => array(
					'id'               => 1003,
					'ip'               => '198.51.100.42',
					'ip_address'       => '198.51.100.42',
					'country_code'     => 'DE',
					'country_flag_emoji' => self::country_code_to_flag( 'DE' ),
					'total_requests'   => 324,
					'total_waf_hits'   => 8,
					'waf_hits'         => 8,
					'total_4xx_errors' => 3,
					'total_5xx_errors' => 0,
					'error_4xx'        => 3,
					'error_5xx'        => 0,
					'first_seen'       => gmdate( 'c', time() - 86400 * 7 ),
					'first_seen_at'    => gmdate( 'c', time() - 86400 * 7 ),
					'last_seen'        => gmdate( 'c', time() - 14400 ),
					'last_seen_at'     => gmdate( 'c', time() - 14400 ),
					'updated_at'       => gmdate( 'c', time() - 14400 ),
				),
			),
			array(
				'id'              => 2005,
				'score'           => 40,
				'confidence'      => 0.45,
				'threat_level'    => 'low',
				'status'          => 'dismissed',
				'ip_address'      => '192.0.2.200',
				'country_code'    => 'BR',
				'country_flag_emoji' => self::country_code_to_flag( 'BR' ),
				'created_at'      => gmdate( 'c', time() - 86400 ),
				'detected_at'     => gmdate( 'c', time() - 86400 ),
				'reasons'         => array( 'Unusual request patterns' ),
				'key_indicators'  => array( 'Unusual request patterns' ),
				'reasons_summary' => array( 'Unusual request patterns' ),
				'actor'           => array(
					'id'               => 1005,
					'ip'               => '192.0.2.200',
					'ip_address'       => '192.0.2.200',
					'country_code'     => 'BR',
					'country_flag_emoji' => self::country_code_to_flag( 'BR' ),
					'total_requests'   => 98,
					'total_waf_hits'   => 3,
					'waf_hits'         => 3,
					'total_4xx_errors' => 1,
					'total_5xx_errors' => 0,
					'error_4xx'        => 1,
					'error_5xx'        => 0,
					'first_seen'       => gmdate( 'c', time() - 86400 * 10 ),
					'first_seen_at'    => gmdate( 'c', time() - 86400 * 10 ),
					'last_seen'        => gmdate( 'c', time() - 43200 ),
					'last_seen_at'     => gmdate( 'c', time() - 43200 ),
					'updated_at'       => gmdate( 'c', time() - 43200 ),
				),
			),
		);

		// Apply status filter.
		$status = isset( $args['status'] ) ? $args['status'] : 'all';
		if ( 'all' !== $status && ! empty( $status ) ) {
			$detections = array_values( array_filter( $detections, function ( $d ) use ( $status ) {
				return $d['status'] === $status;
			} ) );
		}

		$total = count( $detections );
		$page  = isset( $args['page'] ) ? max( 1, (int) $args['page'] ) : 1;
		$per   = isset( $args['per_page'] ) ? max( 1, (int) $args['per_page'] ) : 25;
		$slice = array_slice( $detections, ( $page - 1 ) * $per, $per );

		return array(
			'detections' => $slice,
			'pagination' => array(
				'current_page' => $page,
				'per_page'     => $per,
				'total'        => $total,
				'total_pages'  => max( 1, (int) ceil( $total / $per ) ),
			),
		);
	}

	/**
	 * Get simulated threat detection detail.
	 *
	 * @param int $detection_id The detection ID.
	 * @return array|null Detection detail or null if not found.
	 */
	public static function get_simulated_threat_detection_detail( $detection_id ) {
		$all = self::get_simulated_threat_detections();
		foreach ( $all['detections'] as $detection ) {
			if ( (int) $detection['id'] === (int) $detection_id ) {
				return array(
					'detection' => $detection,
					'actor'     => $detection['actor'],
				);
			}
		}

		// Return the first detection as fallback for any unknown ID.
		if ( ! empty( $all['detections'] ) ) {
			$first = $all['detections'][0];
			return array(
				'detection' => $first,
				'actor'     => $first['actor'],
			);
		}

		return null;
	}

	/**
	 * Simulate a successful block IP response.
	 *
	 * @param string $ip IP address.
	 * @return array
	 */
	public static function simulate_block_ip( $ip ) {
		return array(
			'message'          => sprintf(
				/* translators: %s: IP address */
				__( '[Dev Mode] IP %s has been blocked.', 'atomic-edge-security' ),
				$ip
			),
			'ip'               => $ip,
			'is_blocked'       => true,
			'blocked_at'       => gmdate( 'c' ),
			'block_expires_at' => gmdate( 'c', time() + 86400 ),
		);
	}

	/**
	 * Simulate a successful unblock IP response.
	 *
	 * @param string $ip IP address.
	 * @return array
	 */
	public static function simulate_unblock_ip( $ip ) {
		return array(
			'message' => sprintf(
				/* translators: %s: IP address */
				__( '[Dev Mode] IP %s has been unblocked.', 'atomic-edge-security' ),
				$ip
			),
			'ip'      => $ip,
		);
	}

	/**
	 * Simulate a successful extend block response.
	 * Duration is server-authoritative; simulates a 24h extension for dev mode.
	 *
	 * @param string $ip IP address.
	 * @return array
	 */
	public static function simulate_extend_block( $ip ) {
		return array(
			'message'          => sprintf(
				/* translators: %s: IP address */
				__( '[Dev Mode] Block for %s has been extended.', 'atomic-edge-security' ),
				$ip
			),
			'ip'               => $ip,
			'is_blocked'       => true,
			'blocked_at'       => gmdate( 'c', time() - 3600 ),
			'block_expires_at' => gmdate( 'c', time() + 86400 ),
		);
	}

	/**
	 * Simulate a successful make permanent response.
	 *
	 * @param string $ip IP address.
	 * @return array
	 */
	public static function simulate_make_permanent( $ip ) {
		return array(
			'message'          => sprintf(
				/* translators: %s: IP address */
				__( '[Dev Mode] Block for %s is now permanent.', 'atomic-edge-security' ),
				$ip
			),
			'ip'               => $ip,
			'is_blocked'       => true,
			'blocked_at'       => gmdate( 'c', time() - 3600 ),
			'block_expires_at' => null,
		);
	}

	/**
	 * Simulate a successful dismiss detection response.
	 *
	 * @param int $detection_id Detection ID.
	 * @return array
	 */
	public static function simulate_dismiss_detection( $detection_id ) {
		return array(
			'message' => sprintf(
				/* translators: %d: Detection ID */
				__( '[Dev Mode] Detection #%d has been dismissed.', 'atomic-edge-security' ),
				$detection_id
			),
			'id'      => $detection_id,
			'status'  => 'dismissed',
		);
	}

	/**
	 * Simulate a successful delete actor response.
	 *
	 * @param int $actor_id Actor profile ID.
	 * @return array
	 */
	public static function simulate_delete_actor( $actor_id ) {
		return array(
			'message' => sprintf(
				/* translators: %d: Actor profile ID */
				__( '[Dev Mode] Actor profile #%d has been deleted.', 'atomic-edge-security' ),
				$actor_id
			),
			'id'      => $actor_id,
		);
	}
}
