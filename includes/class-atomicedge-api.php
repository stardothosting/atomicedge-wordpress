<?php
/**
 * AtomicEdge API Client
 *
 * Handles all communication with the AtomicEdge API.
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_API
 *
 * API client for AtomicEdge service.
 */
class AtomicEdge_API {

	/**
	 * API base URL.
	 *
	 * @var string
	 */
	private $api_url;

	/**
	 * Request timeout in seconds.
	 *
	 * @var int
	 */
	private $timeout = 30;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->api_url = get_option( 'atomicedge_api_url', 'https://dashboard.atomicedge.io/api/v1' );
		$this->timeout = apply_filters( 'atomicedge_api_timeout', 30 );
	}

	/**
	 * Check if the site is connected to AtomicEdge.
	 *
	 * @return bool
	 */
	public function is_connected() {
		return (bool) get_option( 'atomicedge_connected', false );
	}

	/**
	 * Get the decrypted API key.
	 *
	 * @return string|false API key or false if not set.
	 */
	public function get_api_key() {
		$encrypted = get_option( 'atomicedge_api_key', '' );
		if ( empty( $encrypted ) ) {
			return false;
		}
		return $this->decrypt_api_key( $encrypted );
	}

	/**
	 * Encrypt the API key for storage.
	 *
	 * @param string $key Plain text API key.
	 * @return string Encrypted API key.
	 */
	private function encrypt_api_key( $key ) {
		$iv        = substr( NONCE_KEY, 0, 16 );
		$encrypted = openssl_encrypt(
			$key,
			'AES-256-CBC',
			hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY ),
			0,
			$iv
		);
		return base64_encode( $encrypted ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Decrypt the API key.
	 *
	 * @param string $encrypted Encrypted API key.
	 * @return string|false Decrypted API key or false on failure.
	 */
	private function decrypt_api_key( $encrypted ) {
		$iv = substr( NONCE_KEY, 0, 16 );
		return openssl_decrypt(
			base64_decode( $encrypted ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			'AES-256-CBC',
			hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY ),
			0,
			$iv
		);
	}

	/**
	 * Connect to AtomicEdge with an API key.
	 *
	 * @param string $api_key The API key to validate.
	 * @return array Result with success status and message/data.
	 */
	public function connect( $api_key ) {
		// Get the site URL without protocol and www.
		$site_url = $this->get_normalized_site_url();

		// Prepare request data.
		$data = apply_filters(
			'atomicedge_before_api_request',
			array(
				'api_key'  => $api_key,
				'site_url' => $site_url,
			),
			'connect'
		);

		// Make the API request.
		$response = $this->request( 'POST', '/connect', $data, $api_key );

		// Handle response.
		if ( ! $response['success'] ) {
			return $response;
		}

		// Store the encrypted API key.
		update_option( 'atomicedge_api_key', $this->encrypt_api_key( $api_key ) );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', $response['data'] );

		// Clear any cached data.
		$this->clear_cache();

		// Fire action hook.
		do_action( 'atomicedge_connected', $response['data'] );

		AtomicEdge::log( 'Successfully connected to Atomic Edge', array( 'site_url' => $site_url ) );

		return array(
			'success' => true,
			'message' => __( 'Successfully connected to Atomic Edge!', 'atomicedge' ),
			'data'    => $response['data'],
		);
	}

	/**
	 * Disconnect from AtomicEdge.
	 *
	 * @return array Result with success status.
	 */
	public function disconnect() {
		// Clear stored data.
		delete_option( 'atomicedge_api_key' );
		update_option( 'atomicedge_connected', false );
		delete_option( 'atomicedge_site_data' );

		// Clear all cached data.
		$this->clear_cache();

		// Fire action hook.
		do_action( 'atomicedge_disconnected' );

		AtomicEdge::log( 'Disconnected from Atomic Edge' );

		return array(
			'success' => true,
			'message' => __( 'Successfully disconnected from Atomic Edge.', 'atomicedge' ),
		);
	}

	/**
	 * Get analytics summary.
	 *
	 * @param string $period Time period (24h, 7d, 30d).
	 * @return array Analytics data or error.
	 */
	public function get_analytics( $period = '24h' ) {
		$cache_key = 'atomicedge_analytics_' . $period;
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$response = $this->request( 'GET', '/analytics', array( 'period' => $period ) );

		if ( $response['success'] ) {
			$cache_duration = apply_filters( 'atomicedge_analytics_cache_duration', 15 * MINUTE_IN_SECONDS );
			set_transient( $cache_key, $response, $cache_duration );
		}

		return $response;
	}

	/**
	 * Get WAF logs.
	 *
	 * @param array $args Query arguments (page, per_page, search, etc.).
	 * @return array WAF logs or error.
	 */
	public function get_waf_logs( $args = array() ) {
		$defaults = array(
			'page'     => 1,
			'per_page' => 50,
		);
		$args     = wp_parse_args( $args, $defaults );

		// Only include search if it has a value.
		if ( isset( $args['search'] ) && '' === $args['search'] ) {
			unset( $args['search'] );
		}

		$cache_key = 'atomicedge_waf_logs_' . hash( 'sha256', (string) wp_json_encode( $args ) );
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$response = $this->request( 'GET', '/waf-logs', $args );

		if ( $response['success'] ) {
			$cache_duration = apply_filters( 'atomicedge_waf_cache_duration', 5 * MINUTE_IN_SECONDS );
			set_transient( $cache_key, $response, $cache_duration );
		}

		return $response;
	}

	/**
	 * Get IP access rules.
	 *
	 * @return array IP rules or error.
	 */
	public function get_ip_rules() {
		$cache_key = 'atomicedge_ip_rules';
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$response = $this->request( 'GET', '/ip-rules' );

		if ( $response['success'] ) {
			$cache_duration = apply_filters( 'atomicedge_ip_rules_cache_duration', 5 * MINUTE_IN_SECONDS );
			set_transient( $cache_key, $response, $cache_duration );
		}

		return $response;
	}

	/**
	 * Add IP to whitelist.
	 *
	 * @param string $ip          IP address or CIDR.
	 * @param string $description Optional description.
	 * @return array Result.
	 */
	public function add_ip_whitelist( $ip, $description = '' ) {
		$data = array(
			'ip'          => $ip,
			'description' => $description,
		);

		$response = $this->request( 'POST', '/ip-rules/whitelist', $data );

		if ( $response['success'] ) {
			delete_transient( 'atomicedge_ip_rules' );
			do_action( 'atomicedge_ip_added', $ip, 'whitelist' );
		}

		return $response;
	}

	/**
	 * Add IP to blacklist.
	 *
	 * @param string $ip          IP address or CIDR.
	 * @param string $description Optional description.
	 * @return array Result.
	 */
	public function add_ip_blacklist( $ip, $description = '' ) {
		$data = array(
			'ip'          => $ip,
			'description' => $description,
		);

		$response = $this->request( 'POST', '/ip-rules/blacklist', $data );

		if ( $response['success'] ) {
			delete_transient( 'atomicedge_ip_rules' );
			do_action( 'atomicedge_ip_added', $ip, 'blacklist' );
		}

		return $response;
	}

	/**
	 * Remove IP from whitelist or blacklist.
	 *
	 * @param string $ip   IP address or CIDR.
	 * @param string $type 'whitelist' or 'blacklist'.
	 * @return array Result.
	 */
	public function remove_ip( $ip, $type ) {
		$endpoint = '/access/ip/' . sanitize_key( $type ) . '/' . rawurlencode( $ip );
		$response = $this->request( 'DELETE', $endpoint );

		if ( $response['success'] ) {
			delete_transient( 'atomicedge_ip_rules' );
			do_action( 'atomicedge_ip_removed', $ip, $type );
		}

		return $response;
	}

	/**
	 * Get geographic access rules.
	 *
	 * @return array Geo rules or error.
	 */
	public function get_geo_rules() {
		$cache_key = 'atomicedge_geo_rules';
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$response = $this->request( 'GET', '/geo-rules' );

		if ( $response['success'] ) {
			$cache_duration = apply_filters( 'atomicedge_geo_rules_cache_duration', 5 * MINUTE_IN_SECONDS );
			set_transient( $cache_key, $response, $cache_duration );
		}

		return $response;
	}

	/**
	 * Update geographic access rules.
	 *
	 * @param array $rules Geo rules configuration.
	 * @return array Result.
	 */
	public function update_geo_rules( $rules ) {
		$response = $this->request( 'PUT', '/geo-rules', $rules );

		if ( $response['success'] ) {
			delete_transient( 'atomicedge_geo_rules' );
		}

		return $response;
	}

	/**
	 * Get site information from AtomicEdge.
	 *
	 * @return array Site info or error.
	 */
	public function get_site_info() {
		$cache_key = 'atomicedge_site_info';
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$response = $this->request( 'GET', '/connect' );

		if ( $response['success'] ) {
			set_transient( $cache_key, $response, HOUR_IN_SECONDS );
		}

		return $response;
	}

	/**
	 * Check vulnerabilities for WordPress installation.
	 *
	 * Sends WordPress core version, plugins, and themes to AtomicEdge API
	 * for vulnerability checking against the Wordfence vulnerability database.
	 *
	 * @param array $installation_data Installation data with wordpress_version, plugins, themes.
	 * @return array Response with success status and vulnerability data.
	 */
	public function check_vulnerabilities( $installation_data ) {
		$response = $this->request( 'POST', '/wp/vulnerabilities/check', $installation_data );

		return $response;
	}

	/**
	 * Make an API request.
	 *
	 * @param string      $method   HTTP method (GET, POST, PUT, DELETE).
	 * @param string      $endpoint API endpoint.
	 * @param array       $data     Request data.
	 * @param string|null $api_key  Optional API key override.
	 * @return array Response with success status and data/error.
	 */
	private function request( $method, $endpoint, $data = array(), $api_key = null ) {
		$api_key = $api_key ?? $this->get_api_key();

		if ( ! $api_key && '/connect' !== $endpoint ) {
			return array(
				'success' => false,
				'error'   => __( 'Not connected to Atomic Edge.', 'atomicedge' ),
			);
		}

		$url = $this->api_url . $endpoint;

		// Add query params for GET requests.
		if ( 'GET' === $method && ! empty( $data ) ) {
			$url = add_query_arg( $data, $url );
		}

		$args = array(
			'method'  => $method,
			'timeout' => $this->timeout,
			'headers' => array(
				'Content-Type'     => 'application/json',
				'Accept'           => 'application/json',
				'X-AtomicEdge-Key' => $api_key,
			),
		);

		// Add body for non-GET requests.
		if ( 'GET' !== $method && ! empty( $data ) ) {
			$args['body'] = wp_json_encode( $data );
		}

		AtomicEdge::log( "API Request: {$method} {$endpoint}" );

		$response = wp_remote_request( $url, $args );

		// Check for WP error.
		if ( is_wp_error( $response ) ) {
			AtomicEdge::log( 'API Error', $response->get_error_message() );
			return array(
				'success' => false,
				'error'   => $response->get_error_message(),
			);
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		// Apply response filter.
		$data = apply_filters( 'atomicedge_after_api_response', $data, $endpoint );

		// Handle HTTP errors.
		if ( $code >= 400 ) {
			$error_message = isset( $data['error'] ) ? $data['error'] : __( 'An error occurred.', 'atomicedge' );
			if ( isset( $data['message'] ) ) {
				$error_message = $data['message'];
			}
			AtomicEdge::log( "API Error ({$code})", $error_message );
			return array(
				'success' => false,
				'error'   => $error_message,
				'code'    => $code,
			);
		}

		// Extract nested data if API returns standard response format.
		// The API returns {"success": true, "data": {...}}, so we extract the inner data.
		if ( isset( $data['success'] ) && true === $data['success'] && isset( $data['data'] ) ) {
			return array(
				'success' => true,
				'data'    => $data['data'],
			);
		}

		// Handle API-level errors.
		if ( isset( $data['success'] ) && false === $data['success'] ) {
			$error_message = isset( $data['message'] ) ? $data['message'] : __( 'An error occurred.', 'atomicedge' );
			if ( isset( $data['error'] ) ) {
				$error_message = $data['error'];
			}
			return array(
				'success' => false,
				'error'   => $error_message,
			);
		}

		// Fallback for non-standard responses.
		return array(
			'success' => true,
			'data'    => $data,
		);
	}

	/**
	 * Get normalized site URL (without protocol and www).
	 *
	 * @return string Normalized URL.
	 */
	private function get_normalized_site_url() {
		$url = home_url();
		$url = preg_replace( '#^https?://#', '', $url );
		$url = preg_replace( '#^www\.#', '', $url );
		$url = rtrim( $url, '/' );
		return $url;
	}

	/**
	 * Clear all cached API data.
	 *
	 * @return void
	 */
	public function clear_cache() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				'_transient_atomicedge_%',
				'_transient_timeout_atomicedge_%'
			)
		);
	}

	/**
	 * Validate an IP address or CIDR range.
	 *
	 * @param string $ip IP address or CIDR.
	 * @return bool True if valid.
	 */
	public function is_valid_ip( $ip ) {
		// Check for CIDR notation.
		if ( strpos( $ip, '/' ) !== false ) {
			list( $ip_part, $mask ) = explode( '/', $ip );

			// Validate IP part.
			if ( ! filter_var( $ip_part, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			// Validate mask.
			$mask = (int) $mask;
			if ( filter_var( $ip_part, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return $mask >= 0 && $mask <= 32;
			} else {
				return $mask >= 0 && $mask <= 128;
			}
		}

		return (bool) filter_var( $ip, FILTER_VALIDATE_IP );
	}
}
