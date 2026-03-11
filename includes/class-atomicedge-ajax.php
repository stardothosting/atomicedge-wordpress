<?php
/**
 * AtomicEdge AJAX Handlers
 *
 * Handles all AJAX requests from the admin interface.
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_Ajax
 *
 * Manages AJAX request handling.
 */
class AtomicEdge_Ajax {

	/**
	 * API client instance.
	 *
	 * @var AtomicEdge_API
	 */
	private $api;

	/**
	 * Constructor.
	 *
	 * @param AtomicEdge_API $api API client instance.
	 */
	public function __construct( AtomicEdge_API $api ) {
		$this->api = $api;
		$this->init_hooks();
	}

	/**
	 * Initialize AJAX hooks.
	 *
	 * @return void
	 */
	private function init_hooks() {
		// Analytics.
		add_action( 'wp_ajax_atomicedge_get_analytics', array( $this, 'ajax_get_analytics' ) );

		// WAF Logs.
		add_action( 'wp_ajax_atomicedge_get_waf_logs', array( $this, 'ajax_get_waf_logs' ) );

		// IP Management.
		add_action( 'wp_ajax_atomicedge_get_ip_rules', array( $this, 'ajax_get_ip_rules' ) );
		add_action( 'wp_ajax_atomicedge_add_ip_whitelist', array( $this, 'ajax_add_ip_whitelist' ) );
		add_action( 'wp_ajax_atomicedge_add_ip_blacklist', array( $this, 'ajax_add_ip_blacklist' ) );
		add_action( 'wp_ajax_atomicedge_remove_ip', array( $this, 'ajax_remove_ip' ) );

		// Geographic Access.
		add_action( 'wp_ajax_atomicedge_get_geo_rules', array( $this, 'ajax_get_geo_rules' ) );
		add_action( 'wp_ajax_atomicedge_update_geo_rules', array( $this, 'ajax_update_geo_rules' ) );

		// Scanner.
		add_action( 'wp_ajax_atomicedge_run_scan', array( $this, 'ajax_run_scan' ) );
		add_action( 'wp_ajax_atomicedge_scan_step', array( $this, 'ajax_scan_step' ) );
		add_action( 'wp_ajax_atomicedge_scan_status', array( $this, 'ajax_scan_status' ) );
		add_action( 'wp_ajax_atomicedge_get_scan_results', array( $this, 'ajax_get_scan_results' ) );
		add_action( 'wp_ajax_atomicedge_cancel_scan', array( $this, 'ajax_cancel_scan' ) );
		add_action( 'wp_ajax_atomicedge_reset_scan', array( $this, 'ajax_reset_scan' ) );
		add_action( 'wp_ajax_atomicedge_scan_debug_test', array( $this, 'ajax_scan_debug_test' ) );

		// Vulnerability Scanner.
		add_action( 'wp_ajax_atomicedge_run_vulnerability_scan', array( $this, 'ajax_run_vulnerability_scan' ) );
		add_action( 'wp_ajax_atomicedge_get_vulnerability_results', array( $this, 'ajax_get_vulnerability_results' ) );
		add_action( 'wp_ajax_atomicedge_reset_vulnerability_results', array( $this, 'ajax_reset_vulnerability_results' ) );

		// CDN.
		add_action( 'wp_ajax_atomicedge_get_cdn_status', array( $this, 'ajax_get_cdn_status' ) );
		add_action( 'wp_ajax_atomicedge_refresh_cdn_status', array( $this, 'ajax_refresh_cdn_status' ) );
		add_action( 'wp_ajax_atomicedge_purge_cdn_cache', array( $this, 'ajax_purge_cdn_cache' ) );
		add_action( 'wp_ajax_atomicedge_update_cdn_settings', array( $this, 'ajax_update_cdn_settings' ) );
		add_action( 'wp_ajax_atomicedge_save_cdn_settings', array( $this, 'ajax_save_cdn_settings' ) );
		add_action( 'wp_ajax_atomicedge_clear_minify_cache', array( $this, 'ajax_clear_minify_cache' ) );

		// Cache.
		add_action( 'wp_ajax_atomicedge_clear_cache', array( $this, 'ajax_clear_cache' ) );

		// Two-Factor Authentication.
		add_action( 'wp_ajax_atomicedge_2fa_start_enrollment', array( $this, 'ajax_2fa_start_enrollment' ) );
		add_action( 'wp_ajax_atomicedge_2fa_verify_enrollment', array( $this, 'ajax_2fa_verify_enrollment' ) );
		add_action( 'wp_ajax_atomicedge_2fa_cancel_enrollment', array( $this, 'ajax_2fa_cancel_enrollment' ) );
		add_action( 'wp_ajax_atomicedge_2fa_disable', array( $this, 'ajax_2fa_disable' ) );
		add_action( 'wp_ajax_atomicedge_2fa_regenerate_codes', array( $this, 'ajax_2fa_regenerate_codes' ) );
		add_action( 'wp_ajax_atomicedge_2fa_get_status', array( $this, 'ajax_2fa_get_status' ) );

		// Adaptive Defense.
		add_action( 'wp_ajax_atomicedge_get_adaptive_defense', array( $this, 'ajax_get_adaptive_defense' ) );
		add_action( 'wp_ajax_atomicedge_get_actor_profiles', array( $this, 'ajax_get_actor_profiles' ) );
		add_action( 'wp_ajax_atomicedge_get_threat_detections', array( $this, 'ajax_get_threat_detections' ) );
		add_action( 'wp_ajax_atomicedge_get_threat_detection_detail', array( $this, 'ajax_get_threat_detection_detail' ) );
		add_action( 'wp_ajax_atomicedge_block_ip', array( $this, 'ajax_block_ip' ) );
		add_action( 'wp_ajax_atomicedge_unblock_ip', array( $this, 'ajax_unblock_ip' ) );
		add_action( 'wp_ajax_atomicedge_extend_block', array( $this, 'ajax_extend_block' ) );
		add_action( 'wp_ajax_atomicedge_make_permanent', array( $this, 'ajax_make_permanent' ) );
		add_action( 'wp_ajax_atomicedge_delete_actor', array( $this, 'ajax_delete_actor' ) );
		add_action( 'wp_ajax_atomicedge_dismiss_detection', array( $this, 'ajax_dismiss_detection' ) );
	}

	/**
	 * Verify AJAX request and return sanitized POST fields.
	 *
	 * NOTE: All values are sanitized at point of retrieval per WordPress Plugin Review
	 * requirements. Values are returned as sanitized strings (text fields) by default.
	 * Array values are recursively sanitized as text fields.
	 *
	 * @param array $allowed_keys Allowed POST keys to return.
	 * @return array Verified, sanitized POST data.
	 */
	private function get_verified_post_fields( array $allowed_keys ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized immediately after isset check.
		$nonce = isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '';
		if ( ! $nonce || ! wp_verify_nonce( $nonce, 'atomicedge_ajax' ) ) {
			wp_send_json_error( array( 'message' => __( 'Security check failed.', 'atomic-edge-security' ) ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission to perform this action.', 'atomic-edge-security' ) ) );
		}

		$post = array();
		foreach ( $allowed_keys as $key ) {
			if ( isset( $_POST[ $key ] ) ) {
				// Sanitize at point of retrieval per WordPress Plugin Review requirements.
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized recursively below.
				$raw_value = wp_unslash( $_POST[ $key ] );
				$post[ $key ] = $this->sanitize_post_value( $raw_value );
			}
		}

		return $post;
	}

	/**
	 * Recursively sanitize a POST value.
	 *
	 * Handles both scalar values and arrays per WordPress Plugin Review requirements.
	 *
	 * @param mixed $value The value to sanitize.
	 * @return mixed Sanitized value (string or array of strings).
	 */
	private function sanitize_post_value( $value ) {
		if ( is_array( $value ) ) {
			return array_map( array( $this, 'sanitize_post_value' ), $value );
		}
		return sanitize_text_field( (string) $value );
	}

	/**
	 * Sanitize and normalize a URL, ensuring it has a proper scheme.
	 *
	 * Simple approach: if URL doesn't start with http:// or https://, add the default scheme.
	 * Then let esc_url_raw() handle validation.
	 *
	 * @param string $url            The URL to sanitize.
	 * @param string $default_scheme Default scheme to use ('http' or 'https').
	 * @return string Sanitized URL with proper scheme.
	 */
	private function sanitize_url_with_scheme( $url, $default_scheme = 'https' ) {
		$url = trim( $url );

		if ( empty( $url ) ) {
			return '';
		}

		// Only add scheme if URL doesn't already have http:// or https://.
		if ( ! preg_match( '#^https?://#i', $url ) ) {
			$url = $default_scheme . '://' . $url;
		}

		return esc_url_raw( $url );
	}

	/**
	 * Get analytics data via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_analytics() {
		$post = $this->get_verified_post_fields( array( 'period' ) );

		$period = isset( $post['period'] ) ? sanitize_text_field( $post['period'] ) : '24h';

		// Validate period.
		$valid_periods = array( '24h', '7d', '30d' );
		if ( ! in_array( $period, $valid_periods, true ) ) {
			$period = '24h';
		}

		$result = $this->api->get_analytics( $period );

		if ( $result['success'] ) {
			wp_send_json_success( $result['data'] );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Get WAF logs via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_waf_logs() {
		$post = $this->get_verified_post_fields( array( 'page', 'per_page', 'search' ) );

		$args = array(
			'page'     => isset( $post['page'] ) ? absint( $post['page'] ) : 1,
			'per_page' => isset( $post['per_page'] ) ? absint( $post['per_page'] ) : 50,
			'search'   => isset( $post['search'] ) ? sanitize_text_field( $post['search'] ) : '',
		);

		// Validate per_page.
		if ( $args['per_page'] < 1 || $args['per_page'] > 100 ) {
			$args['per_page'] = 50;
		}

		$result = $this->api->get_waf_logs( $args );

		if ( $result['success'] ) {
			wp_send_json_success( $result['data'] );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Get IP rules via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_ip_rules() {
		$post = $this->get_verified_post_fields( array( 'force_refresh' ) );

		$force_refresh = ! empty( $post['force_refresh'] ) && 'true' === $post['force_refresh'];
		$result        = $this->api->get_ip_rules( $force_refresh );

		if ( $result['success'] ) {
			wp_send_json_success( $result['data'] );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Add IP to whitelist via AJAX.
	 *
	 * @return void
	 */
	public function ajax_add_ip_whitelist() {
		$post = $this->get_verified_post_fields( array( 'ip', 'description' ) );

		$ip          = isset( $post['ip'] ) ? sanitize_text_field( $post['ip'] ) : '';
		$description = isset( $post['description'] ) ? sanitize_text_field( $post['description'] ) : '';

		// Validate IP.
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Please enter an IP address.', 'atomic-edge-security' ) ) );
		}

		if ( ! $this->api->is_valid_ip( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address or CIDR range.', 'atomic-edge-security' ) ) );
		}

		$result = $this->api->add_ip_whitelist( $ip, $description );

		if ( $result['success'] ) {
			wp_send_json_success( array( 'message' => __( 'IP added to whitelist successfully.', 'atomic-edge-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Add IP to blacklist via AJAX.
	 *
	 * @return void
	 */
	public function ajax_add_ip_blacklist() {
		$post = $this->get_verified_post_fields( array( 'ip', 'description' ) );

		$ip          = isset( $post['ip'] ) ? sanitize_text_field( $post['ip'] ) : '';
		$description = isset( $post['description'] ) ? sanitize_text_field( $post['description'] ) : '';

		// Validate IP.
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Please enter an IP address.', 'atomic-edge-security' ) ) );
		}

		if ( ! $this->api->is_valid_ip( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address or CIDR range.', 'atomic-edge-security' ) ) );
		}

		$result = $this->api->add_ip_blacklist( $ip, $description );

		if ( $result['success'] ) {
			wp_send_json_success( array( 'message' => __( 'IP added to blacklist successfully.', 'atomic-edge-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Remove IP from whitelist or blacklist via AJAX.
	 *
	 * @return void
	 */
	public function ajax_remove_ip() {
		$post = $this->get_verified_post_fields( array( 'ip', 'type' ) );

		$ip   = isset( $post['ip'] ) ? sanitize_text_field( $post['ip'] ) : '';
		$type = isset( $post['type'] ) ? sanitize_key( $post['type'] ) : '';

		// Validate inputs.
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'atomic-edge-security' ) ) );
		}

		if ( ! in_array( $type, array( 'whitelist', 'blacklist' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid list type.', 'atomic-edge-security' ) ) );
		}

		$result = $this->api->remove_ip( $ip, $type );

		if ( $result['success'] ) {
			wp_send_json_success( array( 'message' => __( 'IP removed successfully.', 'atomic-edge-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Get geographic rules via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_geo_rules() {
		$this->get_verified_post_fields( array() );

		$result = $this->api->get_geo_rules();

		if ( $result['success'] ) {
			wp_send_json_success( $result['data'] );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Update geographic rules via AJAX.
	 *
	 * @return void
	 */
	public function ajax_update_geo_rules() {
		$post = $this->get_verified_post_fields( array( 'enabled', 'mode', 'countries' ) );

		// Get and validate rules (values are already sanitized by get_verified_post_fields).
		$enabled   = isset( $post['enabled'] ) && 'true' === $post['enabled'];
		$mode      = isset( $post['mode'] ) ? sanitize_key( $post['mode'] ) : 'blacklist';
		$countries = isset( $post['countries'] ) && is_array( $post['countries'] ) ? $post['countries'] : array();

		// Validate mode.
		if ( ! in_array( $mode, array( 'whitelist', 'blacklist' ), true ) ) {
			$mode = 'blacklist';
		}

		// Validate country codes (ISO 3166-1 alpha-2).
		$valid_countries = array();
		foreach ( $countries as $country ) {
			if ( preg_match( '/^[A-Z]{2}$/', $country ) ) {
				$valid_countries[] = $country;
			}
		}

		$rules = array(
			'enabled'   => $enabled,
			'mode'      => $mode,
			'countries' => $valid_countries,
		);

		$result = $this->api->update_geo_rules( $rules );

		if ( $result['success'] ) {
			wp_send_json_success( array( 'message' => __( 'Geographic rules updated successfully.', 'atomic-edge-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Run malware scan via AJAX.
	 *
	 * @return void
	 */
	public function ajax_run_scan() {
		$post = $this->get_verified_post_fields( array( 'scan_mode', 'verify_integrity' ) );

		$scan_mode = isset( $post['scan_mode'] ) ? sanitize_key( $post['scan_mode'] ) : 'all';
		if ( ! in_array( $scan_mode, array( 'php', 'all' ), true ) ) {
			$scan_mode = 'all';
		}

		$verify_integrity = ! empty( $post['verify_integrity'] );

		// Get scanner instance.
		$scanner = AtomicEdge::get_instance()->scanner;
		$state = $scanner->start_resumable_scan( $scan_mode, array( 'verify_integrity' => (bool) $verify_integrity ) );
		wp_send_json_success( $state );
	}

	/**
	 * Run a single scan step via AJAX.
	 *
	 * @return void
	 */
	public function ajax_scan_step() {
		$post = $this->get_verified_post_fields( array( 'run_id' ) );

		$run_id = isset( $post['run_id'] ) ? sanitize_text_field( $post['run_id'] ) : '';

		$scanner = AtomicEdge::get_instance()->scanner;
		// Pass 0 to auto-detect optimal time budget based on server config.
		$state = $scanner->step_resumable_scan( $run_id, 0 );

		if ( isset( $state['status'] ) && 'complete' === $state['status'] ) {
			// Fire completion hook with the saved final results.
			$results = get_option( 'atomicedge_scan_results', array() );
			do_action( 'atomicedge_scan_completed', $results );
		}

		wp_send_json_success( $state );
	}

	/**
	 * Get scan status via AJAX.
	 *
	 * @return void
	 */
	public function ajax_scan_status() {
		$post = $this->get_verified_post_fields( array( 'run_id' ) );

		$run_id = isset( $post['run_id'] ) ? sanitize_text_field( $post['run_id'] ) : '';
		$scanner = AtomicEdge::get_instance()->scanner;
		$state = $scanner->get_resumable_scan_status( $run_id );
		wp_send_json_success( $state );
	}

	/**
	 * Get last scan results via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_scan_results() {
		$this->get_verified_post_fields( array() );

		$results = get_option( 'atomicedge_scan_results', array() );
		wp_send_json_success( $results );
	}

	/**
	 * Cancel an in-progress resumable scan.
	 *
	 * @return void
	 */
	public function ajax_cancel_scan() {
		$post = $this->get_verified_post_fields( array( 'run_id' ) );

		$run_id = isset( $post['run_id'] ) ? sanitize_text_field( $post['run_id'] ) : '';
		$scanner = AtomicEdge::get_instance()->scanner;
		$state = $scanner->cancel_resumable_scan( $run_id );
		wp_send_json_success( $state );
	}

	/**
	 * Reset/clear the resumable scan state/cache so a new scan starts fresh.
	 *
	 * @return void
	 */
	public function ajax_reset_scan() {
		$this->get_verified_post_fields( array() );

		$scanner = AtomicEdge::get_instance()->scanner;
		$state = $scanner->reset_resumable_scan();
		wp_send_json_success( $state );
	}

	/**
	 * Run a quick debug test scan (limited files) for development.
	 *
	 * Only available when WP_DEBUG is true. Runs a real scan on 500 files
	 * to test performance without waiting for 30,000+ files.
	 *
	 * @return void
	 */
	public function ajax_scan_debug_test() {
		$this->get_verified_post_fields( array() );

		// Only allow in debug mode.
		if ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) {
			wp_send_json_error( array( 'message' => 'Debug mode not enabled' ) );
		}

		$scanner = AtomicEdge::get_instance()->scanner;
		$results = $scanner->run_debug_test( 500 );

		wp_send_json_success( $results );
	}

	/**
	 * Clear API cache via AJAX.
	 *
	 * @return void
	 */
	public function ajax_clear_cache() {
		$this->get_verified_post_fields( array() );

		$this->api->clear_cache();

		wp_send_json_success( array( 'message' => __( 'Cache cleared successfully.', 'atomic-edge-security' ) ) );
	}

	/**
	 * Run vulnerability scan via AJAX.
	 *
	 * @return void
	 */
	public function ajax_run_vulnerability_scan() {
		$post = $this->get_verified_post_fields( array( 'force_refresh' ) );

		$vuln_scanner = AtomicEdge::get_instance()->vulnerability_scanner;

		$force_refresh = isset( $post['force_refresh'] ) && 'true' === sanitize_text_field( $post['force_refresh'] );
		$results = $vuln_scanner->run_full_scan( $force_refresh );

		if ( isset( $results['error'] ) ) {
			$error_data = array( 'message' => $results['error'] );

			// Pass through rate limit flag so the JS can show a specific message.
			if ( ! empty( $results['rate_limited'] ) ) {
				$error_data['rate_limited'] = true;
			}

			wp_send_json_error( $error_data );
		}

		wp_send_json_success( $results );
	}

	/**
	 * Get last vulnerability scan results via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_vulnerability_results() {
		$this->get_verified_post_fields( array() );

		$vuln_scanner = AtomicEdge::get_instance()->vulnerability_scanner;
		$results = $vuln_scanner->get_last_results();
		$last_scan = $vuln_scanner->get_last_scan_time();

		wp_send_json_success( array(
			'results'   => $results,
			'last_scan' => $last_scan,
			'available' => $vuln_scanner->is_available(),
		) );
	}

	/**
	 * Reset vulnerability scan results via AJAX.
	 *
	 * @return void
	 */
	public function ajax_reset_vulnerability_results() {
		$this->get_verified_post_fields( array() );

		$vuln_scanner = AtomicEdge::get_instance()->vulnerability_scanner;
		$state        = $vuln_scanner->reset_results();
		wp_send_json_success( $state );
	}

	/**
	 * Get CDN status via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_cdn_status() {
		$this->get_verified_post_fields( array() );

		$result = $this->api->get_cdn_status();

		if ( $result['success'] ) {
			wp_send_json_success( $result['data'] );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Refresh CDN status and update stored site data.
	 *
	 * This fetches the latest CDN status from the API and updates
	 * the locally stored site data with any CDN configuration changes.
	 *
	 * @return void
	 */
	public function ajax_refresh_cdn_status() {
		$this->get_verified_post_fields( array() );

		// Clear CDN status cache to force fresh API call.
		delete_transient( 'atomicedge_cdn_status' );

		$result = $this->api->get_cdn_status();

		// Debug: Log the API response.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( 'AtomicEdge CDN refresh result: ' . wp_json_encode( $result ) );
		}

		if ( $result['success'] ) {
			// Update stored site data with CDN information.
			$site_data = get_option( 'atomicedge_site_data', array() );

			// Merge CDN-related fields from API response.
			if ( isset( $result['data']['cdn_enabled'] ) ) {
				$site_data['cdn_enabled'] = (bool) $result['data']['cdn_enabled'];
			}
			if ( isset( $result['data']['cdn_prefix'] ) ) {
				$site_data['cdn_prefix'] = sanitize_text_field( $result['data']['cdn_prefix'] );
			}
			if ( isset( $result['data']['cdn_url'] ) ) {
				$site_data['cdn_url'] = esc_url_raw( $result['data']['cdn_url'] );
			}

			update_option( 'atomicedge_site_data', $site_data );

			// Sync edge-side optimization settings from API to local WP options.
			// Note: js_minification and css_minification are plugin-local only, not synced.
			if ( isset( $result['data']['optimization'] ) ) {
				$optimization = $result['data']['optimization'];
				if ( isset( $optimization['brotli'] ) ) {
					update_option( 'atomicedge_cdn_brotli', (bool) $optimization['brotli'] );
				}
				if ( isset( $optimization['image_optimization'] ) ) {
					update_option( 'atomicedge_cdn_image_optimization', (bool) $optimization['image_optimization'] );
				}
			}

			wp_send_json_success( array(
				'message'     => __( 'CDN status refreshed.', 'atomic-edge-security' ),
				'cdn_enabled' => $site_data['cdn_enabled'] ?? false,
				'optimization' => $result['data']['optimization'] ?? array(),
				'debug'       => defined( 'WP_DEBUG' ) && WP_DEBUG ? $result : null,
			) );
		} else {
			$error_message = isset( $result['error'] ) ? $result['error'] : __( 'Failed to fetch CDN status.', 'atomic-edge-security' );
			wp_send_json_error( array(
				'message' => $error_message,
				'debug'   => defined( 'WP_DEBUG' ) && WP_DEBUG ? $result : null,
			) );
		}
	}

	/**
	 * Purge CDN cache via AJAX.
	 *
	 * @return void
	 */
	public function ajax_purge_cdn_cache() {
		$this->get_verified_post_fields( array() );

		$result = $this->api->purge_cdn_cache();

		if ( $result['success'] ) {
			wp_send_json_success( array(
				'message'   => isset( $result['data']['message'] ) ? $result['data']['message'] : __( 'Cache purge has been queued.', 'atomic-edge-security' ),
				'purged_at' => isset( $result['data']['purged_at'] ) ? $result['data']['purged_at'] : gmdate( 'c' ),
			) );
		} else {
			$error_message = isset( $result['error'] ) ? $result['error'] : __( 'Failed to purge cache.', 'atomic-edge-security' );
			// Handle specific error codes.
			if ( isset( $result['data']['error'] ) ) {
				switch ( $result['data']['error'] ) {
					case 'cdn_disabled':
						$error_message = __( 'CDN is not enabled for this site.', 'atomic-edge-security' );
						break;
					case 'no_cdn_prefix':
						$error_message = __( 'CDN is not configured for this site.', 'atomic-edge-security' );
						break;
					case 'cooldown_active':
						$error_message = __( 'Please wait a few minutes between purge requests.', 'atomic-edge-security' );
						break;
				}
			}
			wp_send_json_error( array( 'message' => $error_message ) );
		}
	}

	/**
	 * Update CDN settings via AJAX.
	 *
	 * @return void
	 */
	public function ajax_update_cdn_settings() {
		$post = $this->get_verified_post_fields( array( 'brotli', 'js_minification', 'css_minification', 'image_optimization' ) );

		// JS/CSS minification are plugin-local only - save to WP options but don't sync to API.
		if ( isset( $post['js_minification'] ) ) {
			update_option( 'atomicedge_cdn_js_minification', 'true' === $post['js_minification'] || '1' === $post['js_minification'] );
		}
		if ( isset( $post['css_minification'] ) ) {
			update_option( 'atomicedge_cdn_css_minification', 'true' === $post['css_minification'] || '1' === $post['css_minification'] );
		}

		// Build settings array for API - only edge-side settings (brotli, image_optimization).
		// JS/CSS minification are already saved to local WP options above.
		$settings = array();

		if ( isset( $post['brotli'] ) ) {
			$settings['brotli'] = 'true' === $post['brotli'] || '1' === $post['brotli'];
		}
		if ( isset( $post['image_optimization'] ) ) {
			$settings['image_optimization'] = 'true' === $post['image_optimization'] || '1' === $post['image_optimization'];
		}

		if ( empty( $settings ) ) {
			wp_send_json_error( array( 'message' => __( 'No settings provided.', 'atomic-edge-security' ) ) );
		}

		$result = $this->api->update_cdn_settings( $settings );

		if ( $result['success'] ) {
			// Sync edge-side settings to local WP options for page display.
			if ( isset( $settings['brotli'] ) ) {
				update_option( 'atomicedge_cdn_brotli', $settings['brotli'] );
			}
			if ( isset( $settings['image_optimization'] ) ) {
				update_option( 'atomicedge_cdn_image_optimization', $settings['image_optimization'] );
			}

			wp_send_json_success( array(
				'message' => __( 'CDN settings updated successfully.', 'atomic-edge-security' ),
			) );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}

	/**
	 * Save CDN settings from the tabbed settings form.
	 *
	 * Handles all CDN settings across General, Minification, and Advanced tabs.
	 *
	 * @return void
	 */
	public function ajax_save_cdn_settings() {
		$post = $this->get_verified_post_fields( array( 'formData' ) );

		if ( empty( $post['formData'] ) ) {
			wp_send_json_error( array( 'message' => __( 'No form data provided.', 'atomic-edge-security' ) ) );
		}

		// Parse the serialized form data.
		parse_str( $post['formData'], $form_data );

		// DEBUG: Log raw form data to trace corruption.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log( 'AtomicEdge CDN Save - Raw formData: ' . $post['formData'] );
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log, WordPress.PHP.DevelopmentFunctions.error_log_print_r
		error_log( 'AtomicEdge CDN Save - Parsed form_data: ' . print_r( $form_data, true ) );

		// Verify nonce from form data.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Already sanitized by get_verified_post_fields.
		$form_nonce = isset( $form_data['atomicedge_cdn_nonce'] ) ? sanitize_text_field( $form_data['atomicedge_cdn_nonce'] ) : '';
		if ( ! wp_verify_nonce( $form_nonce, 'atomicedge_cdn_settings' ) ) {
			wp_send_json_error( array( 'message' => __( 'Security check failed.', 'atomic-edge-security' ) ) );
		}

		// General tab settings.
		$cdn_local_enabled = isset( $form_data['atomicedge_cdn_local_enabled'] ) && 'on' === $form_data['atomicedge_cdn_local_enabled'];
		update_option( 'atomicedge_cdn_local_enabled', $cdn_local_enabled ? 'on' : 'off' );

		// File type settings.
		$cdn_css = isset( $form_data['atomicedge_cdn_css'] ) && 'on' === $form_data['atomicedge_cdn_css'];
		update_option( 'atomicedge_cdn_css', $cdn_css ? 'on' : 'off' );

		$cdn_js = isset( $form_data['atomicedge_cdn_js'] ) && 'on' === $form_data['atomicedge_cdn_js'];
		update_option( 'atomicedge_cdn_js', $cdn_js ? 'on' : 'off' );

		$cdn_media = isset( $form_data['atomicedge_cdn_media'] ) && 'on' === $form_data['atomicedge_cdn_media'];
		update_option( 'atomicedge_cdn_media', $cdn_media ? 'on' : 'off' );

		// Note: CDN URL comes from dashboard - no user-configurable URL needed.

		// Minification tab settings.
		$minify_css = isset( $form_data['atomicedge_cdn_minify_css'] ) && 'on' === $form_data['atomicedge_cdn_minify_css'];
		update_option( 'atomicedge_cdn_minify_css', $minify_css ? 'on' : 'off' );

		$minify_js = isset( $form_data['atomicedge_cdn_minify_js'] ) && 'on' === $form_data['atomicedge_cdn_minify_js'];
		update_option( 'atomicedge_cdn_minify_js', $minify_js ? 'on' : 'off' );

		$minify_html = isset( $form_data['atomicedge_cdn_minify_html'] ) && 'on' === $form_data['atomicedge_cdn_minify_html'];
		update_option( 'atomicedge_cdn_minify_html', $minify_html ? 'on' : 'off' );

		// Advanced tab settings.
		if ( isset( $form_data['atomicedge_cdn_reject_files'] ) ) {
			$reject_files = sanitize_textarea_field( $form_data['atomicedge_cdn_reject_files'] );
			update_option( 'atomicedge_cdn_reject_files', $reject_files );
		}

		$dns_prefetch = isset( $form_data['atomicedge_cdn_dns_prefetch'] ) && 'on' === $form_data['atomicedge_cdn_dns_prefetch'];
		update_option( 'atomicedge_cdn_dns_prefetch', $dns_prefetch ? 'on' : 'off' );

		wp_send_json_success( array(
			'message' => __( 'CDN settings saved successfully.', 'atomic-edge-security' ),
		) );
	}

	/**
	 * Clear the minification cache via AJAX.
	 *
	 * @return void
	 */
	public function ajax_clear_minify_cache() {
		$this->get_verified_post_fields( array() );

		// Check if CDN class is available.
		if ( ! class_exists( 'AtomicEdge_CDN' ) ) {
			wp_send_json_error( array( 'message' => __( 'CDN module not available.', 'atomic-edge-security' ) ) );
		}

		$result = AtomicEdge_CDN::clear_minified_cache();

		if ( $result['success'] ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %d: Number of files deleted */
					__( 'Cleared %d cached files.', 'atomic-edge-security' ),
					$result['deleted']
				),
			) );
		} else {
			wp_send_json_error( array(
				'message' => $result['error'] ?? __( 'Failed to clear cache.', 'atomic-edge-security' ),
			) );
		}
	}

	/**
	 * Debug log helper - only logs when WP_DEBUG is true.
	 *
	 * @param string $message Log message.
	 * @return void
	 */
	private function debug_log( $message ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'AtomicEdge AJAX: ' . $message );
		}
	}

	/**
	 * Check whether Adaptive Defense handlers should use dev mode simulation.
	 *
	 * Dev mode provides simulated data for local development environments
	 * that have NO API key configured. If an API key exists (even when the
	 * `atomicedge_connected` flag is not set), the real API should be used.
	 *
	 * @return bool True if dev mode simulation should be used.
	 */
	private function should_use_dev_mode() {
		if ( ! \AtomicEdge_Dev_Mode::is_enabled() ) {
			return false;
		}

		// If an API key is configured, always use the real API.
		if ( $this->api->get_api_key() ) {
			return false;
		}

		return true;
	}

	// =========================================================================
	// Adaptive Defense AJAX Handlers
	// =========================================================================

	/**
	 * Get Adaptive Defense status and overview data.
	 *
	 * @return void
	 */
	public function ajax_get_adaptive_defense() {
		$post = $this->get_verified_post_fields( array( 'force_refresh' ) );

		// Dev mode: return simulated data (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( AtomicEdge_Dev_Mode::get_simulated_adaptive_defense() );
		}

		$force_refresh = ! empty( $post['force_refresh'] ) && 'true' === $post['force_refresh'];
		$response      = $this->api->get_adaptive_defense( $force_refresh );

		if ( $response['success'] ) {
			wp_send_json_success( $response['data'] );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to fetch Adaptive Defense data.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Get actor profiles (paginated).
	 *
	 * @return void
	 */
	public function ajax_get_actor_profiles() {
		$post = $this->get_verified_post_fields( array( 'page', 'per_page', 'filter', 'search', 'force_refresh' ) );

		$args = array(
			'page'     => isset( $post['page'] ) ? absint( $post['page'] ) : 1,
			'per_page' => isset( $post['per_page'] ) ? absint( $post['per_page'] ) : 25,
			'filter'   => isset( $post['filter'] ) ? $post['filter'] : 'all',
		);

		if ( ! empty( $post['search'] ) ) {
			$args['search'] = $post['search'];
		}

		// Dev mode: return simulated data (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( AtomicEdge_Dev_Mode::get_simulated_actor_profiles( $args ) );
		}

		$force_refresh = ! empty( $post['force_refresh'] ) && 'true' === $post['force_refresh'];
		$response      = $this->api->get_actor_profiles( $args, $force_refresh );

		if ( $response['success'] ) {
			wp_send_json_success( $response['data'] );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to fetch actor profiles.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Get threat detections (paginated).
	 *
	 * @return void
	 */
	public function ajax_get_threat_detections() {
		$post = $this->get_verified_post_fields( array( 'page', 'per_page', 'status', 'force_refresh' ) );

		$args = array(
			'page'     => isset( $post['page'] ) ? absint( $post['page'] ) : 1,
			'per_page' => isset( $post['per_page'] ) ? absint( $post['per_page'] ) : 25,
			'status'   => isset( $post['status'] ) ? $post['status'] : 'all',
		);

		// Dev mode: return simulated data (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( AtomicEdge_Dev_Mode::get_simulated_threat_detections( $args ) );
		}

		$force_refresh = ! empty( $post['force_refresh'] ) && 'true' === $post['force_refresh'];
		$response      = $this->api->get_threat_detections( $args, $force_refresh );

		if ( $response['success'] ) {
			wp_send_json_success( $response['data'] );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to fetch threat detections.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Get threat detection detail.
	 *
	 * @return void
	 */
	public function ajax_get_threat_detection_detail() {
		$post = $this->get_verified_post_fields( array( 'detection_id' ) );

		if ( empty( $post['detection_id'] ) ) {
			wp_send_json_error( array( 'message' => __( 'Detection ID is required.', 'atomic-edge-security' ) ) );
		}

		// Dev mode: return simulated detail data (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			$detail = AtomicEdge_Dev_Mode::get_simulated_threat_detection_detail( absint( $post['detection_id'] ) );
			if ( $detail ) {
				wp_send_json_success( $detail );
			}
			wp_send_json_error( array( 'message' => __( 'Detection not found.', 'atomic-edge-security' ) ) );
		}

		$response = $this->api->get_threat_detection_detail( absint( $post['detection_id'] ) );

		if ( $response['success'] ) {
			wp_send_json_success( $response['data'] );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to fetch detection details.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Block an IP address via Adaptive Defense.
	 *
	 * @return void
	 */
	public function ajax_block_ip() {
		$post = $this->get_verified_post_fields( array( 'ip', 'permanent', 'reason' ) );

		if ( empty( $post['ip'] ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'atomic-edge-security' ) ) );
		}

		$ip        = $post['ip'];
		$permanent = isset( $post['permanent'] ) && 'true' === $post['permanent'];
		$reason    = isset( $post['reason'] ) ? sanitize_text_field( $post['reason'] ) : '';

		// Dev mode: return simulated success (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %s: IP address */
					__( '[Dev Mode] IP address %s has been blocked.', 'atomic-edge-security' ),
					esc_html( $ip )
				),
				'data'    => AtomicEdge_Dev_Mode::simulate_block_ip( $ip ),
			) );
		}

		$response = $this->api->block_ip( $ip, $permanent, $reason );

		if ( $response['success'] ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %s: IP address */
					__( 'IP address %s has been blocked.', 'atomic-edge-security' ),
					esc_html( $ip )
				),
				'data'    => $response['data'] ?? array(),
			) );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to block IP address.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Unblock an IP address via Adaptive Defense.
	 *
	 * @return void
	 */
	public function ajax_unblock_ip() {
		$post = $this->get_verified_post_fields( array( 'ip' ) );

		if ( empty( $post['ip'] ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'atomic-edge-security' ) ) );
		}

		// Dev mode: return simulated success (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %s: IP address */
					__( '[Dev Mode] IP address %s has been unblocked.', 'atomic-edge-security' ),
					esc_html( $post['ip'] )
				),
			) );
		}

		$response = $this->api->unblock_ip( $post['ip'] );

		if ( $response['success'] ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %s: IP address */
					__( 'IP address %s has been unblocked.', 'atomic-edge-security' ),
					esc_html( $post['ip'] )
				),
			) );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to unblock IP address.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Extend the block duration for a blocked IP.
	 * Duration is server-authoritative (uses the site's configured auto_block_ttl_hours).
	 *
	 * @return void
	 */
	public function ajax_extend_block() {
		$post = $this->get_verified_post_fields( array( 'ip' ) );

		if ( empty( $post['ip'] ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'atomic-edge-security' ) ) );
		}

		$ip = $post['ip'];

		// Dev mode: return simulated success (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %s: IP address */
					__( '[Dev Mode] Block for %s has been extended.', 'atomic-edge-security' ),
					esc_html( $ip )
				),
				'data' => AtomicEdge_Dev_Mode::simulate_extend_block( $ip ),
			) );
		}

		$response = $this->api->extend_block( $ip );

		if ( $response['success'] ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %s: IP address */
					__( 'Block for %s has been extended.', 'atomic-edge-security' ),
					esc_html( $ip )
				),
				'data' => $response['data'] ?? array(),
			) );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to extend block.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Make a timed block permanent.
	 *
	 * @return void
	 */
	public function ajax_make_permanent() {
		$post = $this->get_verified_post_fields( array( 'ip' ) );

		if ( empty( $post['ip'] ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'atomic-edge-security' ) ) );
		}

		$ip = $post['ip'];

		// Dev mode: return simulated success (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %s: IP address */
					__( '[Dev Mode] Block for %s is now permanent.', 'atomic-edge-security' ),
					esc_html( $ip )
				),
				'data' => AtomicEdge_Dev_Mode::simulate_make_permanent( $ip ),
			) );
		}

		$response = $this->api->make_permanent( $ip );

		if ( $response['success'] ) {
			wp_send_json_success( array(
				'message' => sprintf(
					/* translators: %s: IP address */
					__( 'Block for %s is now permanent.', 'atomic-edge-security' ),
					esc_html( $ip )
				),
				'data' => $response['data'] ?? array(),
			) );
		} else {
			$error_data = array( 'message' => $response['error'] ?? __( 'Failed to make block permanent.', 'atomic-edge-security' ) );
			if ( ! empty( $response['error_code'] ) ) {
				$error_data['error_code'] = sanitize_text_field( $response['error_code'] );
			}
			wp_send_json_error( $error_data );
		}
	}

	/**
	 * Delete an actor profile.
	 *
	 * @return void
	 */
	public function ajax_delete_actor() {
		$post = $this->get_verified_post_fields( array( 'actor_id' ) );

		if ( empty( $post['actor_id'] ) ) {
			wp_send_json_error( array( 'message' => __( 'Actor ID is required.', 'atomic-edge-security' ) ) );
		}

		// Dev mode: return simulated success (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( array(
				'message' => __( '[Dev Mode] Actor profile has been deleted.', 'atomic-edge-security' ),
			) );
		}

		$response = $this->api->delete_actor_profile( absint( $post['actor_id'] ) );

		if ( $response['success'] ) {
			wp_send_json_success( array(
				'message' => __( 'Actor profile has been deleted.', 'atomic-edge-security' ),
			) );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to delete actor profile.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Dismiss a threat detection.
	 *
	 * @return void
	 */
	public function ajax_dismiss_detection() {
		$post = $this->get_verified_post_fields( array( 'detection_id' ) );

		if ( empty( $post['detection_id'] ) ) {
			wp_send_json_error( array( 'message' => __( 'Detection ID is required.', 'atomic-edge-security' ) ) );
		}

		// Dev mode: return simulated success (only when not connected to real API).
		if ( $this->should_use_dev_mode() ) {
			wp_send_json_success( array(
				'message' => __( '[Dev Mode] Threat detection has been dismissed.', 'atomic-edge-security' ),
			) );
		}

		$response = $this->api->dismiss_threat_detection( absint( $post['detection_id'] ) );

		if ( $response['success'] ) {
			wp_send_json_success( array(
				'message' => __( 'Threat detection has been dismissed.', 'atomic-edge-security' ),
			) );
		} else {
			wp_send_json_error( array( 'message' => $response['error'] ?? __( 'Failed to dismiss detection.', 'atomic-edge-security' ) ) );
		}
	}

	// =========================================================================
	// Two-Factor Authentication AJAX Handlers
	// =========================================================================

	/**
	 * Start 2FA enrollment via AJAX.
	 *
	 * @return void
	 */
	public function ajax_2fa_start_enrollment() {
		$this->debug_log( 'ajax_2fa_start_enrollment() called' );

		$this->verify_2fa_request();

		$user_id = $this->get_2fa_user_id();
		$this->debug_log( 'ajax_2fa_start_enrollment() user_id: ' . $user_id );

		// Check if encryption is available.
		$this->debug_log( 'ajax_2fa_start_enrollment() checking is_available...' );
		if ( ! AtomicEdge_2FA::is_available() ) {
			$this->debug_log( 'ajax_2fa_start_enrollment() FAILED: encryption not available' );
			wp_send_json_error( array(
				'message' => __( 'Two-factor authentication is not available. Your server may not support the required encryption features.', 'atomic-edge-security' ),
			) );
		}
		$this->debug_log( 'ajax_2fa_start_enrollment() encryption is available' );

		// Check if already enabled.
		if ( AtomicEdge_2FA::is_enabled_for_user( $user_id ) ) {
			$this->debug_log( 'ajax_2fa_start_enrollment() FAILED: already enabled' );
			wp_send_json_error( array(
				'message' => __( 'Two-factor authentication is already enabled.', 'atomic-edge-security' ),
			) );
		}

		// Start enrollment.
		$this->debug_log( 'ajax_2fa_start_enrollment() calling start_enrollment...' );
		$result = AtomicEdge_2FA::start_enrollment( $user_id );

		if ( is_wp_error( $result ) ) {
			$this->debug_log( 'ajax_2fa_start_enrollment() FAILED: ' . $result->get_error_code() . ' - ' . $result->get_error_message() );
			wp_send_json_error( array(
				'message' => $result->get_error_message(),
			) );
		}

		if ( ! $result ) {
			$this->debug_log( 'ajax_2fa_start_enrollment() FAILED: result was false/empty' );
			wp_send_json_error( array(
				'message' => __( 'Failed to start enrollment. Please try again.', 'atomic-edge-security' ),
			) );
		}

		$this->debug_log( 'ajax_2fa_start_enrollment() SUCCESS' );
		wp_send_json_success( array(
			'secret'           => $result['secret'],
			'provisioning_uri' => $result['provisioning_uri'],
		) );
	}

	/**
	 * Verify 2FA enrollment via AJAX.
	 *
	 * @return void
	 */
	public function ajax_2fa_verify_enrollment() {
		$this->verify_2fa_request();

		$user_id = $this->get_2fa_user_id();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in verify_2fa_request.
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';

		if ( empty( $code ) ) {
			wp_send_json_error( array(
				'message' => __( 'Please enter the verification code.', 'atomic-edge-security' ),
			) );
		}

		$result = AtomicEdge_2FA::complete_enrollment( $user_id, $code );

		if ( ! $result['success'] ) {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}

		// Format backup codes for display.
		$user = get_userdata( $user_id );
		$download_content = AtomicEdge_2FA_Backup::format_for_download(
			$result['backup_codes'],
			get_bloginfo( 'name' ),
			$user ? $user->user_login : ''
		);

		wp_send_json_success( array(
			'message'          => __( 'Two-factor authentication enabled successfully!', 'atomic-edge-security' ),
			'backup_codes'     => $result['backup_codes'],
			'download_content' => $download_content,
		) );
	}

	/**
	 * Cancel 2FA enrollment via AJAX.
	 *
	 * @return void
	 */
	public function ajax_2fa_cancel_enrollment() {
		$this->verify_2fa_request();

		$user_id = $this->get_2fa_user_id();

		AtomicEdge_2FA::cancel_enrollment( $user_id );

		wp_send_json_success( array(
			'message' => __( 'Enrollment cancelled.', 'atomic-edge-security' ),
		) );
	}

	/**
	 * Disable 2FA via AJAX.
	 *
	 * @return void
	 */
	public function ajax_2fa_disable() {
		$this->verify_2fa_request();

		$user_id = $this->get_2fa_user_id();

		// Require password confirmation for security.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in verify_2fa_request.
		$password = isset( $_POST['password'] ) ? wp_unslash( $_POST['password'] ) : '';

		if ( empty( $password ) ) {
			wp_send_json_error( array(
				'message' => __( 'Please enter your password to confirm.', 'atomic-edge-security' ),
			) );
		}

		// Verify password.
		$user = get_userdata( $user_id );
		if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user_id ) ) {
			wp_send_json_error( array(
				'message' => __( 'Incorrect password. Please try again.', 'atomic-edge-security' ),
			) );
		}

		AtomicEdge_2FA::disable( $user_id );

		wp_send_json_success( array(
			'message' => __( 'Two-factor authentication has been disabled.', 'atomic-edge-security' ),
		) );
	}

	/**
	 * Regenerate backup codes via AJAX.
	 *
	 * @return void
	 */
	public function ajax_2fa_regenerate_codes() {
		$this->verify_2fa_request();

		$user_id = $this->get_2fa_user_id();

		if ( ! AtomicEdge_2FA::is_enabled_for_user( $user_id ) ) {
			wp_send_json_error( array(
				'message' => __( 'Two-factor authentication is not enabled.', 'atomic-edge-security' ),
			) );
		}

		$codes = AtomicEdge_2FA::regenerate_backup_codes( $user_id );

		if ( ! $codes ) {
			wp_send_json_error( array(
				'message' => __( 'Failed to regenerate backup codes. Please try again.', 'atomic-edge-security' ),
			) );
		}

		// Format for download.
		$user = get_userdata( $user_id );
		$download_content = AtomicEdge_2FA_Backup::format_for_download(
			$codes,
			get_bloginfo( 'name' ),
			$user ? $user->user_login : ''
		);

		wp_send_json_success( array(
			'message'          => __( 'Backup codes regenerated. Please save your new codes.', 'atomic-edge-security' ),
			'backup_codes'     => $codes,
			'download_content' => $download_content,
		) );
	}

	/**
	 * Get 2FA status via AJAX.
	 *
	 * @return void
	 */
	public function ajax_2fa_get_status() {
		$this->verify_2fa_request();

		$user_id = $this->get_2fa_user_id();
		$status  = AtomicEdge_2FA::get_user_status( $user_id );

		wp_send_json_success( $status );
	}

	/**
	 * Verify 2FA AJAX request.
	 *
	 * @return void
	 */
	private function verify_2fa_request() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized immediately.
		$nonce = isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '';

		if ( ! $nonce || ! wp_verify_nonce( $nonce, 'atomicedge_2fa' ) ) {
			wp_send_json_error( array( 'message' => __( 'Security check failed.', 'atomic-edge-security' ) ) );
		}

		if ( ! current_user_can( 'read' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'atomic-edge-security' ) ) );
		}
	}

	/**
	 * Get the user ID for 2FA operations.
	 *
	 * @return int User ID.
	 */
	private function get_2fa_user_id() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in verify_2fa_request.
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();

		// Only allow admins to modify other users' 2FA.
		if ( $user_id !== get_current_user_id() && ! current_user_can( 'edit_users' ) ) {
			wp_send_json_error( array( 'message' => __( 'You cannot modify another user\'s settings.', 'atomic-edge-security' ) ) );
		}

		return $user_id;
	}
}
