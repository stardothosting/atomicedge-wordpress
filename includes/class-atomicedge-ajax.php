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

		// Vulnerability Scanner.
		add_action( 'wp_ajax_atomicedge_run_vulnerability_scan', array( $this, 'ajax_run_vulnerability_scan' ) );
		add_action( 'wp_ajax_atomicedge_get_vulnerability_results', array( $this, 'ajax_get_vulnerability_results' ) );
		add_action( 'wp_ajax_atomicedge_reset_vulnerability_results', array( $this, 'ajax_reset_vulnerability_results' ) );

		// CDN.
		add_action( 'wp_ajax_atomicedge_get_cdn_status', array( $this, 'ajax_get_cdn_status' ) );
		add_action( 'wp_ajax_atomicedge_refresh_cdn_status', array( $this, 'ajax_refresh_cdn_status' ) );
		add_action( 'wp_ajax_atomicedge_purge_cdn_cache', array( $this, 'ajax_purge_cdn_cache' ) );
		add_action( 'wp_ajax_atomicedge_update_cdn_settings', array( $this, 'ajax_update_cdn_settings' ) );

		// Cache.
		add_action( 'wp_ajax_atomicedge_clear_cache', array( $this, 'ajax_clear_cache' ) );
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
		$this->get_verified_post_fields( array() );

		$result = $this->api->get_ip_rules();

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
		$state = $scanner->step_resumable_scan( $run_id, 8 );

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

		if ( ! $vuln_scanner->is_available() ) {
			wp_send_json_error( array(
				'message' => __( 'Vulnerability scanning requires an Atomic Edge API connection. Please connect your site in the Settings page.', 'atomic-edge-security' ),
				'need_connection' => true,
			) );
		}

		$force_refresh = isset( $post['force_refresh'] ) && 'true' === sanitize_text_field( $post['force_refresh'] );
		$results = $vuln_scanner->run_full_scan( $force_refresh );

		if ( isset( $results['error'] ) ) {
			wp_send_json_error( array( 'message' => $results['error'] ) );
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

		$result = $this->api->get_cdn_status();

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

			wp_send_json_success( array(
				'message'     => __( 'CDN status refreshed.', 'atomic-edge-security' ),
				'cdn_enabled' => $site_data['cdn_enabled'] ?? false,
			) );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ?? __( 'Failed to fetch CDN status.', 'atomic-edge-security' ) ) );
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

		// Build settings array from provided values.
		$settings = array();

		if ( isset( $post['brotli'] ) ) {
			$settings['brotli'] = 'true' === $post['brotli'] || '1' === $post['brotli'];
		}
		if ( isset( $post['js_minification'] ) ) {
			$settings['js_minification'] = 'true' === $post['js_minification'] || '1' === $post['js_minification'];
		}
		if ( isset( $post['css_minification'] ) ) {
			$settings['css_minification'] = 'true' === $post['css_minification'] || '1' === $post['css_minification'];
		}
		if ( isset( $post['image_optimization'] ) ) {
			$settings['image_optimization'] = 'true' === $post['image_optimization'] || '1' === $post['image_optimization'];
		}

		if ( empty( $settings ) ) {
			wp_send_json_error( array( 'message' => __( 'No settings provided.', 'atomic-edge-security' ) ) );
		}

		$result = $this->api->update_cdn_settings( $settings );

		if ( $result['success'] ) {
			wp_send_json_success( array(
				'message' => __( 'CDN settings updated successfully.', 'atomic-edge-security' ),
			) );
		} else {
			wp_send_json_error( array( 'message' => $result['error'] ) );
		}
	}
}
