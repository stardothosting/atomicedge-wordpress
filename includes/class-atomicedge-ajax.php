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
		add_action( 'wp_ajax_atomicedge_get_scan_results', array( $this, 'ajax_get_scan_results' ) );

		// Vulnerability Scanner.
		add_action( 'wp_ajax_atomicedge_run_vulnerability_scan', array( $this, 'ajax_run_vulnerability_scan' ) );
		add_action( 'wp_ajax_atomicedge_get_vulnerability_results', array( $this, 'ajax_get_vulnerability_results' ) );

		// Cache.
		add_action( 'wp_ajax_atomicedge_clear_cache', array( $this, 'ajax_clear_cache' ) );
	}

	/**
	 * Verify AJAX request and check capabilities.
	 *
	 * @return bool True if valid, sends JSON error and exits otherwise.
	 */
	private function verify_ajax_request() {
		// Verify nonce.
		if ( ! check_ajax_referer( 'atomicedge_ajax', 'nonce', false ) ) {
			wp_send_json_error( array( 'message' => __( 'Security check failed.', 'atomicedge' ) ) );
		}

		// Check capabilities.
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission to perform this action.', 'atomicedge' ) ) );
		}

		return true;
	}

	/**
	 * Get analytics data via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_analytics() {
		$this->verify_ajax_request();

		$period = isset( $_POST['period'] ) ? sanitize_text_field( wp_unslash( $_POST['period'] ) ) : '24h';

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
		$this->verify_ajax_request();

		$args = array(
			'page'     => isset( $_POST['page'] ) ? absint( $_POST['page'] ) : 1,
			'per_page' => isset( $_POST['per_page'] ) ? absint( $_POST['per_page'] ) : 50,
			'search'   => isset( $_POST['search'] ) ? sanitize_text_field( wp_unslash( $_POST['search'] ) ) : '',
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
		$this->verify_ajax_request();

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
		$this->verify_ajax_request();

		$ip          = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$description = isset( $_POST['description'] ) ? sanitize_text_field( wp_unslash( $_POST['description'] ) ) : '';

		// Validate IP.
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Please enter an IP address.', 'atomicedge' ) ) );
		}

		if ( ! $this->api->is_valid_ip( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address or CIDR range.', 'atomicedge' ) ) );
		}

		$result = $this->api->add_ip_whitelist( $ip, $description );

		if ( $result['success'] ) {
			wp_send_json_success( array( 'message' => __( 'IP added to whitelist successfully.', 'atomicedge' ) ) );
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
		$this->verify_ajax_request();

		$ip          = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$description = isset( $_POST['description'] ) ? sanitize_text_field( wp_unslash( $_POST['description'] ) ) : '';

		// Validate IP.
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Please enter an IP address.', 'atomicedge' ) ) );
		}

		if ( ! $this->api->is_valid_ip( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address or CIDR range.', 'atomicedge' ) ) );
		}

		$result = $this->api->add_ip_blacklist( $ip, $description );

		if ( $result['success'] ) {
			wp_send_json_success( array( 'message' => __( 'IP added to blacklist successfully.', 'atomicedge' ) ) );
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
		$this->verify_ajax_request();

		$ip   = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$type = isset( $_POST['type'] ) ? sanitize_key( wp_unslash( $_POST['type'] ) ) : '';

		// Validate inputs.
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'atomicedge' ) ) );
		}

		if ( ! in_array( $type, array( 'whitelist', 'blacklist' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid list type.', 'atomicedge' ) ) );
		}

		$result = $this->api->remove_ip( $ip, $type );

		if ( $result['success'] ) {
			wp_send_json_success( array( 'message' => __( 'IP removed successfully.', 'atomicedge' ) ) );
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
		$this->verify_ajax_request();

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
		$this->verify_ajax_request();

		// Get and validate rules.
		$enabled   = isset( $_POST['enabled'] ) && 'true' === sanitize_text_field( wp_unslash( $_POST['enabled'] ) );
		$mode      = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'blacklist';
		$countries = isset( $_POST['countries'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['countries'] ) ) : array();

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
			wp_send_json_success( array( 'message' => __( 'Geographic rules updated successfully.', 'atomicedge' ) ) );
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
		$this->verify_ajax_request();

		// Get scanner instance.
		$scanner = AtomicEdge::get_instance()->scanner;
		$results = $scanner->run_full_scan();

		if ( false === $results ) {
			wp_send_json_error( array( 'message' => __( 'Scan failed. Please try again.', 'atomicedge' ) ) );
		}

		// Fire action.
		do_action( 'atomicedge_scan_completed', $results );

		wp_send_json_success( $results );
	}

	/**
	 * Get last scan results via AJAX.
	 *
	 * @return void
	 */
	public function ajax_get_scan_results() {
		$this->verify_ajax_request();

		$results = get_option( 'atomicedge_scan_results', array() );
		wp_send_json_success( $results );
	}

	/**
	 * Clear API cache via AJAX.
	 *
	 * @return void
	 */
	public function ajax_clear_cache() {
		$this->verify_ajax_request();

		$this->api->clear_cache();

		wp_send_json_success( array( 'message' => __( 'Cache cleared successfully.', 'atomicedge' ) ) );
	}

	/**
	 * Run vulnerability scan via AJAX.
	 *
	 * @return void
	 */
	public function ajax_run_vulnerability_scan() {
		$this->verify_ajax_request();

		$vuln_scanner = AtomicEdge::get_instance()->vulnerability_scanner;

		if ( ! $vuln_scanner->is_available() ) {
			wp_send_json_error( array(
				'message' => __( 'Vulnerability scanning requires an Atomic Edge API connection. Please connect your site in the Settings page.', 'atomicedge' ),
				'need_connection' => true,
			) );
		}

		$force_refresh = isset( $_POST['force_refresh'] ) && 'true' === sanitize_text_field( wp_unslash( $_POST['force_refresh'] ) );
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
		$this->verify_ajax_request();

		$vuln_scanner = AtomicEdge::get_instance()->vulnerability_scanner;
		$results = $vuln_scanner->get_last_results();
		$last_scan = $vuln_scanner->get_last_scan_time();

		wp_send_json_success( array(
			'results'   => $results,
			'last_scan' => $last_scan,
			'available' => $vuln_scanner->is_available(),
		) );
	}
}
