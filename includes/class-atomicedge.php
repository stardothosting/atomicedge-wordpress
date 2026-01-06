<?php
/**
 * Main AtomicEdge Plugin Class
 *
 * Initializes and coordinates all plugin functionality.
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge
 *
 * Main plugin class implementing singleton pattern.
 */
class AtomicEdge {

	/**
	 * Singleton instance.
	 *
	 * @var AtomicEdge|null
	 */
	private static $instance = null;

	/**
	 * API client instance.
	 *
	 * @var AtomicEdge_API
	 */
	public $api;

	/**
	 * Admin instance.
	 *
	 * @var AtomicEdge_Admin
	 */
	public $admin;

	/**
	 * AJAX handler instance.
	 *
	 * @var AtomicEdge_Ajax
	 */
	public $ajax;

	/**
	 * Scanner instance.
	 *
	 * @var AtomicEdge_Scanner
	 */
	public $scanner;

	/**
	 * Cron handler instance.
	 *
	 * @var AtomicEdge_Cron
	 */
	public $cron;

	/**
	 * Get singleton instance.
	 *
	 * @return AtomicEdge
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor - private to enforce singleton.
	 */
	private function __construct() {
		$this->init_components();
		$this->init_hooks();
	}

	/**
	 * Prevent cloning.
	 */
	private function __clone() {}

	/**
	 * Prevent unserialization.
	 *
	 * @throws Exception Always throws exception.
	 */
	public function __wakeup() {
		throw new Exception( esc_html__( 'Cannot unserialize singleton', 'atomicedge' ) );
	}

	/**
	 * Initialize plugin components.
	 *
	 * @return void
	 */
	private function init_components() {
		$this->api     = new AtomicEdge_API();
		$this->admin   = new AtomicEdge_Admin( $this->api );
		$this->ajax    = new AtomicEdge_Ajax( $this->api );
		$this->scanner = new AtomicEdge_Scanner();
		$this->cron    = new AtomicEdge_Cron( $this->api, $this->scanner );
	}

	/**
	 * Initialize WordPress hooks.
	 *
	 * @return void
	 */
	private function init_hooks() {
		// Admin-specific hooks.
		if ( is_admin() ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		}
	}

	/**
	 * Enqueue admin CSS and JavaScript.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_admin_assets( $hook ) {
		// Only load on our plugin pages.
		if ( strpos( $hook, 'atomicedge' ) === false ) {
			return;
		}

		// Determine version for cache busting.
		$version = ATOMICEDGE_VERSION;
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$version .= '-' . time();
		}

		// Enqueue Chart.js for analytics.
		wp_enqueue_script(
			'atomicedge-chartjs',
			ATOMICEDGE_PLUGIN_URL . 'assets/js/chart.min.js',
			array(),
			'4.4.1',
			true
		);

		// Enqueue admin CSS.
		wp_enqueue_style(
			'atomicedge-admin',
			ATOMICEDGE_PLUGIN_URL . 'admin/css/admin.css',
			array(),
			$version
		);

		// Enqueue admin JavaScript.
		wp_enqueue_script(
			'atomicedge-admin',
			ATOMICEDGE_PLUGIN_URL . 'admin/js/admin.js',
			array( 'jquery', 'atomicedge-chartjs' ),
			$version,
			true
		);

		// Localize script with data.
		wp_localize_script(
			'atomicedge-admin',
			'atomicedgeAdmin',
			array(
				'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
				'nonce'     => wp_create_nonce( 'atomicedge_ajax' ),
				'connected' => $this->api->is_connected(),
				'strings'   => array(
					'loading'      => esc_html__( 'Loading...', 'atomicedge' ),
					'error'        => esc_html__( 'An error occurred. Please try again.', 'atomicedge' ),
					'success'      => esc_html__( 'Success!', 'atomicedge' ),
					'confirm'      => esc_html__( 'Are you sure?', 'atomicedge' ),
					'confirmIp'    => esc_html__( 'Are you sure you want to remove this IP?', 'atomicedge' ),
					'invalidIp'    => esc_html__( 'Please enter a valid IP address or CIDR range.', 'atomicedge' ),
					'scanning'     => esc_html__( 'Scanning files...', 'atomicedge' ),
					'scanComplete' => esc_html__( 'Scan complete!', 'atomicedge' ),
				),
			)
		);
	}

	/**
	 * Check if the site is connected to AtomicEdge.
	 *
	 * @return bool
	 */
	public function is_connected() {
		return $this->api->is_connected();
	}

	/**
	 * Get the API client instance.
	 *
	 * @return AtomicEdge_API
	 */
	public function get_api() {
		return $this->api;
	}

	/**
	 * Log debug information.
	 *
	 * @param string $message Debug message.
	 * @param mixed  $data    Optional data to log.
	 * @return void
	 */
	public static function log( $message, $data = null ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			$log_message = 'AtomicEdge: ' . $message;
			if ( null !== $data ) {
				$log_message .= ' | Data: ' . wp_json_encode( $data );
			}
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( $log_message );
		}
	}
}
