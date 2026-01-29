<?php
/**
 * AtomicEdge Admin Pages
 *
 * Handles all WordPress admin interface functionality.
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_Admin
 *
 * Manages admin pages and menus.
 */
class AtomicEdge_Admin {

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
	 * Initialize hooks.
	 *
	 * @return void
	 */
	private function init_hooks() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'handle_form_submissions' ) );
		add_action( 'admin_notices', array( $this, 'display_admin_notices' ) );
		add_action( 'admin_notices', array( $this, 'display_conflicting_plugin_notice' ) );
	}

	/**
	 * Register admin menu.
	 *
	 * @return void
	 */
	public function register_menu() {
		// Main menu.
		add_menu_page(
			__( 'Atomic Edge Security', 'atomic-edge-security' ),
			__( 'Atomic Edge', 'atomic-edge-security' ),
			'manage_options',
			'atomic-edge-security',
			array( $this, 'render_dashboard_page' ),
			'dashicons-shield',
			30
		);

		// Dashboard submenu (same as main).
		add_submenu_page(
			'atomic-edge-security',
			__( 'Dashboard', 'atomic-edge-security' ),
			__( 'Dashboard', 'atomic-edge-security' ),
			'manage_options',
			'atomic-edge-security',
			array( $this, 'render_dashboard_page' )
		);

		// Analytics submenu.
		add_submenu_page(
			'atomic-edge-security',
			__( 'Analytics', 'atomic-edge-security' ),
			__( 'Analytics', 'atomic-edge-security' ),
			'manage_options',
			'atomicedge-analytics',
			array( $this, 'render_analytics_page' )
		);

		// WAF Logs submenu.
		add_submenu_page(
			'atomic-edge-security',
			__( 'WAF Logs', 'atomic-edge-security' ),
			__( 'WAF Logs', 'atomic-edge-security' ),
			'manage_options',
			'atomicedge-waf-logs',
			array( $this, 'render_waf_logs_page' )
		);

		// Access Control submenu.
		add_submenu_page(
			'atomic-edge-security',
			__( 'Access Control', 'atomic-edge-security' ),
			__( 'Access Control', 'atomic-edge-security' ),
			'manage_options',
			'atomicedge-access-control',
			array( $this, 'render_access_control_page' )
		);

		// Malware Scanner submenu.
		add_submenu_page(
			'atomic-edge-security',
			__( 'Malware Scanner', 'atomic-edge-security' ),
			__( 'Malware Scanner', 'atomic-edge-security' ),
			'manage_options',
			'atomicedge-scanner',
			array( $this, 'render_scanner_page' )
		);

		// Vulnerability Scanner submenu.
		add_submenu_page(
			'atomic-edge-security',
			__( 'Vulnerability Scanner', 'atomic-edge-security' ),
			__( 'Vulnerability Scanner', 'atomic-edge-security' ),
			'manage_options',
			'atomicedge-vulnerabilities',
			array( $this, 'render_vulnerability_scanner_page' )
		);

		// CDN submenu.
		add_submenu_page(
			'atomic-edge-security',
			__( 'CDN', 'atomic-edge-security' ),
			__( 'CDN', 'atomic-edge-security' ),
			'manage_options',
			'atomicedge-cdn',
			array( $this, 'render_cdn_page' )
		);

		// 2FA submenu (unified page with tabs).
		add_submenu_page(
			'atomic-edge-security',
			__( '2FA', 'atomic-edge-security' ),
			__( '2FA', 'atomic-edge-security' ),
			'manage_options',
			'atomicedge-2fa',
			array( $this, 'render_2fa_settings_page' )
		);

		// Settings submenu.
		add_submenu_page(
			'atomic-edge-security',
			__( 'Settings', 'atomic-edge-security' ),
			__( 'Settings', 'atomic-edge-security' ),
			'manage_options',
			'atomicedge-settings',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Handle form submissions.
	 *
	 * @return void
	 */
	public function handle_form_submissions() {
		// Handle settings form.
		if ( isset( $_POST['atomicedge_save_settings'], $_POST['_wpnonce'] ) &&
			wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'atomicedge_settings' ) ) {
			$this->handle_settings_save();
		}

		// Handle connection.
		if ( isset( $_POST['atomicedge_connect'], $_POST['_wpnonce'] ) &&
			wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'atomicedge_connect' ) ) {
			$this->handle_connect();
		}

		// Handle disconnection.
		if ( isset( $_POST['atomicedge_disconnect'], $_POST['_wpnonce'] ) &&
			wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'atomicedge_disconnect' ) ) {
			$this->handle_disconnect();
		}
	}

	/**
	 * Handle settings save.
	 *
	 * @return void
	 */
	private function handle_settings_save() {
		// Verify nonce.
		if ( ! isset( $_POST['_wpnonce'] ) ||
			 ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'atomicedge_settings' ) ) {
			$this->add_admin_notice( 'error', __( 'Security check failed. Please try again.', 'atomic-edge-security' ) );
			return;
		}

		// Check capabilities.
		if ( ! current_user_can( 'manage_options' ) ) {
			$this->add_admin_notice( 'error', __( 'You do not have permission to change settings.', 'atomic-edge-security' ) );
			return;
		}

		// Save API URL.
		if ( isset( $_POST['atomicedge_api_url'] ) ) {
			$api_url = esc_url_raw( wp_unslash( $_POST['atomicedge_api_url'] ) );
			update_option( 'atomicedge_api_url', $api_url );
		}

		$this->add_admin_notice( 'success', __( 'Settings saved successfully.', 'atomic-edge-security' ) );
	}

	/**
	 * Handle connect action.
	 *
	 * @return void
	 */
	private function handle_connect() {
		// Verify nonce.
		if ( ! isset( $_POST['_wpnonce'] ) ||
			 ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'atomicedge_connect' ) ) {
			$this->add_admin_notice( 'error', __( 'Security check failed. Please try again.', 'atomic-edge-security' ) );
			return;
		}

		// Check capabilities.
		if ( ! current_user_can( 'manage_options' ) ) {
			$this->add_admin_notice( 'error', __( 'You do not have permission to connect.', 'atomic-edge-security' ) );
			return;
		}

		// Get and validate API key.
		$api_key = isset( $_POST['atomicedge_api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['atomicedge_api_key'] ) ) : '';
		$api_key = trim( $api_key );

		if ( empty( $api_key ) ) {
			$this->add_admin_notice( 'error', __( 'Please enter an API key.', 'atomic-edge-security' ) );
			return;
		}

		// AtomicEdge keys are 32-64 alphanumeric characters (no prefixes).
		if ( ! preg_match( '/^[A-Za-z0-9]{32,64}$/', $api_key ) ) {
			$this->add_admin_notice(
				'error',
				__( 'Invalid API key format. Paste the key exactly as shown in the Atomic Edge dashboard (32–64 letters/numbers, no prefix).', 'atomic-edge-security' )
			);
			return;
		}

		// Attempt connection.
		$result = $this->api->connect( $api_key );

		if ( $result['success'] ) {
			$this->add_admin_notice( 'success', $result['message'] );
		} else {
			$this->add_admin_notice( 'error', $result['error'] );
		}
	}

	/**
	 * Handle disconnect action.
	 *
	 * @return void
	 */
	private function handle_disconnect() {
		// Verify nonce.
		if ( ! isset( $_POST['_wpnonce'] ) ||
			 ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'atomicedge_disconnect' ) ) {
			$this->add_admin_notice( 'error', __( 'Security check failed. Please try again.', 'atomic-edge-security' ) );
			return;
		}

		// Check capabilities.
		if ( ! current_user_can( 'manage_options' ) ) {
			$this->add_admin_notice( 'error', __( 'You do not have permission to disconnect.', 'atomic-edge-security' ) );
			return;
		}

		$result = $this->api->disconnect();
		$this->add_admin_notice( 'success', $result['message'] );
	}

	/**
	 * Add admin notice to be displayed.
	 *
	 * @param string $type    Notice type (success, error, warning, info).
	 * @param string $message Notice message.
	 * @return void
	 */
	private function add_admin_notice( $type, $message ) {
		$notices   = get_transient( 'atomicedge_admin_notices' );
		$notices   = is_array( $notices ) ? $notices : array();
		$notices[] = array(
			'type'    => $type,
			'message' => $message,
		);
		set_transient( 'atomicedge_admin_notices', $notices, 60 );
	}

	/**
	 * Display admin notices.
	 *
	 * @return void
	 */
	public function display_admin_notices() {
		$notices = get_transient( 'atomicedge_admin_notices' );
		if ( ! is_array( $notices ) || empty( $notices ) ) {
			return;
		}

		foreach ( $notices as $notice ) {
			$class = 'notice-' . esc_attr( $notice['type'] );
			printf(
				'<div class="notice %s is-dismissible"><p>%s</p></div>',
				esc_attr( $class ),
				esc_html( $notice['message'] )
			);
		}

		delete_transient( 'atomicedge_admin_notices' );
	}

	/**
	 * Display notice if Shift8 CDN plugin is active.
	 *
	 * @return void
	 */
	public function display_conflicting_plugin_notice() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		if ( ! function_exists( 'is_plugin_active' ) ) {
			$file_php = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( file_exists( $file_php ) ) {
				require_once $file_php;
			}
		}

		if ( ! function_exists( 'is_plugin_active' ) ) {
			return;
		}

		$conflicting_plugin = 'shift8-cdn/shift8-cdn.php';
		if ( ! is_plugin_active( $conflicting_plugin ) ) {
			return;
		}

		$deactivate_url = wp_nonce_url(
			admin_url( 'plugins.php?action=deactivate&plugin=' . rawurlencode( $conflicting_plugin ) ),
			'deactivate-plugin_' . $conflicting_plugin
		);

		$message = sprintf(
			/* translators: 1: plugin name, 2: deactivate link */
			__( '%1$s is active. Atomic Edge Security should not run alongside the retired Shift8 CDN plugin. %2$s', 'atomic-edge-security' ),
			esc_html__( 'Shift8 CDN', 'atomic-edge-security' ),
			sprintf(
				'<a href="%s">%s</a>',
				esc_url( $deactivate_url ),
				esc_html__( 'Deactivate Shift8 CDN', 'atomic-edge-security' )
			)
		);

		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			wp_kses_post( $message )
		);
	}

	/**
	 * Render dashboard page.
	 *
	 * @return void
	 */
	public function render_dashboard_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	/**
	 * Render analytics page.
	 *
	 * @return void
	 */
	public function render_analytics_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		if ( ! $this->api->is_connected() ) {
			$this->render_not_connected_notice();
			return;
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/analytics.php';
	}

	/**
	 * Render WAF logs page.
	 *
	 * @return void
	 */
	public function render_waf_logs_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		if ( ! $this->api->is_connected() ) {
			$this->render_not_connected_notice();
			return;
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/waf-logs.php';
	}

	/**
	 * Render access control page.
	 *
	 * @return void
	 */
	public function render_access_control_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		if ( ! $this->api->is_connected() ) {
			$this->render_not_connected_notice();
			return;
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/access-control.php';
	}

	/**
	 * Render scanner page.
	 *
	 * @return void
	 */
	public function render_scanner_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/scanner.php';
	}

	/**
	 * Render vulnerability scanner page.
	 *
	 * @return void
	 */
	public function render_vulnerability_scanner_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/vulnerability-scanner.php';
	}

	/**
	 * Render CDN page.
	 *
	 * Handles form submission for CDN settings before rendering.
	 *
	 * @return void
	 */
	public function render_cdn_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		// Handle CDN settings form submission.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce check first.
		if ( isset( $_POST['atomicedge_save_cdn_settings'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized immediately.
			$nonce = isset( $_POST['atomicedge_cdn_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['atomicedge_cdn_nonce'] ) ) : '';
			if ( wp_verify_nonce( $nonce, 'atomicedge_cdn_settings' ) ) {
				// Save CDN optimization settings to WP options.
				update_option( 'atomicedge_cdn_brotli', isset( $_POST['atomicedge_cdn_brotli'] ) ? true : false );
				update_option( 'atomicedge_cdn_js_minification', isset( $_POST['atomicedge_cdn_js_minification'] ) ? true : false );
				update_option( 'atomicedge_cdn_css_minification', isset( $_POST['atomicedge_cdn_css_minification'] ) ? true : false );
				update_option( 'atomicedge_cdn_image_optimization', isset( $_POST['atomicedge_cdn_image_optimization'] ) ? true : false );

				add_settings_error( 'atomicedge_cdn', 'settings_saved', __( 'CDN settings saved.', 'atomic-edge-security' ), 'success' );
			} else {
				add_settings_error( 'atomicedge_cdn', 'nonce_failed', __( 'Security check failed.', 'atomic-edge-security' ), 'error' );
			}
			settings_errors( 'atomicedge_cdn' );
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/cdn.php';
	}

	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/**
	 * Render the unified 2FA settings page with tabs.
	 *
	 * @return void
	 */
	public function render_2fa_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomic-edge-security' ) );
		}

		// Handle export action (from audit tab).
		if ( isset( $_GET['action'], $_GET['tab'] ) && 'export' === $_GET['action'] && 'audit' === $_GET['tab'] ) {
			// Verify nonce.
			if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'atomicedge_export_audit' ) ) {
				wp_die( esc_html__( 'Security check failed.', 'atomic-edge-security' ) );
			}

			$this->export_audit_csv();
			return;
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/2fa-settings.php';
	}

	/**
	 * Export audit log as CSV.
	 *
	 * @return void
	 */
	private function export_audit_csv() {
		$entries = AtomicEdge_2FA_Audit::export( 1000 );

		$filename = 'atomicedge-2fa-audit-' . gmdate( 'Y-m-d' ) . '.csv';

		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=' . $filename );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		$output = fopen( 'php://output', 'w' );

		// CSV header.
		fputcsv( $output, array( 'Date/Time', 'User', 'Email', 'Event', 'IP Address', 'Admin' ) );

		// CSV data.
		foreach ( $entries as $entry ) {
			fputcsv( $output, array(
				$entry['date'],
				$entry['user'],
				$entry['user_email'],
				$entry['event'],
				$entry['ip_address'],
				$entry['admin'],
			) );
		}

		fclose( $output );
		exit;
	}

	/**
	 * Render not connected notice.
	 *
	 * @return void
	 */
	private function render_not_connected_notice() {
		?>
		<div class="wrap atomicedge-wrap">
			<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'admin/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>
			<div class="notice notice-warning">
				<p>
					<?php
					printf(
						wp_kses(
								/* translators: %s: Settings page URL */
							__( 'Please <a href="%s">connect your site</a> to Atomic Edge to access this feature.', 'atomic-edge-security' ),
							array( 'a' => array( 'href' => array() ) )
						),
						esc_url( admin_url( 'admin.php?page=atomicedge' ) )
					);
					?>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Get masked API key for display.
	 *
	 * @return string Masked API key or empty string.
	 */
	public function get_masked_api_key() {
		$api_key = $this->api->get_api_key();
		if ( ! $api_key || strlen( $api_key ) < 8 ) {
			return '';
		}
		return str_repeat( '•', strlen( $api_key ) - 4 ) . substr( $api_key, -4 );
	}
}
