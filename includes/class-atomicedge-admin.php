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
	}

	/**
	 * Register admin menu.
	 *
	 * @return void
	 */
	public function register_menu() {
		// Main menu.
		add_menu_page(
			__( 'Atomic Edge Security', 'atomicedge' ),
			__( 'Atomic Edge', 'atomicedge' ),
			'manage_options',
			'atomicedge',
			array( $this, 'render_dashboard_page' ),
			'dashicons-shield',
			30
		);

		// Dashboard submenu (same as main).
		add_submenu_page(
			'atomicedge',
			__( 'Dashboard', 'atomicedge' ),
			__( 'Dashboard', 'atomicedge' ),
			'manage_options',
			'atomicedge',
			array( $this, 'render_dashboard_page' )
		);

		// Analytics submenu.
		add_submenu_page(
			'atomicedge',
			__( 'Analytics', 'atomicedge' ),
			__( 'Analytics', 'atomicedge' ),
			'manage_options',
			'atomicedge-analytics',
			array( $this, 'render_analytics_page' )
		);

		// WAF Logs submenu.
		add_submenu_page(
			'atomicedge',
			__( 'WAF Logs', 'atomicedge' ),
			__( 'WAF Logs', 'atomicedge' ),
			'manage_options',
			'atomicedge-waf-logs',
			array( $this, 'render_waf_logs_page' )
		);

		// Access Control submenu.
		add_submenu_page(
			'atomicedge',
			__( 'Access Control', 'atomicedge' ),
			__( 'Access Control', 'atomicedge' ),
			'manage_options',
			'atomicedge-access-control',
			array( $this, 'render_access_control_page' )
		);

		// Malware Scanner submenu.
		add_submenu_page(
			'atomicedge',
			__( 'Malware Scanner', 'atomicedge' ),
			__( 'Malware Scanner', 'atomicedge' ),
			'manage_options',
			'atomicedge-scanner',
			array( $this, 'render_scanner_page' )
		);

		// Vulnerability Scanner submenu.
		add_submenu_page(
			'atomicedge',
			__( 'Vulnerability Scanner', 'atomicedge' ),
			__( 'Vulnerability Scanner', 'atomicedge' ),
			'manage_options',
			'atomicedge-vulnerabilities',
			array( $this, 'render_vulnerability_scanner_page' )
		);

		// Settings submenu.
		add_submenu_page(
			'atomicedge',
			__( 'Settings', 'atomicedge' ),
			__( 'Settings', 'atomicedge' ),
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
		if ( isset( $_POST['atomicedge_save_settings'] ) ) {
			$this->handle_settings_save();
		}

		// Handle connection.
		if ( isset( $_POST['atomicedge_connect'] ) ) {
			$this->handle_connect();
		}

		// Handle disconnection.
		if ( isset( $_POST['atomicedge_disconnect'] ) ) {
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
			$this->add_admin_notice( 'error', __( 'Security check failed. Please try again.', 'atomicedge' ) );
			return;
		}

		// Check capabilities.
		if ( ! current_user_can( 'manage_options' ) ) {
			$this->add_admin_notice( 'error', __( 'You do not have permission to change settings.', 'atomicedge' ) );
			return;
		}

		// Save API URL.
		if ( isset( $_POST['atomicedge_api_url'] ) ) {
			$api_url = esc_url_raw( wp_unslash( $_POST['atomicedge_api_url'] ) );
			update_option( 'atomicedge_api_url', $api_url );
		}

		$this->add_admin_notice( 'success', __( 'Settings saved successfully.', 'atomicedge' ) );
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
			$this->add_admin_notice( 'error', __( 'Security check failed. Please try again.', 'atomicedge' ) );
			return;
		}

		// Check capabilities.
		if ( ! current_user_can( 'manage_options' ) ) {
			$this->add_admin_notice( 'error', __( 'You do not have permission to connect.', 'atomicedge' ) );
			return;
		}

		// Get and validate API key.
		$api_key = isset( $_POST['atomicedge_api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['atomicedge_api_key'] ) ) : '';
		$api_key = trim( $api_key );

		if ( empty( $api_key ) ) {
			$this->add_admin_notice( 'error', __( 'Please enter an API key.', 'atomicedge' ) );
			return;
		}

		// AtomicEdge keys are 32-64 alphanumeric characters (no prefixes).
		if ( ! preg_match( '/^[A-Za-z0-9]{32,64}$/', $api_key ) ) {
			$this->add_admin_notice(
				'error',
				__( 'Invalid API key format. Paste the key exactly as shown in the Atomic Edge dashboard (32–64 letters/numbers, no prefix).', 'atomicedge' )
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
			$this->add_admin_notice( 'error', __( 'Security check failed. Please try again.', 'atomicedge' ) );
			return;
		}

		// Check capabilities.
		if ( ! current_user_can( 'manage_options' ) ) {
			$this->add_admin_notice( 'error', __( 'You do not have permission to disconnect.', 'atomicedge' ) );
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
	 * Render dashboard page.
	 *
	 * @return void
	 */
	public function render_dashboard_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomicedge' ) );
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
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomicedge' ) );
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
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomicedge' ) );
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
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomicedge' ) );
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
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomicedge' ) );
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
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomicedge' ) );
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/vulnerability-scanner.php';
	}

	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'atomicedge' ) );
		}

		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/**
	 * Render not connected notice.
	 *
	 * @return void
	 */
	private function render_not_connected_notice() {
		?>
		<div class="wrap atomicedge-wrap">
			<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomicedge' ); ?>" class="atomicedge-logo" /></h1>
			<div class="notice notice-warning">
				<p>
					<?php
					printf(
						/* translators: %s: Settings page URL */
						wp_kses(
							__( 'Please <a href="%s">connect your site</a> to Atomic Edge to access this feature.', 'atomicedge' ),
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
