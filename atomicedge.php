<?php
/**
 * Plugin Name: Atomic Edge Security
 * Plugin URI: https://atomicedge.io/wordpress
 * Description: Connect your WordPress site to Atomic Edge WAF/CDN for advanced security protection, analytics, and access control management.
 * Version: 1.1.1
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Tested up to: 6.7
 * Author: Atomic Edge
 * Author URI: https://atomicedge.io
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: atomicedge
 * Domain Path: /languages
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin constants.
define( 'ATOMICEDGE_VERSION', '1.1.1' );
define( 'ATOMICEDGE_PLUGIN_FILE', __FILE__ );
define( 'ATOMICEDGE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'ATOMICEDGE_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'ATOMICEDGE_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

// Minimum requirements.
define( 'ATOMICEDGE_MIN_PHP_VERSION', '7.4' );
define( 'ATOMICEDGE_MIN_WP_VERSION', '5.8' );

/**
 * Check minimum requirements before loading the plugin.
 *
 * @return bool True if requirements are met, false otherwise.
 */
function atomicedge_check_requirements() {
	$errors = array();

	// Check PHP version.
	if ( version_compare( PHP_VERSION, ATOMICEDGE_MIN_PHP_VERSION, '<' ) ) {
		$errors[] = sprintf(
			/* translators: 1: Current PHP version, 2: Required PHP version */
			esc_html__( 'Atomic Edge Security requires PHP %2$s or higher. You are running PHP %1$s.', 'atomicedge' ),
			esc_html( PHP_VERSION ),
			esc_html( ATOMICEDGE_MIN_PHP_VERSION )
		);
	}

	// Check WordPress version.
	global $wp_version;
	if ( version_compare( $wp_version, ATOMICEDGE_MIN_WP_VERSION, '<' ) ) {
		$errors[] = sprintf(
			/* translators: 1: Current WordPress version, 2: Required WordPress version */
			esc_html__( 'Atomic Edge Security requires WordPress %2$s or higher. You are running WordPress %1$s.', 'atomicedge' ),
			esc_html( $wp_version ),
			esc_html( ATOMICEDGE_MIN_WP_VERSION )
		);
	}

	// Check for OpenSSL (required for API key encryption).
	if ( ! function_exists( 'openssl_encrypt' ) ) {
		$errors[] = esc_html__( 'Atomic Edge Security requires the OpenSSL PHP extension to be enabled.', 'atomicedge' );
	}

	if ( ! empty( $errors ) ) {
		add_action(
			'admin_notices',
			function () use ( $errors ) {
				?>
				<div class="notice notice-error">
					<p><strong><?php esc_html_e( 'Atomic Edge Security cannot be activated:', 'atomicedge' ); ?></strong></p>
					<ul>
						<?php foreach ( $errors as $error ) : ?>
							<li><?php echo esc_html( $error ); ?></li>
						<?php endforeach; ?>
					</ul>
				</div>
				<?php
			}
		);
		return false;
	}

	return true;
}

/**
 * Initialize the plugin.
 *
 * @return void
 */
function atomicedge_init() {
	// Check requirements.
	if ( ! atomicedge_check_requirements() ) {
		return;
	}

	// Load text domain.
	load_plugin_textdomain( 'atomicedge', false, dirname( ATOMICEDGE_PLUGIN_BASENAME ) . '/languages' );

	// Include required files.
	require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge.php';
	require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-api.php';
	require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-admin.php';
	require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-ajax.php';
	require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-scanner.php';
	require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-vulnerability-scanner.php';
	require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cron.php';

	// Load WP-CLI commands if available.
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cli.php';
	}

	// Initialize main plugin class.
	AtomicEdge::get_instance();
}
add_action( 'plugins_loaded', 'atomicedge_init' );

/**
 * Plugin activation hook.
 *
 * @return void
 */
function atomicedge_activate() {
	// Check requirements on activation.
	if ( ! atomicedge_check_requirements() ) {
		deactivate_plugins( ATOMICEDGE_PLUGIN_BASENAME );
		wp_die(
			esc_html__( 'AtomicEdge Security cannot be activated. Please check the requirements.', 'atomicedge' ),
			esc_html__( 'Plugin Activation Error', 'atomicedge' ),
			array( 'back_link' => true )
		);
	}

	// Set default options.
	$defaults = array(
		'api_url'   => 'https://dashboard.atomicedge.io/api/v1',
		'connected' => false,
	);

	foreach ( $defaults as $key => $value ) {
		if ( false === get_option( 'atomicedge_' . $key ) ) {
			add_option( 'atomicedge_' . $key, $value );
		}
	}

	// Schedule cron events.
	if ( ! wp_next_scheduled( 'atomicedge_daily_scan' ) ) {
		wp_schedule_event( time(), 'daily', 'atomicedge_daily_scan' );
	}

	// Flush rewrite rules.
	flush_rewrite_rules();
}
register_activation_hook( __FILE__, 'atomicedge_activate' );

/**
 * Plugin deactivation hook.
 *
 * @return void
 */
function atomicedge_deactivate() {
	// Clear scheduled events.
	wp_clear_scheduled_hook( 'atomicedge_daily_scan' );
	wp_clear_scheduled_hook( 'atomicedge_sync_settings' );

	// Flush rewrite rules.
	flush_rewrite_rules();
}
register_deactivation_hook( __FILE__, 'atomicedge_deactivate' );

/**
 * Add settings link to plugins page.
 *
 * @param array $links Existing plugin action links.
 * @return array Modified plugin action links.
 */
function atomicedge_plugin_action_links( $links ) {
	$settings_link = sprintf(
		'<a href="%s">%s</a>',
		esc_url( admin_url( 'admin.php?page=atomicedge' ) ),
		esc_html__( 'Settings', 'atomicedge' )
	);
	array_unshift( $links, $settings_link );
	return $links;
}
add_filter( 'plugin_action_links_' . ATOMICEDGE_PLUGIN_BASENAME, 'atomicedge_plugin_action_links' );
