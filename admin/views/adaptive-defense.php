<?php
/**
 * Adaptive Defense Page View
 *
 * AI-powered threat detection and automatic IP blocking.
 * Uses tabbed interface: Status, Blocked IPs, Actor Profiles, Threat Detections.
 *
 * @package AtomicEdge
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check for dev mode (local environments).
$atomicedge_dev_mode = AtomicEdge_Dev_Mode::is_enabled();

// Get connection status.
$atomicedge_is_connected = $atomicedge_dev_mode ? true : $this->api->is_connected();

// Tab navigation.
$current_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'status';
$valid_tabs  = array( 'status', 'actors', 'detections' );
if ( ! in_array( $current_tab, $valid_tabs, true ) ) {
	$current_tab = 'status';
}

// Tab definitions.
$tabs = array(
	'status'     => array(
		'label' => __( 'Status', 'atomic-edge-security' ),
		'icon'  => 'dashicons-shield-alt',
	),
	'actors'     => array(
		'label' => __( 'Actor Profiles', 'atomic-edge-security' ),
		'icon'  => 'dashicons-admin-users',
	),
	'detections' => array(
		'label' => __( 'Threat Detections', 'atomic-edge-security' ),
		'icon'  => 'dashicons-warning',
	),
);
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'admin/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<div id="atomicedge-adaptive-defense-page" class="atomicedge-adaptive-defense">
		<h2>
			<span class="dashicons dashicons-shield" style="font-size: 24px; width: 24px; height: 24px; margin-right: 8px; vertical-align: middle;"></span>
			<?php esc_html_e( 'Adaptive Defense', 'atomic-edge-security' ); ?>
		</h2>
		<p class="atomicedge-page-description">
			<?php esc_html_e( 'AI-powered threat detection that automatically identifies and blocks malicious actors based on behavioral analysis.', 'atomic-edge-security' ); ?>
		</p>

		<?php
		// Show dev mode notice.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML is escaped in the method.
		echo AtomicEdge_Dev_Mode::get_admin_notice();
		?>

		<?php if ( ! $atomicedge_is_connected ) : ?>
			<!-- Not Connected State -->
			<div class="atomicedge-card">
				<div class="atomicedge-notice atomicedge-notice-warning">
					<span class="dashicons dashicons-warning"></span>
					<div>
						<p><strong><?php esc_html_e( 'Not Connected to Atomic Edge', 'atomic-edge-security' ); ?></strong></p>
						<p><?php esc_html_e( 'Connect your site to Atomic Edge to access Adaptive Defense features.', 'atomic-edge-security' ); ?></p>
						<p>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-settings' ) ); ?>" class="button button-primary">
								<?php esc_html_e( 'Go to Settings', 'atomic-edge-security' ); ?>
							</a>
						</p>
					</div>
				</div>
			</div>
		<?php else : ?>
			<!-- Tab Navigation -->
			<nav class="nav-tab-wrapper wp-clearfix" style="margin-bottom: 0;">
				<?php foreach ( $tabs as $tab_id => $tab ) : ?>
					<a href="<?php echo esc_url( add_query_arg( 'tab', $tab_id, admin_url( 'admin.php?page=atomicedge-adaptive-defense' ) ) ); ?>" 
						class="nav-tab <?php echo $current_tab === $tab_id ? 'nav-tab-active' : ''; ?>">
						<span class="dashicons <?php echo esc_attr( $tab['icon'] ); ?>" style="font-size: 16px; width: 16px; height: 16px; vertical-align: text-bottom; margin-right: 5px;"></span>
						<?php echo esc_html( $tab['label'] ); ?>
					</a>
				<?php endforeach; ?>
			</nav>

			<!-- Tab Content -->
			<div class="atomicedge-ad-tab-content">
				<?php
				switch ( $current_tab ) {

					case 'actors':
						include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/adaptive-defense-actors-tab.php';
						break;
					case 'detections':
						include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/adaptive-defense-detections-tab.php';
						break;
					default:
						include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/adaptive-defense-status-tab.php';
						break;
				}
				?>
			</div>
		<?php endif; ?>
	</div>
</div>
