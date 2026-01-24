<?php
/**
 * 2FA Settings - Unified Admin View with Tabs
 *
 * Consolidates Policy, User Management, and Audit Log into tabbed sections.
 *
 * @package AtomicEdge
 * @since   1.9.1
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get current tab.
$current_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'policy';
$valid_tabs  = array( 'policy', 'users', 'audit' );
if ( ! in_array( $current_tab, $valid_tabs, true ) ) {
	$current_tab = 'policy';
}

// Tab definitions.
$tabs = array(
	'policy' => array(
		'label' => __( 'Policy', 'atomicedge' ),
		'icon'  => 'dashicons-shield',
	),
	'users'  => array(
		'label' => __( 'Users', 'atomicedge' ),
		'icon'  => 'dashicons-groups',
	),
	'audit'  => array(
		'label' => __( 'Audit Log', 'atomicedge' ),
		'icon'  => 'dashicons-list-view',
	),
);
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-2fa">
		<h2>
			<span class="dashicons dashicons-lock" style="font-size: 24px; width: 24px; height: 24px; margin-right: 8px; vertical-align: middle;"></span>
			<?php echo esc_html__( 'Two-Factor Authentication', 'atomicedge' ); ?>
		</h2>
		<p class="atomicedge-page-description">
			<?php echo esc_html__( 'Manage two-factor authentication settings, user status, and security audit logs.', 'atomicedge' ); ?>
		</p>

		<!-- Tab Navigation -->
		<nav class="nav-tab-wrapper wp-clearfix" style="margin-bottom: 20px;">
			<?php foreach ( $tabs as $tab_id => $tab ) : ?>
				<a href="<?php echo esc_url( add_query_arg( 'tab', $tab_id, admin_url( 'admin.php?page=atomicedge-2fa' ) ) ); ?>" 
					class="nav-tab <?php echo $current_tab === $tab_id ? 'nav-tab-active' : ''; ?>">
					<span class="dashicons <?php echo esc_attr( $tab['icon'] ); ?>" style="font-size: 16px; width: 16px; height: 16px; vertical-align: text-bottom; margin-right: 5px;"></span>
					<?php echo esc_html( $tab['label'] ); ?>
				</a>
			<?php endforeach; ?>
		</nav>

		<!-- Tab Content -->
		<div class="atomicedge-2fa-tab-content">
			<?php
			switch ( $current_tab ) {
				case 'users':
					include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/2fa-users-tab.php';
					break;
				case 'audit':
					include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/2fa-audit-tab.php';
					break;
				case 'policy':
				default:
					include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/2fa-policy-tab.php';
					break;
			}
			?>
		</div>
	</div>
</div>

<style>
.atomicedge-wrap .nav-tab {
	display: inline-flex;
	align-items: center;
}
.atomicedge-wrap .nav-tab-active {
	background: #fff;
	border-bottom-color: #fff;
}
.atomicedge-2fa-tab-content {
	background: #fff;
	border: 1px solid #c3c4c7;
	border-top: none;
	padding: 20px;
}
.atomicedge-stats-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
	gap: 15px;
	margin: 20px 0;
}
.atomicedge-stat-card {
	background: #f9f9f9;
	padding: 20px;
	border-left: 4px solid #0073aa;
	box-shadow: 0 1px 1px rgba(0,0,0,.04);
}
.atomicedge-stat-card .stat-value {
	font-size: 28px;
	font-weight: 600;
	color: #23282d;
}
.atomicedge-stat-card .stat-label {
	color: #666;
	font-size: 13px;
}
</style>
