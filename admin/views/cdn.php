<?php
/**
 * CDN Page View
 *
 * This page allows users to configure CDN settings for their site.
 * Uses tabbed interface: General, Minification, Advanced.
 *
 * User scenarios:
 * 1. New user not connected to AtomicEdge - show connection prompt
 * 2. Connected user without CDN enabled - show how to enable CDN
 * 3. Connected user with CDN enabled - show tabbed settings
 * 4. Local dev environment - show dev mode with simulated features
 *
 * @package AtomicEdge
 * @since   2.0.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check for dev mode (local environments).
$atomicedge_dev_mode = AtomicEdge_Dev_Mode::is_enabled();

// Get connection status and CDN settings - use effective data for dev mode.
$atomicedge_is_connected = $atomicedge_dev_mode ? true : $this->api->is_connected();
$atomicedge_site_data    = AtomicEdge_Dev_Mode::get_effective_site_data();

// CDN settings from site data (populated when site connects or refreshes).
$atomicedge_cdn_prefix   = $atomicedge_site_data['cdn_prefix'] ?? '';
$atomicedge_cdn_url      = $atomicedge_site_data['cdn_url'] ?? '';

// Use actual is_cdn_enabled() - checks local switch + CDN URL available.
// No dashboard gating - if user has a CDN URL (from constant or dashboard), show settings.
$atomicedge_cdn_enabled       = AtomicEdge_CDN::is_cdn_enabled();
$atomicedge_show_cdn_settings = $atomicedge_cdn_enabled || ! empty( AtomicEdge_CDN::get_cdn_hostname() );

// Last purge time.
$atomicedge_cdn_last_purge = get_option( 'atomicedge_cdn_last_purge', '' );

// Tab navigation.
$current_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'general';
$valid_tabs  = array( 'general', 'minification', 'advanced' );
if ( ! in_array( $current_tab, $valid_tabs, true ) ) {
	$current_tab = 'general';
}

// Tab definitions.
$tabs = array(
	'general'      => array(
		'label' => __( 'General', 'atomic-edge-security' ),
		'icon'  => 'dashicons-admin-generic',
	),
	'minification' => array(
		'label' => __( 'Minification', 'atomic-edge-security' ),
		'icon'  => 'dashicons-editor-code',
	),
	'advanced'     => array(
		'label' => __( 'Advanced', 'atomic-edge-security' ),
		'icon'  => 'dashicons-admin-tools',
	),
);
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'admin/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-cdn">
		<h2>
			<span class="dashicons dashicons-cloud" style="font-size: 24px; width: 24px; height: 24px; margin-right: 8px; vertical-align: middle;"></span>
			<?php esc_html_e( 'CDN Settings', 'atomic-edge-security' ); ?>
		</h2>
		<p class="atomicedge-page-description">
			<?php esc_html_e( 'Content Delivery Network (CDN) caches your static assets on global edge servers for faster page loads.', 'atomic-edge-security' ); ?>
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
						<p><?php esc_html_e( 'Connect your site to Atomic Edge to access CDN features.', 'atomic-edge-security' ); ?></p>
						<p>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-settings' ) ); ?>" class="button button-primary">
								<?php esc_html_e( 'Go to Settings', 'atomic-edge-security' ); ?>
							</a>
						</p>
					</div>
				</div>
			</div>

		<?php elseif ( ! $atomicedge_show_cdn_settings ) : ?>
			<!-- Connected but CDN Not Enabled on Dashboard -->
			<div class="atomicedge-card">
				<h3><?php esc_html_e( 'CDN Status', 'atomic-edge-security' ); ?></h3>
				<div class="atomicedge-cdn-status-display">
					<span class="atomicedge-status-badge atomicedge-status-inactive">
						<span class="atomicedge-status-indicator"></span>
						<span><?php esc_html_e( 'CDN Not Enabled', 'atomic-edge-security' ); ?></span>
					</span>
				</div>
				<div class="atomicedge-notice atomicedge-notice-info" style="margin-top: 15px;">
					<span class="dashicons dashicons-info"></span>
					<div>
						<p><strong><?php esc_html_e( 'Enable CDN in Your Dashboard', 'atomic-edge-security' ); ?></strong></p>
						<p><?php esc_html_e( 'CDN is not currently enabled for this site. You can enable it from your Atomic Edge dashboard.', 'atomic-edge-security' ); ?></p>
						<p style="margin-top: 10px;">
							<a href="https://dashboard.atomicedge.io" target="_blank" rel="noopener noreferrer" class="button button-primary">
								<?php esc_html_e( 'Open Dashboard', 'atomic-edge-security' ); ?>
								<span class="dashicons dashicons-external" style="margin-top: 3px;"></span>
							</a>
							<button type="button" id="atomicedge-cdn-refresh" class="button" style="margin-left: 10px;">
								<span class="dashicons dashicons-update" style="margin-top: 3px;"></span>
								<?php esc_html_e( 'Refresh Status', 'atomic-edge-security' ); ?>
							</button>
							<span id="atomicedge-cdn-refresh-status" class="atomicedge-inline-status"></span>
						</p>
					</div>
				</div>
			</div>

			<!-- Shift8 CDN Migration Notice -->
			<div class="atomicedge-card">
				<h3><?php esc_html_e( 'Migrating from Shift8 CDN?', 'atomic-edge-security' ); ?></h3>
				<p><?php esc_html_e( 'If you were using the Shift8 CDN plugin, your CDN service will continue to work through Atomic Edge.', 'atomic-edge-security' ); ?></p>
				<ol>
					<li><?php esc_html_e( 'Log in to your Atomic Edge dashboard', 'atomic-edge-security' ); ?></li>
					<li><?php esc_html_e( 'Enable CDN for your site in the site settings', 'atomic-edge-security' ); ?></li>
					<li><?php esc_html_e( 'Return here and click "Refresh Status"', 'atomic-edge-security' ); ?></li>
				</ol>
			</div>

		<?php else : ?>
			<!-- CDN Enabled - Show Tabbed Settings -->
			
			<!-- CDN Status Header Card -->
			<div class="atomicedge-card" style="margin-bottom: 20px;">
				<div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
					<div style="display: flex; align-items: center; gap: 15px;">
						<span class="atomicedge-status-badge atomicedge-status-active" style="font-size: 14px; padding: 8px 12px;">
							<span class="atomicedge-status-indicator"></span>
							<span><?php esc_html_e( 'CDN Active', 'atomic-edge-security' ); ?></span>
						</span>
						<?php if ( ! empty( $atomicedge_cdn_url ) ) : ?>
						<code style="font-size: 13px;"><?php echo esc_html( $atomicedge_cdn_url ); ?></code>
						<?php endif; ?>
					</div>
					<div style="display: flex; gap: 10px; align-items: center;">
						<button type="button" id="atomicedge-cdn-refresh" class="button">
							<span class="dashicons dashicons-update" style="margin-top: 3px;"></span>
							<?php esc_html_e( 'Refresh', 'atomic-edge-security' ); ?>
						</button>
						<button type="button" id="atomicedge-purge-cdn" class="button button-primary">
							<span class="dashicons dashicons-trash" style="margin-top: 3px;"></span>
							<?php esc_html_e( 'Purge Cache', 'atomic-edge-security' ); ?>
						</button>
						<span id="atomicedge-cdn-refresh-status" class="atomicedge-inline-status"></span>
						<span id="atomicedge-purge-status" class="atomicedge-inline-status"></span>
					</div>
				</div>
				<?php if ( ! empty( $atomicedge_cdn_last_purge ) ) : ?>
				<p style="margin: 10px 0 0; font-size: 12px; color: #646970;">
					<?php esc_html_e( 'Last cache purge:', 'atomic-edge-security' ); ?> <?php echo esc_html( $atomicedge_cdn_last_purge ); ?>
				</p>
				<?php endif; ?>
			</div>

			<!-- Tab Navigation -->
			<nav class="nav-tab-wrapper wp-clearfix" style="margin-bottom: 0;">
				<?php foreach ( $tabs as $tab_id => $tab ) : ?>
					<a href="<?php echo esc_url( add_query_arg( 'tab', $tab_id, admin_url( 'admin.php?page=atomicedge-cdn' ) ) ); ?>" 
						class="nav-tab <?php echo $current_tab === $tab_id ? 'nav-tab-active' : ''; ?>">
						<span class="dashicons <?php echo esc_attr( $tab['icon'] ); ?>" style="font-size: 16px; width: 16px; height: 16px; vertical-align: text-bottom; margin-right: 5px;"></span>
						<?php echo esc_html( $tab['label'] ); ?>
					</a>
				<?php endforeach; ?>
			</nav>

			<!-- Tab Content -->
			<div class="atomicedge-cdn-tab-content">
				<form id="atomicedge-cdn-settings-form" method="post" action="">
					<?php wp_nonce_field( 'atomicedge_cdn_settings', 'atomicedge_cdn_nonce' ); ?>
					<input type="hidden" name="atomicedge_cdn_tab" value="<?php echo esc_attr( $current_tab ); ?>">
					
					<?php
					switch ( $current_tab ) {
						case 'minification':
							include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/cdn-minification-tab.php';
							break;
						case 'advanced':
							include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/cdn-advanced-tab.php';
							break;
						case 'general':
						default:
							include ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/cdn-general-tab.php';
							break;
					}
					?>

					<div class="atomicedge-card" style="margin-top: 20px; border-top: 1px solid #c3c4c7;">
						<p class="submit" style="margin: 0; padding: 15px 0 0;">
							<button type="submit" name="atomicedge_save_cdn_settings" class="button button-primary button-large">
								<?php esc_html_e( 'Save CDN Settings', 'atomic-edge-security' ); ?>
							</button>
							<span id="atomicedge-cdn-settings-status" class="atomicedge-inline-status"></span>
						</p>
					</div>
				</form>
			</div>

		<?php endif; ?>
	</div>
</div>

<script type="text/javascript">
(function($) {
	'use strict';

	$(document).ready(function() {
		// Debug: Check if atomicedgeAdmin is available.
		if (typeof atomicedgeAdmin === 'undefined') {
			console.error('AtomicEdge: atomicedgeAdmin is not defined. Scripts may not be loaded correctly.');
			return;
		}

		// Copy to clipboard.
		$('.atomicedge-copy-btn').on('click', function(e) {
			e.preventDefault();
			var targetSelector = $(this).data('copy-target');
			var textToCopy = $(targetSelector).text();
			
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(textToCopy).then(function() {
					showCopySuccess(e.currentTarget);
				});
			} else {
				var $temp = $('<textarea>');
				$('body').append($temp);
				$temp.val(textToCopy).select();
				document.execCommand('copy');
				$temp.remove();
				showCopySuccess(e.currentTarget);
			}
		});

		function showCopySuccess(button) {
			var $btn = $(button);
			$btn.find('.dashicons').removeClass('dashicons-clipboard').addClass('dashicons-yes');
			setTimeout(function() {
				$btn.find('.dashicons').removeClass('dashicons-yes').addClass('dashicons-clipboard');
			}, 2000);
		}

		// Refresh CDN status.
		$('#atomicedge-cdn-refresh').on('click', function(e) {
			e.preventDefault();
			var $button = $(this);
			var $status = $('#atomicedge-cdn-refresh-status');
			
			$button.prop('disabled', true).find('.dashicons').addClass('atomicedge-spinning');
			$status.removeClass('atomicedge-status-success atomicedge-status-error').text('<?php echo esc_js( __( 'Refreshing...', 'atomic-edge-security' ) ); ?>');
			
			$.ajax({
				url: atomicedgeAdmin.ajaxUrl,
				type: 'POST',
				timeout: 30000,
				data: {
					action: 'atomicedge_refresh_cdn_status',
					nonce: atomicedgeAdmin.nonce
				},
				success: function(response) {
					if (response.success) {
						$status.addClass('atomicedge-status-success').text(response.data.message || '<?php echo esc_js( __( 'Status refreshed!', 'atomic-edge-security' ) ); ?>');
						setTimeout(function() {
							location.reload();
						}, 500);
					} else {
						var errorMsg = response.data && response.data.message ? response.data.message : '<?php echo esc_js( __( 'Failed to refresh status.', 'atomic-edge-security' ) ); ?>';
						$status.addClass('atomicedge-status-error').text(errorMsg);
						$button.prop('disabled', false).find('.dashicons').removeClass('atomicedge-spinning');
					}
				},
				error: function(xhr, status) {
					var errorMsg = '<?php echo esc_js( __( 'Connection failed.', 'atomic-edge-security' ) ); ?>';
					if (status === 'timeout') {
						errorMsg = '<?php echo esc_js( __( 'Request timed out.', 'atomic-edge-security' ) ); ?>';
					}
					$status.addClass('atomicedge-status-error').text(errorMsg);
					$button.prop('disabled', false).find('.dashicons').removeClass('atomicedge-spinning');
				}
			});
		});

		// Purge CDN cache.
		$('#atomicedge-purge-cdn').on('click', function(e) {
			e.preventDefault();
			
			if (!confirm('<?php echo esc_js( __( 'Are you sure you want to purge the CDN cache?', 'atomic-edge-security' ) ); ?>')) {
				return;
			}
			
			var $button = $(this);
			var $status = $('#atomicedge-purge-status');
			
			$button.prop('disabled', true);
			$status.removeClass('atomicedge-status-success atomicedge-status-error').text('<?php echo esc_js( __( 'Purging...', 'atomic-edge-security' ) ); ?>');
			
			$.ajax({
				url: atomicedgeAdmin.ajaxUrl,
				type: 'POST',
				data: {
					action: 'atomicedge_purge_cdn_cache',
					nonce: atomicedgeAdmin.nonce
				},
				success: function(response) {
					if (response.success) {
						$status.addClass('atomicedge-status-success').text(response.data.message || '<?php echo esc_js( __( 'Cache purged!', 'atomic-edge-security' ) ); ?>');
					} else {
						$status.addClass('atomicedge-status-error').text(response.data ? response.data.message : '<?php echo esc_js( __( 'Failed to purge cache.', 'atomic-edge-security' ) ); ?>');
						$button.prop('disabled', false);
					}
				},
				error: function() {
					$status.addClass('atomicedge-status-error').text('<?php echo esc_js( __( 'Connection failed.', 'atomic-edge-security' ) ); ?>');
					$button.prop('disabled', false);
				}
			});
		});

		// CDN Settings form AJAX submission.
		$('#atomicedge-cdn-settings-form').on('submit', function(e) {
			e.preventDefault();
			
			var $form = $(this);
			var $status = $('#atomicedge-cdn-settings-status');
			var $submitBtn = $form.find('button[type="submit"]');
			
			$submitBtn.prop('disabled', true);
			$status.removeClass('atomicedge-status-success atomicedge-status-error').text('<?php echo esc_js( __( 'Saving...', 'atomic-edge-security' ) ); ?>');
			
			$.ajax({
				url: atomicedgeAdmin.ajaxUrl,
				type: 'POST',
				data: {
					action: 'atomicedge_save_cdn_settings',
					nonce: atomicedgeAdmin.nonce,
					formData: $form.serialize()
				},
				success: function(response) {
					if (response.success) {
						$status.addClass('atomicedge-status-success').text(response.data.message || '<?php echo esc_js( __( 'Settings saved!', 'atomic-edge-security' ) ); ?>');
					} else {
						$status.addClass('atomicedge-status-error').text(response.data ? response.data.message : '<?php echo esc_js( __( 'Failed to save settings.', 'atomic-edge-security' ) ); ?>');
					}
				},
				error: function() {
					$status.addClass('atomicedge-status-error').text('<?php echo esc_js( __( 'Connection failed.', 'atomic-edge-security' ) ); ?>');
				},
				complete: function() {
					$submitBtn.prop('disabled', false);
					setTimeout(function() {
						$status.text('');
					}, 3000);
				}
			});
		});
	});
})(jQuery);
</script>

<style type="text/css">
/* Tab Navigation */
.atomicedge-cdn .nav-tab-wrapper {
	border-bottom: 1px solid #c3c4c7;
}
.atomicedge-cdn .nav-tab {
	display: inline-flex;
	align-items: center;
	margin-left: 0;
	margin-right: 5px;
}
.atomicedge-cdn .nav-tab-active {
	background: #fff;
	border-bottom-color: #fff;
}

/* Tab Content */
.atomicedge-cdn-tab-content {
	background: #fff;
	border: 1px solid #c3c4c7;
	border-top: none;
	padding: 0;
}
.atomicedge-cdn-tab-content .atomicedge-card {
	border: none;
	border-radius: 0;
	box-shadow: none;
	margin: 0;
	padding: 20px;
	border-bottom: 1px solid #f0f0f1;
}
.atomicedge-cdn-tab-content .atomicedge-card:last-child {
	border-bottom: none;
}

/* Inline status messages */
.atomicedge-inline-status {
	margin-left: 10px;
	font-style: italic;
}
.atomicedge-inline-status.atomicedge-status-success {
	color: #00a32a;
}
.atomicedge-inline-status.atomicedge-status-error {
	color: #d63638;
}

/* Spinning animation for refresh */
.atomicedge-spinning {
	animation: atomicedge-spin 1s linear infinite;
}
@keyframes atomicedge-spin {
	from { transform: rotate(0deg); }
	to { transform: rotate(360deg); }
}

/* Status table */
.atomicedge-status-table th {
	width: 150px;
	padding: 10px 10px 10px 0;
}
.atomicedge-status-table td {
	padding: 10px 0;
}

/* Status display for non-enabled state */
.atomicedge-cdn-status-display {
	margin: 10px 0;
}
</style>
