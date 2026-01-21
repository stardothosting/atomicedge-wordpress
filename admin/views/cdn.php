<?php
/**
 * CDN Page View
 *
 * This page allows users to configure CDN settings for their site.
 * CDN settings are stored locally in WordPress options.
 * The API is only called when the user clicks "Refresh Status" or "Purge Cache".
 *
 * User scenarios:
 * 1. New user not connected to AtomicEdge - show connection prompt
 * 2. Connected user without CDN enabled - show how to enable CDN
 * 3. Connected user with CDN enabled - show settings and controls
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get connection status and CDN settings.
$atomicedge_is_connected = $this->api->is_connected();
$atomicedge_site_data    = get_option( 'atomicedge_site_data', array() );

// CDN settings from site data (populated when site connects or refreshes).
$atomicedge_cdn_enabled  = ! empty( $atomicedge_site_data['cdn_enabled'] );
$atomicedge_cdn_prefix   = $atomicedge_site_data['cdn_prefix'] ?? '';
$atomicedge_cdn_url      = $atomicedge_site_data['cdn_url'] ?? '';

// Local CDN optimization settings (stored in WP options).
$atomicedge_cdn_brotli     = get_option( 'atomicedge_cdn_brotli', true );
$atomicedge_cdn_js_min     = get_option( 'atomicedge_cdn_js_minification', false );
$atomicedge_cdn_css_min    = get_option( 'atomicedge_cdn_css_minification', false );
$atomicedge_cdn_image_opt  = get_option( 'atomicedge_cdn_image_optimization', false );

// Last purge time.
$atomicedge_cdn_last_purge = get_option( 'atomicedge_cdn_last_purge', '' );
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-cdn">
		<h2><?php esc_html_e( 'CDN Settings', 'atomic-edge-security' ); ?></h2>
		<p class="atomicedge-page-description">
			<?php esc_html_e( 'Content Delivery Network (CDN) caches your static assets on global edge servers for faster page loads.', 'atomic-edge-security' ); ?>
		</p>

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

		<?php elseif ( ! $atomicedge_cdn_enabled ) : ?>
			<!-- Connected but CDN Not Enabled -->
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
			<!-- CDN Enabled - Show Full Settings -->
			
			<!-- CDN Status Card -->
			<div class="atomicedge-card">
				<h3><?php esc_html_e( 'CDN Status', 'atomic-edge-security' ); ?></h3>
				<table class="form-table atomicedge-status-table">
					<tr>
						<th><?php esc_html_e( 'Status', 'atomic-edge-security' ); ?></th>
						<td>
							<span class="atomicedge-status-badge atomicedge-status-active">
								<span class="atomicedge-status-indicator"></span>
								<span><?php esc_html_e( 'Active', 'atomic-edge-security' ); ?></span>
							</span>
						</td>
					</tr>
					<?php if ( ! empty( $atomicedge_cdn_prefix ) ) : ?>
					<tr>
						<th><?php esc_html_e( 'CDN Prefix', 'atomic-edge-security' ); ?></th>
						<td><code><?php echo esc_html( $atomicedge_cdn_prefix ); ?></code></td>
					</tr>
					<?php endif; ?>
					<?php if ( ! empty( $atomicedge_cdn_url ) ) : ?>
					<tr>
						<th><?php esc_html_e( 'CDN URL', 'atomic-edge-security' ); ?></th>
						<td>
							<code id="atomicedge-cdn-url-value"><?php echo esc_html( $atomicedge_cdn_url ); ?></code>
							<button type="button" class="button button-small atomicedge-copy-btn" data-copy-target="#atomicedge-cdn-url-value" title="<?php esc_attr_e( 'Copy to clipboard', 'atomic-edge-security' ); ?>">
								<span class="dashicons dashicons-clipboard"></span>
							</button>
						</td>
					</tr>
					<?php endif; ?>
					<?php if ( ! empty( $atomicedge_cdn_last_purge ) ) : ?>
					<tr>
						<th><?php esc_html_e( 'Last Cache Purge', 'atomic-edge-security' ); ?></th>
						<td><?php echo esc_html( $atomicedge_cdn_last_purge ); ?></td>
					</tr>
					<?php endif; ?>
				</table>
				<p style="margin-top: 15px;">
					<button type="button" id="atomicedge-cdn-refresh" class="button">
						<span class="dashicons dashicons-update" style="margin-top: 3px;"></span>
						<?php esc_html_e( 'Refresh Status', 'atomic-edge-security' ); ?>
					</button>
				</p>
			</div>

			<!-- Cache Purge Card -->
			<div class="atomicedge-card">
				<h3><?php esc_html_e( 'Purge Cache', 'atomic-edge-security' ); ?></h3>
				<p class="atomicedge-card-description">
					<?php esc_html_e( 'Clear the CDN cache to serve fresh content. Use this after making significant changes to your site. Cache purge can only be performed once every 5 minutes.', 'atomic-edge-security' ); ?>
				</p>
				<p>
					<button type="button" id="atomicedge-purge-cdn" class="button button-primary">
						<span class="dashicons dashicons-trash" style="margin-top: 3px;"></span>
						<?php esc_html_e( 'Purge Cache', 'atomic-edge-security' ); ?>
					</button>
					<span id="atomicedge-purge-status" class="atomicedge-inline-status"></span>
				</p>
			</div>

			<!-- CDN Optimization Settings -->
			<div class="atomicedge-card">
				<h3><?php esc_html_e( 'Optimization Settings', 'atomic-edge-security' ); ?></h3>
				<p class="atomicedge-card-description">
					<?php esc_html_e( 'Configure how CDN optimizes your content.', 'atomic-edge-security' ); ?>
				</p>
				
				<form id="atomicedge-cdn-settings-form" method="post" action="">
					<?php wp_nonce_field( 'atomicedge_cdn_settings', 'atomicedge_cdn_nonce' ); ?>
					
					<table class="form-table">
						<tr>
							<th scope="row">
								<label for="atomicedge-cdn-brotli"><?php esc_html_e( 'Brotli Compression', 'atomic-edge-security' ); ?></label>
							</th>
							<td>
								<label class="atomicedge-toggle">
									<input type="checkbox" id="atomicedge-cdn-brotli" name="atomicedge_cdn_brotli" value="1" <?php checked( $atomicedge_cdn_brotli ); ?>>
									<span class="atomicedge-toggle-slider"></span>
								</label>
								<p class="description"><?php esc_html_e( 'Enable Brotli compression for smaller file sizes and faster transfers.', 'atomic-edge-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="atomicedge-cdn-js-min"><?php esc_html_e( 'JavaScript Minification', 'atomic-edge-security' ); ?></label>
							</th>
							<td>
								<label class="atomicedge-toggle">
									<input type="checkbox" id="atomicedge-cdn-js-min" name="atomicedge_cdn_js_minification" value="1" <?php checked( $atomicedge_cdn_js_min ); ?>>
									<span class="atomicedge-toggle-slider"></span>
								</label>
								<p class="description"><?php esc_html_e( 'Minify JavaScript files to reduce their size.', 'atomic-edge-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="atomicedge-cdn-css-min"><?php esc_html_e( 'CSS Minification', 'atomic-edge-security' ); ?></label>
							</th>
							<td>
								<label class="atomicedge-toggle">
									<input type="checkbox" id="atomicedge-cdn-css-min" name="atomicedge_cdn_css_minification" value="1" <?php checked( $atomicedge_cdn_css_min ); ?>>
									<span class="atomicedge-toggle-slider"></span>
								</label>
								<p class="description"><?php esc_html_e( 'Minify CSS files to reduce their size.', 'atomic-edge-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="atomicedge-cdn-image-opt"><?php esc_html_e( 'Image Optimization', 'atomic-edge-security' ); ?></label>
							</th>
							<td>
								<label class="atomicedge-toggle">
									<input type="checkbox" id="atomicedge-cdn-image-opt" name="atomicedge_cdn_image_optimization" value="1" <?php checked( $atomicedge_cdn_image_opt ); ?>>
									<span class="atomicedge-toggle-slider"></span>
								</label>
								<p class="description"><?php esc_html_e( 'Automatically optimize images for faster loading.', 'atomic-edge-security' ); ?></p>
							</td>
						</tr>
					</table>
					
					<p class="submit">
						<button type="submit" name="atomicedge_save_cdn_settings" class="button button-primary">
							<?php esc_html_e( 'Save Settings', 'atomic-edge-security' ); ?>
						</button>
						<span id="atomicedge-cdn-settings-status" class="atomicedge-inline-status"></span>
					</p>
				</form>
			</div>

		<?php endif; ?>
	</div>
</div>

<script type="text/javascript">
(function($) {
	'use strict';

	$(document).ready(function() {
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
			$button.prop('disabled', true).find('.dashicons').addClass('atomicedge-spinning');
			
			$.ajax({
				url: atomicedge_ajax.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_refresh_cdn_status',
					nonce: atomicedge_ajax.nonce
				},
				success: function(response) {
					if (response.success) {
						// Reload page to show updated status.
						location.reload();
					} else {
						alert(response.data ? response.data.message : '<?php echo esc_js( __( 'Failed to refresh status.', 'atomic-edge-security' ) ); ?>');
						$button.prop('disabled', false).find('.dashicons').removeClass('atomicedge-spinning');
					}
				},
				error: function() {
					alert('<?php echo esc_js( __( 'Failed to connect to the server.', 'atomic-edge-security' ) ); ?>');
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
				url: atomicedge_ajax.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_purge_cdn_cache',
					nonce: atomicedge_ajax.nonce
				},
				success: function(response) {
					if (response.success) {
						$status.addClass('atomicedge-status-success').text(response.data.message || '<?php echo esc_js( __( 'Cache purged successfully!', 'atomic-edge-security' ) ); ?>');
						// Keep button disabled for cooldown (re-enable on page refresh).
					} else {
						$status.addClass('atomicedge-status-error').text(response.data ? response.data.message : '<?php echo esc_js( __( 'Failed to purge cache.', 'atomic-edge-security' ) ); ?>');
						$button.prop('disabled', false);
					}
				},
				error: function() {
					$status.addClass('atomicedge-status-error').text('<?php echo esc_js( __( 'Failed to connect to the server.', 'atomic-edge-security' ) ); ?>');
					$button.prop('disabled', false);
				}
			});
		});
	});
})(jQuery);
</script>

<style type="text/css">
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
