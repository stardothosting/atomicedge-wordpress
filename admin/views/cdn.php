<?php
/**
 * CDN Page View
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-cdn">
		<h2><?php esc_html_e( 'CDN', 'atomic-edge-security' ); ?></h2>
		<p class="atomicedge-page-description">
			<?php esc_html_e( 'Manage your Content Delivery Network settings. CDN caches your static assets globally for faster load times.', 'atomic-edge-security' ); ?>
		</p>

		<!-- CDN Status Loading -->
		<div id="atomicedge-cdn-loading" class="atomicedge-loading">
			<span class="spinner is-active"></span>
			<span><?php esc_html_e( 'Loading CDN status...', 'atomic-edge-security' ); ?></span>
		</div>

		<!-- CDN Status Display -->
		<div id="atomicedge-cdn-content" style="display: none;">
			<!-- CDN Status Card -->
			<div class="atomicedge-card atomicedge-cdn-status-card">
				<h3><?php esc_html_e( 'CDN Status', 'atomic-edge-security' ); ?></h3>
				
				<div class="atomicedge-cdn-status-grid">
					<div class="atomicedge-cdn-status-item">
						<span class="atomicedge-cdn-label"><?php esc_html_e( 'Status', 'atomic-edge-security' ); ?></span>
						<span id="atomicedge-cdn-enabled-status" class="atomicedge-cdn-value atomicedge-cdn-status-badge">
							<span class="atomicedge-status-indicator"></span>
							<span class="atomicedge-status-text"><?php esc_html_e( 'Loading...', 'atomic-edge-security' ); ?></span>
						</span>
					</div>
					
					<div class="atomicedge-cdn-status-item" id="atomicedge-cdn-url-row" style="display: none;">
						<span class="atomicedge-cdn-label"><?php esc_html_e( 'CDN URL', 'atomic-edge-security' ); ?></span>
						<span class="atomicedge-cdn-value">
							<code id="atomicedge-cdn-url"></code>
							<button type="button" class="button button-small atomicedge-copy-btn" data-copy-target="#atomicedge-cdn-url" title="<?php esc_attr_e( 'Copy to clipboard', 'atomic-edge-security' ); ?>">
								<span class="dashicons dashicons-clipboard"></span>
							</button>
						</span>
					</div>
					
					<div class="atomicedge-cdn-status-item" id="atomicedge-cdn-last-purge-row" style="display: none;">
						<span class="atomicedge-cdn-label"><?php esc_html_e( 'Last Cache Purge', 'atomic-edge-security' ); ?></span>
						<span id="atomicedge-cdn-last-purge" class="atomicedge-cdn-value"><?php esc_html_e( 'Never', 'atomic-edge-security' ); ?></span>
					</div>
					
					<div class="atomicedge-cdn-status-item" id="atomicedge-cdn-bandwidth-row" style="display: none;">
						<span class="atomicedge-cdn-label"><?php esc_html_e( 'Bandwidth Used', 'atomic-edge-security' ); ?></span>
						<span id="atomicedge-cdn-bandwidth" class="atomicedge-cdn-value"><?php esc_html_e( '0 B', 'atomic-edge-security' ); ?></span>
					</div>
				</div>
			</div>

			<!-- CDN Not Enabled Message -->
			<div id="atomicedge-cdn-disabled-notice" class="atomicedge-notice atomicedge-notice-info" style="display: none;">
				<span class="dashicons dashicons-info"></span>
				<div>
					<p><strong><?php esc_html_e( 'CDN is not enabled', 'atomic-edge-security' ); ?></strong></p>
					<p><?php esc_html_e( 'Enable CDN in your Atomic Edge dashboard to accelerate your site with global content delivery.', 'atomic-edge-security' ); ?></p>
					<p>
						<a href="https://dashboard.atomicedge.io" target="_blank" rel="noopener noreferrer" class="button button-primary">
							<?php esc_html_e( 'Go to Atomic Edge Dashboard', 'atomic-edge-security' ); ?>
							<span class="dashicons dashicons-external"></span>
						</a>
					</p>
				</div>
			</div>

			<!-- CDN Enabled Content -->
			<div id="atomicedge-cdn-enabled-content" style="display: none;">
				<!-- Cache Purge Card -->
				<div class="atomicedge-card atomicedge-cdn-purge-card">
					<h3><?php esc_html_e( 'Cache Purge', 'atomic-edge-security' ); ?></h3>
					<p class="atomicedge-card-description">
						<?php esc_html_e( 'Clear the CDN cache to serve fresh content. Use this after making significant changes to your site.', 'atomic-edge-security' ); ?>
					</p>
					
					<div class="atomicedge-cdn-purge-actions">
						<button type="button" id="atomicedge-purge-cdn" class="button button-primary">
							<span class="dashicons dashicons-update"></span>
							<?php esc_html_e( 'Purge Cache', 'atomic-edge-security' ); ?>
						</button>
						<span id="atomicedge-purge-cooldown" class="atomicedge-cooldown-notice" style="display: none;">
							<span class="dashicons dashicons-clock"></span>
							<span class="atomicedge-cooldown-text"></span>
						</span>
					</div>
					
					<div id="atomicedge-purge-progress" class="atomicedge-inline-progress" style="display: none;">
						<span class="spinner is-active"></span>
						<span><?php esc_html_e( 'Purging cache...', 'atomic-edge-security' ); ?></span>
					</div>
				</div>

				<!-- Optimization Settings Card -->
				<div class="atomicedge-card atomicedge-cdn-settings-card">
					<h3><?php esc_html_e( 'Optimization Settings', 'atomic-edge-security' ); ?></h3>
					<p class="atomicedge-card-description">
						<?php esc_html_e( 'Configure how CDN optimizes your content for faster delivery.', 'atomic-edge-security' ); ?>
					</p>
					
					<form id="atomicedge-cdn-settings-form">
						<table class="form-table atomicedge-settings-table">
							<tbody>
								<tr>
									<th scope="row">
										<label for="atomicedge-cdn-brotli"><?php esc_html_e( 'Brotli Compression', 'atomic-edge-security' ); ?></label>
									</th>
									<td>
										<label class="atomicedge-toggle">
											<input type="checkbox" id="atomicedge-cdn-brotli" name="brotli" value="1">
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
											<input type="checkbox" id="atomicedge-cdn-js-min" name="js_minification" value="1">
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
											<input type="checkbox" id="atomicedge-cdn-css-min" name="css_minification" value="1">
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
											<input type="checkbox" id="atomicedge-cdn-image-opt" name="image_optimization" value="1">
											<span class="atomicedge-toggle-slider"></span>
										</label>
										<p class="description"><?php esc_html_e( 'Automatically optimize images for faster loading.', 'atomic-edge-security' ); ?></p>
									</td>
								</tr>
							</tbody>
						</table>
						
						<div class="atomicedge-form-actions">
							<button type="submit" class="button button-primary">
								<span class="dashicons dashicons-saved"></span>
								<?php esc_html_e( 'Save Settings', 'atomic-edge-security' ); ?>
							</button>
							<span id="atomicedge-cdn-settings-status" class="atomicedge-form-status"></span>
						</div>
					</form>
				</div>
			</div>
		</div>
	</div>
</div>

<script type="text/javascript">
(function($) {
	'use strict';

	var AtomicEdgeCDN = {
		nonce: atomicedge_ajax.nonce,
		cdnStatus: null,
		cooldownTimer: null,

		init: function() {
			this.loadStatus();
			this.bindEvents();
		},

		bindEvents: function() {
			$('#atomicedge-purge-cdn').on('click', this.purgeCache.bind(this));
			$('#atomicedge-cdn-settings-form').on('submit', this.saveSettings.bind(this));
			$('.atomicedge-copy-btn').on('click', this.copyToClipboard.bind(this));
		},

		loadStatus: function() {
			var self = this;
			
			$.ajax({
				url: atomicedge_ajax.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_get_cdn_status',
					nonce: this.nonce
				},
				success: function(response) {
					$('#atomicedge-cdn-loading').hide();
					$('#atomicedge-cdn-content').show();
					
					if (response.success) {
						self.cdnStatus = response.data;
						self.renderStatus(response.data);
					} else {
						self.showError(response.data ? response.data.message : '<?php echo esc_js( __( 'Failed to load CDN status.', 'atomic-edge-security' ) ); ?>');
					}
				},
				error: function() {
					$('#atomicedge-cdn-loading').hide();
					$('#atomicedge-cdn-content').show();
					self.showError('<?php echo esc_js( __( 'Failed to connect to the server.', 'atomic-edge-security' ) ); ?>');
				}
			});
		},

		renderStatus: function(data) {
			var $statusBadge = $('#atomicedge-cdn-enabled-status');
			var $indicator = $statusBadge.find('.atomicedge-status-indicator');
			var $text = $statusBadge.find('.atomicedge-status-text');
			
			if (data.cdn_enabled) {
				$indicator.addClass('atomicedge-status-active');
				$text.text('<?php echo esc_js( __( 'Active', 'atomic-edge-security' ) ); ?>');
				$statusBadge.addClass('atomicedge-status-active');
				
				// Show CDN URL.
				if (data.cdn_url) {
					$('#atomicedge-cdn-url').text(data.cdn_url);
					$('#atomicedge-cdn-url-row').show();
				}
				
				// Show last purge.
				if (data.last_purged_at) {
					var purgeDate = new Date(data.last_purged_at);
					$('#atomicedge-cdn-last-purge').text(purgeDate.toLocaleString());
					$('#atomicedge-cdn-last-purge-row').show();
				}
				
				// Show bandwidth.
				if (data.bandwidth && data.bandwidth.total > 0) {
					$('#atomicedge-cdn-bandwidth').text(this.formatBytes(data.bandwidth.total));
					$('#atomicedge-cdn-bandwidth-row').show();
				}
				
				// Show purge button state.
				if (!data.can_purge) {
					$('#atomicedge-purge-cdn').prop('disabled', true);
					$('#atomicedge-purge-cooldown').show();
					$('#atomicedge-purge-cooldown .atomicedge-cooldown-text').text('<?php echo esc_js( __( 'Please wait before purging again.', 'atomic-edge-security' ) ); ?>');
				}
				
				// Set optimization toggles.
				if (data.optimization) {
					$('#atomicedge-cdn-brotli').prop('checked', data.optimization.brotli);
					$('#atomicedge-cdn-js-min').prop('checked', data.optimization.js_minification);
					$('#atomicedge-cdn-css-min').prop('checked', data.optimization.css_minification);
					$('#atomicedge-cdn-image-opt').prop('checked', data.optimization.image_optimization);
				}
				
				$('#atomicedge-cdn-disabled-notice').hide();
				$('#atomicedge-cdn-enabled-content').show();
			} else {
				$indicator.addClass('atomicedge-status-inactive');
				$text.text('<?php echo esc_js( __( 'Disabled', 'atomic-edge-security' ) ); ?>');
				$statusBadge.addClass('atomicedge-status-inactive');
				
				$('#atomicedge-cdn-disabled-notice').show();
				$('#atomicedge-cdn-enabled-content').hide();
			}
		},

		purgeCache: function(e) {
			e.preventDefault();
			
			var self = this;
			var $button = $('#atomicedge-purge-cdn');
			var $progress = $('#atomicedge-purge-progress');
			
			$button.prop('disabled', true);
			$progress.show();
			
			$.ajax({
				url: atomicedge_ajax.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_purge_cdn_cache',
					nonce: this.nonce
				},
				success: function(response) {
					$progress.hide();
					
					if (response.success) {
						self.showSuccess(response.data.message || '<?php echo esc_js( __( 'Cache purge has been queued.', 'atomic-edge-security' ) ); ?>');
						
						// Update last purge time.
						if (response.data.purged_at) {
							var purgeDate = new Date(response.data.purged_at);
							$('#atomicedge-cdn-last-purge').text(purgeDate.toLocaleString());
							$('#atomicedge-cdn-last-purge-row').show();
						}
						
						// Show cooldown.
						$('#atomicedge-purge-cooldown').show();
						$('#atomicedge-purge-cooldown .atomicedge-cooldown-text').text('<?php echo esc_js( __( 'Please wait before purging again.', 'atomic-edge-security' ) ); ?>');
						
						// Enable button after cooldown (5 minutes).
						setTimeout(function() {
							$button.prop('disabled', false);
							$('#atomicedge-purge-cooldown').hide();
						}, 5 * 60 * 1000);
					} else {
						self.showError(response.data ? response.data.message : '<?php echo esc_js( __( 'Failed to purge cache.', 'atomic-edge-security' ) ); ?>');
						$button.prop('disabled', false);
					}
				},
				error: function() {
					$progress.hide();
					$button.prop('disabled', false);
					self.showError('<?php echo esc_js( __( 'Failed to connect to the server.', 'atomic-edge-security' ) ); ?>');
				}
			});
		},

		saveSettings: function(e) {
			e.preventDefault();
			
			var self = this;
			var $form = $('#atomicedge-cdn-settings-form');
			var $button = $form.find('button[type="submit"]');
			var $status = $('#atomicedge-cdn-settings-status');
			
			$button.prop('disabled', true);
			$status.removeClass('atomicedge-status-success atomicedge-status-error').text('<?php echo esc_js( __( 'Saving...', 'atomic-edge-security' ) ); ?>');
			
			$.ajax({
				url: atomicedge_ajax.ajax_url,
				type: 'POST',
				data: {
					action: 'atomicedge_update_cdn_settings',
					nonce: this.nonce,
					brotli: $('#atomicedge-cdn-brotli').is(':checked') ? 'true' : 'false',
					js_minification: $('#atomicedge-cdn-js-min').is(':checked') ? 'true' : 'false',
					css_minification: $('#atomicedge-cdn-css-min').is(':checked') ? 'true' : 'false',
					image_optimization: $('#atomicedge-cdn-image-opt').is(':checked') ? 'true' : 'false'
				},
				success: function(response) {
					$button.prop('disabled', false);
					
					if (response.success) {
						$status.addClass('atomicedge-status-success').text('<?php echo esc_js( __( 'Settings saved!', 'atomic-edge-security' ) ); ?>');
						setTimeout(function() {
							$status.text('');
						}, 3000);
					} else {
						$status.addClass('atomicedge-status-error').text(response.data ? response.data.message : '<?php echo esc_js( __( 'Failed to save settings.', 'atomic-edge-security' ) ); ?>');
					}
				},
				error: function() {
					$button.prop('disabled', false);
					$status.addClass('atomicedge-status-error').text('<?php echo esc_js( __( 'Failed to connect to the server.', 'atomic-edge-security' ) ); ?>');
				}
			});
		},

		copyToClipboard: function(e) {
			e.preventDefault();
			
			var $button = $(e.currentTarget);
			var targetSelector = $button.data('copy-target');
			var textToCopy = $(targetSelector).text();
			
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(textToCopy).then(function() {
					$button.find('.dashicons').removeClass('dashicons-clipboard').addClass('dashicons-yes');
					setTimeout(function() {
						$button.find('.dashicons').removeClass('dashicons-yes').addClass('dashicons-clipboard');
					}, 2000);
				});
			} else {
				// Fallback for older browsers.
				var $temp = $('<textarea>');
				$('body').append($temp);
				$temp.val(textToCopy).select();
				document.execCommand('copy');
				$temp.remove();
				
				$button.find('.dashicons').removeClass('dashicons-clipboard').addClass('dashicons-yes');
				setTimeout(function() {
					$button.find('.dashicons').removeClass('dashicons-yes').addClass('dashicons-clipboard');
				}, 2000);
			}
		},

		formatBytes: function(bytes) {
			if (bytes === 0) return '0 B';
			
			var k = 1024;
			var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
			var i = Math.floor(Math.log(bytes) / Math.log(k));
			
			return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
		},

		showSuccess: function(message) {
			this.showNotice(message, 'success');
		},

		showError: function(message) {
			this.showNotice(message, 'error');
		},

		showNotice: function(message, type) {
			var $notice = $('<div class="notice notice-' + type + ' is-dismissible"><p>' + message + '</p></div>');
			$('.atomicedge-cdn h2').after($notice);
			
			// Auto-dismiss after 5 seconds.
			setTimeout(function() {
				$notice.fadeOut(function() {
					$(this).remove();
				});
			}, 5000);
		}
	};

	$(document).ready(function() {
		AtomicEdgeCDN.init();
	});
})(jQuery);
</script>
