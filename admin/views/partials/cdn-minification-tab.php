<?php
/**
 * CDN Minification Tab
 *
 * Minification settings for CSS, JavaScript, and HTML.
 *
 * @package AtomicEdge
 * @since   2.0.0
 *
 * @var AtomicEdge_Admin $this Admin instance.
 * @var bool $atomicedge_is_connected Connection status.
 * @var array $atomicedge_site_data Site data from API.
 * @var bool $atomicedge_cdn_enabled Dashboard CDN enabled status.
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Minification settings.
$minify_css  = get_option( 'atomicedge_cdn_minify_css', 'off' );
$minify_js   = get_option( 'atomicedge_cdn_minify_js', 'off' );
$minify_html = get_option( 'atomicedge_cdn_minify_html', 'off' );

// Cache statistics.
$cache_stats     = AtomicEdge_CDN::get_cache_stats();
$cache_count     = $cache_stats['count'];
$cache_size      = $cache_stats['size_human'];
$cache_css_count = $cache_stats['css_count'];
$cache_js_count  = $cache_stats['js_count'];
?>

<div class="atomicedge-card">
	<h3>
		<span class="dashicons dashicons-editor-code" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'Minification Settings', 'atomic-edge-security' ); ?>
	</h3>
	<p class="atomicedge-card-description">
		<?php esc_html_e( 'Minification reduces file sizes by removing whitespace and comments. This can improve page load times.', 'atomic-edge-security' ); ?>
	</p>
	
	<div class="atomicedge-notice atomicedge-notice-info" style="margin-bottom: 20px;">
		<span class="dashicons dashicons-info"></span>
		<div>
			<p><strong><?php esc_html_e( 'Important', 'atomic-edge-security' ); ?>:</strong> <?php esc_html_e( 'Minification can sometimes cause issues with certain themes or plugins. If you experience layout problems after enabling, try disabling individual options to identify conflicts.', 'atomic-edge-security' ); ?></p>
		</div>
	</div>

	<table class="form-table">
		<tr>
			<th scope="row">
				<label for="atomicedge-minify-css"><?php esc_html_e( 'Minify CSS', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<label class="atomicedge-toggle">
					<input type="checkbox" id="atomicedge-minify-css" name="atomicedge_cdn_minify_css" value="on" <?php checked( $minify_css, 'on' ); ?>>
					<span class="atomicedge-toggle-slider"></span>
				</label>
				<p class="description"><?php esc_html_e( 'Removes whitespace and comments from CSS files. May cause issues with some themes.', 'atomic-edge-security' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row">
				<label for="atomicedge-minify-js"><?php esc_html_e( 'Minify JavaScript', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<label class="atomicedge-toggle">
					<input type="checkbox" id="atomicedge-minify-js" name="atomicedge_cdn_minify_js" value="on" <?php checked( $minify_js, 'on' ); ?>>
					<span class="atomicedge-toggle-slider"></span>
				</label>
				<p class="description"><?php esc_html_e( 'Removes whitespace and comments from JavaScript files. May break some scripts.', 'atomic-edge-security' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row">
				<label for="atomicedge-minify-html"><?php esc_html_e( 'Minify HTML', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<label class="atomicedge-toggle">
					<input type="checkbox" id="atomicedge-minify-html" name="atomicedge_cdn_minify_html" value="on" <?php checked( $minify_html, 'on' ); ?>>
					<span class="atomicedge-toggle-slider"></span>
				</label>
				<p class="description"><?php esc_html_e( 'Removes whitespace from HTML output. Preserves script and style blocks.', 'atomic-edge-security' ); ?></p>
			</td>
		</tr>
	</table>
</div>

<div class="atomicedge-card">
	<h3>
		<span class="dashicons dashicons-database" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'Minification Cache', 'atomic-edge-security' ); ?>
	</h3>
	<p class="atomicedge-card-description">
		<?php esc_html_e( 'Minified files are cached locally to improve performance. Clear the cache if you have updated CSS or JavaScript files.', 'atomic-edge-security' ); ?>
	</p>

	<div class="atomicedge-stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0;">
		<div class="atomicedge-stat-card" style="background: #f0f0f1; padding: 15px; border-radius: 4px; text-align: center;">
			<div class="atomicedge-stat-value" style="font-size: 24px; font-weight: 600; color: #1d2327;">
				<?php echo esc_html( $cache_count ); ?>
			</div>
			<div class="atomicedge-stat-label" style="font-size: 13px; color: #50575e;">
				<?php esc_html_e( 'Total Files', 'atomic-edge-security' ); ?>
			</div>
		</div>
		<div class="atomicedge-stat-card" style="background: #f0f0f1; padding: 15px; border-radius: 4px; text-align: center;">
			<div class="atomicedge-stat-value" style="font-size: 24px; font-weight: 600; color: #1d2327;">
				<?php echo esc_html( $cache_size ); ?>
			</div>
			<div class="atomicedge-stat-label" style="font-size: 13px; color: #50575e;">
				<?php esc_html_e( 'Cache Size', 'atomic-edge-security' ); ?>
			</div>
		</div>
		<div class="atomicedge-stat-card" style="background: #f0f0f1; padding: 15px; border-radius: 4px; text-align: center;">
			<div class="atomicedge-stat-value" style="font-size: 24px; font-weight: 600; color: #1d2327;">
				<?php echo esc_html( $cache_css_count ); ?>
			</div>
			<div class="atomicedge-stat-label" style="font-size: 13px; color: #50575e;">
				<?php esc_html_e( 'CSS Files', 'atomic-edge-security' ); ?>
			</div>
		</div>
		<div class="atomicedge-stat-card" style="background: #f0f0f1; padding: 15px; border-radius: 4px; text-align: center;">
			<div class="atomicedge-stat-value" style="font-size: 24px; font-weight: 600; color: #1d2327;">
				<?php echo esc_html( $cache_js_count ); ?>
			</div>
			<div class="atomicedge-stat-label" style="font-size: 13px; color: #50575e;">
				<?php esc_html_e( 'JS Files', 'atomic-edge-security' ); ?>
			</div>
		</div>
	</div>

	<div style="margin-top: 15px;">
		<button type="button" id="atomicedge-clear-minify-cache" class="button button-secondary">
			<span class="dashicons dashicons-trash" style="margin-top: 3px;"></span>
			<?php esc_html_e( 'Clear Minification Cache', 'atomic-edge-security' ); ?>
		</button>
		<span id="atomicedge-clear-cache-status" style="margin-left: 10px;"></span>
	</div>
</div>

<script type="text/javascript">
(function($) {
	'use strict';
	$(document).ready(function() {
		$('#atomicedge-clear-minify-cache').on('click', function(e) {
			e.preventDefault();
			var $button = $(this);
			var $status = $('#atomicedge-clear-cache-status');
			
			$button.prop('disabled', true);
			$status.html('<span class="spinner is-active" style="float: none; margin: 0;"></span> <?php echo esc_js( __( 'Clearing...', 'atomic-edge-security' ) ); ?>');
			
			$.ajax({
				url: atomicedgeAdmin.ajaxUrl,
				type: 'POST',
				data: {
					action: 'atomicedge_clear_minify_cache',
					nonce: atomicedgeAdmin.nonce
				},
				success: function(response) {
					if (response.success) {
						$status.html('<span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span> ' + response.data.message);
						// Refresh stats after short delay.
						setTimeout(function() {
							location.reload();
						}, 1500);
					} else {
						$status.html('<span class="dashicons dashicons-warning" style="color: #d63638;"></span> ' + (response.data.message || '<?php echo esc_js( __( 'Failed to clear cache', 'atomic-edge-security' ) ); ?>'));
					}
				},
				error: function() {
					$status.html('<span class="dashicons dashicons-warning" style="color: #d63638;"></span> <?php echo esc_js( __( 'Request failed', 'atomic-edge-security' ) ); ?>');
				},
				complete: function() {
					$button.prop('disabled', false);
				}
			});
		});
	});
})(jQuery);
</script>
