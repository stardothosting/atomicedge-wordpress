<?php
/**
 * CDN General Tab
 *
 * General CDN settings including enable switch and file type toggles.
 * CDN URL comes from ATOMICEDGE_CDN_DEV_URL constant or dashboard API.
 *
 * @package AtomicEdge
 * @since   2.0.0
 *
 * @var AtomicEdge_Admin $this Admin instance.
 * @var bool $atomicedge_is_connected Connection status.
 * @var array $atomicedge_site_data Site data from API.
 * @var bool $atomicedge_cdn_enabled CDN enabled status.
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Local CDN settings.
$local_cdn_enabled = get_option( 'atomicedge_cdn_local_enabled' ) === 'on';
$cdn_css           = get_option( 'atomicedge_cdn_css', 'on' );
$cdn_js            = get_option( 'atomicedge_cdn_js', 'on' );
$cdn_media         = get_option( 'atomicedge_cdn_media', 'on' );

// Get CDN hostname.
$cdn_hostname = AtomicEdge_CDN::get_cdn_hostname();

// Check if using dev constant.
$using_dev_constant = defined( 'ATOMICEDGE_CDN_DEV_URL' ) && ATOMICEDGE_CDN_DEV_URL;

// Test URL.
$test_url = '';
if ( ! empty( $cdn_hostname ) ) {
	$test_url = 'https://' . $cdn_hostname . '/wp-content/plugins/atomicedge/admin/images/logo.svg';
}
?>

<!-- Master Enable Switch -->
<div class="atomicedge-card">
	<h3>
		<span class="dashicons dashicons-admin-plugins" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'Enable CDN', 'atomic-edge-security' ); ?>
	</h3>

	<?php if ( $using_dev_constant ) : ?>
		<div class="atomicedge-notice atomicedge-notice-info" style="margin-bottom: 15px;">
			<span class="dashicons dashicons-info"></span>
			<div>
				<p><strong><?php esc_html_e( 'Development Mode Active', 'atomic-edge-security' ); ?></strong></p>
				<p><?php esc_html_e( 'Using ATOMICEDGE_CDN_DEV_URL constant from wp-config.php:', 'atomic-edge-security' ); ?> <code><?php echo esc_html( ATOMICEDGE_CDN_DEV_URL ); ?></code></p>
			</div>
		</div>
	<?php endif; ?>

	<table class="form-table">
		<tr>
			<th scope="row">
				<label for="atomicedge-cdn-local-enabled"><?php esc_html_e( 'Enable Atomic Edge CDN', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<label class="atomicedge-toggle">
					<input type="checkbox" id="atomicedge-cdn-local-enabled" name="atomicedge_cdn_local_enabled" value="on" <?php checked( $local_cdn_enabled ); ?>>
					<span class="atomicedge-toggle-slider"></span>
				</label>
				<p class="description">
					<?php esc_html_e( 'When enabled, static assets will be served through the CDN.', 'atomic-edge-security' ); ?>
				</p>
			</td>
		</tr>
	</table>
</div>

<!-- CDN Status / Test -->
<?php if ( ! empty( $cdn_hostname ) ) : ?>
<div class="atomicedge-card">
	<h3>
		<span class="dashicons dashicons-cloud" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'CDN Status', 'atomic-edge-security' ); ?>
	</h3>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'CDN Hostname', 'atomic-edge-security' ); ?></th>
			<td>
				<code id="atomicedge-cdn-hostname"><?php echo esc_html( $cdn_hostname ); ?></code>
				<button type="button" class="button button-small atomicedge-copy-btn" data-copy-target="#atomicedge-cdn-hostname" title="<?php esc_attr_e( 'Copy to clipboard', 'atomic-edge-security' ); ?>">
					<span class="dashicons dashicons-clipboard"></span>
				</button>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Status', 'atomic-edge-security' ); ?></th>
			<td>
				<?php if ( AtomicEdge_CDN::is_cdn_enabled() ) : ?>
					<span class="atomicedge-status-badge atomicedge-status-active">
						<span class="atomicedge-status-indicator"></span>
						<?php esc_html_e( 'CDN Active', 'atomic-edge-security' ); ?>
					</span>
				<?php else : ?>
					<span class="atomicedge-status-badge atomicedge-status-inactive">
						<span class="atomicedge-status-indicator"></span>
						<?php esc_html_e( 'CDN Disabled', 'atomic-edge-security' ); ?>
					</span>
					<p class="description"><?php esc_html_e( 'Enable the switch above to activate CDN rewriting.', 'atomic-edge-security' ); ?></p>
				<?php endif; ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Test CDN', 'atomic-edge-security' ); ?></th>
			<td>
				<a href="<?php echo esc_url( $test_url ); ?>" target="_blank" rel="noopener noreferrer" class="button">
					<?php esc_html_e( 'Test CDN Connection', 'atomic-edge-security' ); ?>
					<span class="dashicons dashicons-external" style="margin-top: 3px;"></span>
				</a>
				<p class="description">
					<?php esc_html_e( 'Click to verify your CDN is serving assets correctly.', 'atomic-edge-security' ); ?>
				</p>
			</td>
		</tr>
	</table>
</div>
<?php endif; ?>

<!-- File Types -->
<div class="atomicedge-card">
	<h3>
		<span class="dashicons dashicons-media-default" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'File Types', 'atomic-edge-security' ); ?>
	</h3>
	<p class="atomicedge-card-description">
		<?php esc_html_e( 'Choose which types of files should be served through the CDN.', 'atomic-edge-security' ); ?>
	</p>
	<table class="form-table">
		<tr>
			<th scope="row">
				<label for="atomicedge-cdn-css"><?php esc_html_e( 'CSS Files', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<label class="atomicedge-toggle">
					<input type="checkbox" id="atomicedge-cdn-css" name="atomicedge_cdn_css" value="on" <?php checked( $cdn_css, 'on' ); ?>>
					<span class="atomicedge-toggle-slider"></span>
				</label>
				<p class="description"><?php esc_html_e( 'Stylesheets (.css files)', 'atomic-edge-security' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row">
				<label for="atomicedge-cdn-js"><?php esc_html_e( 'JavaScript Files', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<label class="atomicedge-toggle">
					<input type="checkbox" id="atomicedge-cdn-js" name="atomicedge_cdn_js" value="on" <?php checked( $cdn_js, 'on' ); ?>>
					<span class="atomicedge-toggle-slider"></span>
				</label>
				<p class="description"><?php esc_html_e( 'JavaScript files (.js files)', 'atomic-edge-security' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row">
				<label for="atomicedge-cdn-media"><?php esc_html_e( 'Image & Media Files', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<label class="atomicedge-toggle">
					<input type="checkbox" id="atomicedge-cdn-media" name="atomicedge_cdn_media" value="on" <?php checked( $cdn_media, 'on' ); ?>>
					<span class="atomicedge-toggle-slider"></span>
				</label>
				<p class="description"><?php esc_html_e( 'Images, fonts, PDFs, videos, and other media files', 'atomic-edge-security' ); ?></p>
			</td>
		</tr>
	</table>
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
	});
})(jQuery);
</script>
