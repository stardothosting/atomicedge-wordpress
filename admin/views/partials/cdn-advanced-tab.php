<?php
/**
 * CDN Advanced Tab
 *
 * Advanced CDN settings including URL exclusions and debugging.
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

// Advanced settings.
$reject_files = get_option( 'atomicedge_cdn_reject_files', '' );
$dns_prefetch = get_option( 'atomicedge_cdn_dns_prefetch', 'on' );

// Default exclusion patterns for reference.
$default_exclusions = array(
	'.php',
	'wp-login.php',
	'wp-admin/',
	'xmlrpc.php',
	'wp-cron.php',
	'admin-ajax.php',
);
?>

<div class="atomicedge-card">
	<h3>
		<span class="dashicons dashicons-no-alt" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'URL Exclusions', 'atomic-edge-security' ); ?>
	</h3>
	<p class="atomicedge-card-description">
		<?php esc_html_e( 'Specify URL patterns that should NOT be rewritten to use the CDN. Enter one pattern per line.', 'atomic-edge-security' ); ?>
	</p>

	<table class="form-table">
		<tr>
			<th scope="row">
				<label for="atomicedge-reject-files"><?php esc_html_e( 'Exclude Patterns', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<textarea id="atomicedge-reject-files" name="atomicedge_cdn_reject_files" rows="8" class="large-text code" placeholder="wp-admin/&#10;wp-login.php&#10;/my-custom-path/"><?php echo esc_textarea( $reject_files ); ?></textarea>
				<p class="description">
					<?php esc_html_e( 'Enter one pattern per line. Patterns can be partial URLs or file extensions. Example:', 'atomic-edge-security' ); ?>
				</p>
				<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
					<li><code>/wp-admin/</code> - <?php esc_html_e( 'Excludes all admin URLs', 'atomic-edge-security' ); ?></li>
					<li><code>.php</code> - <?php esc_html_e( 'Excludes all PHP files (already excluded by default)', 'atomic-edge-security' ); ?></li>
					<li><code>/my-plugin/script.js</code> - <?php esc_html_e( 'Excludes a specific file', 'atomic-edge-security' ); ?></li>
				</ul>
			</td>
		</tr>
	</table>

	<div class="atomicedge-notice atomicedge-notice-info" style="margin-top: 15px;">
		<span class="dashicons dashicons-shield"></span>
		<div>
			<p><strong><?php esc_html_e( 'Always Excluded', 'atomic-edge-security' ); ?>:</strong></p>
			<p><?php esc_html_e( 'The following patterns are always excluded for security and compatibility:', 'atomic-edge-security' ); ?></p>
			<code style="display: block; margin-top: 8px; padding: 10px; background: #f6f7f7; word-break: break-all;">
				<?php echo esc_html( implode( ', ', $default_exclusions ) ); ?>
			</code>
		</div>
	</div>
</div>

<div class="atomicedge-card">
	<h3>
		<span class="dashicons dashicons-performance" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'Performance Options', 'atomic-edge-security' ); ?>
	</h3>
	<table class="form-table">
		<tr>
			<th scope="row">
				<label for="atomicedge-dns-prefetch"><?php esc_html_e( 'DNS Prefetch', 'atomic-edge-security' ); ?></label>
			</th>
			<td>
				<label class="atomicedge-toggle">
					<input type="checkbox" id="atomicedge-dns-prefetch" name="atomicedge_cdn_dns_prefetch" value="on" <?php checked( $dns_prefetch, 'on' ); ?>>
					<span class="atomicedge-toggle-slider"></span>
				</label>
				<p class="description">
					<?php esc_html_e( 'Add DNS prefetch hints for the CDN hostname to speed up initial resource loading.', 'atomic-edge-security' ); ?>
				</p>
			</td>
		</tr>
	</table>
</div>

<div class="atomicedge-card">
	<h3>
		<span class="dashicons dashicons-info-outline" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'CDN Information', 'atomic-edge-security' ); ?>
	</h3>
	<?php
	// Get active CDN URL from dashboard.
	$active_cdn_url = $atomicedge_site_data['cdn_url'] ?? '';
	?>
	<table class="form-table atomicedge-debug-info">
		<tr>
			<th scope="row"><?php esc_html_e( 'Dashboard CDN Status', 'atomic-edge-security' ); ?></th>
			<td>
				<?php if ( $atomicedge_cdn_enabled ) : ?>
					<span class="atomicedge-status-badge atomicedge-status-active">
						<span class="dashicons dashicons-yes-alt"></span>
						<?php esc_html_e( 'Enabled', 'atomic-edge-security' ); ?>
					</span>
				<?php else : ?>
					<span class="atomicedge-status-badge atomicedge-status-inactive">
						<span class="dashicons dashicons-warning"></span>
						<?php esc_html_e( 'Disabled', 'atomic-edge-security' ); ?>
					</span>
				<?php endif; ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Local CDN Status', 'atomic-edge-security' ); ?></th>
			<td>
				<?php if ( AtomicEdge_CDN::is_cdn_enabled() ) : ?>
					<span class="atomicedge-status-badge atomicedge-status-active">
						<span class="dashicons dashicons-yes-alt"></span>
						<?php esc_html_e( 'Active', 'atomic-edge-security' ); ?>
					</span>
				<?php else : ?>
					<span class="atomicedge-status-badge atomicedge-status-inactive">
						<span class="dashicons dashicons-minus"></span>
						<?php esc_html_e( 'Inactive', 'atomic-edge-security' ); ?>
					</span>
				<?php endif; ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'CDN Prefix', 'atomic-edge-security' ); ?></th>
			<td>
				<code><?php echo esc_html( $atomicedge_site_data['cdn_prefix'] ?? __( 'Not set', 'atomic-edge-security' ) ); ?></code>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Active CDN URL', 'atomic-edge-security' ); ?></th>
			<td>
				<?php if ( ! empty( $active_cdn_url ) ) : ?>
					<code><?php echo esc_html( $active_cdn_url ); ?></code>
				<?php else : ?>
					<code><?php esc_html_e( 'Not set', 'atomic-edge-security' ); ?></code>
				<?php endif; ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Cache Directory', 'atomic-edge-security' ); ?></th>
			<td>
				<code><?php echo esc_html( AtomicEdge_CDN::get_cache_dir() ); ?></code>
			</td>
		</tr>
	</table>
</div>

<style>
.atomicedge-debug-info th {
	width: 180px;
}
.atomicedge-debug-info code {
	background: #f0f0f1;
	padding: 3px 6px;
	border-radius: 3px;
	font-size: 12px;
}
.atomicedge-status-badge {
	display: inline-flex;
	align-items: center;
	gap: 4px;
	padding: 4px 8px;
	border-radius: 3px;
	font-size: 12px;
	font-weight: 500;
}
.atomicedge-status-active {
	background: #d1e7dd;
	color: #0f5132;
}
.atomicedge-status-inactive {
	background: #f8d7da;
	color: #842029;
}
.atomicedge-status-badge .dashicons {
	font-size: 14px;
	width: 14px;
	height: 14px;
}
</style>
