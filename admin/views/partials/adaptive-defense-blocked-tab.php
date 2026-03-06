<?php
/**
 * Adaptive Defense Blocked IPs Tab
 *
 * Shows currently blocked IPs with ability to unblock or delete.
 *
 * @package AtomicEdge
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="atomicedge-card" id="atomicedge-ad-blocked-card">
	<h3>
		<span class="dashicons dashicons-dismiss" style="margin-right: 8px; color: #d63638;"></span>
		<?php esc_html_e( 'Blocked IP Addresses', 'atomic-edge-security' ); ?>
	</h3>
	<p class="description"><?php esc_html_e( 'IP addresses currently blocked by Adaptive Defense. You can unblock or permanently remove them.', 'atomic-edge-security' ); ?></p>

	<!-- Block IP Form -->
	<div class="atomicedge-ad-block-form" style="margin: 15px 0; padding: 15px; background: #f6f7f7; border: 1px solid #dcdcde; border-radius: 4px;">
		<h4 style="margin-top: 0;"><?php esc_html_e( 'Block an IP Address', 'atomic-edge-security' ); ?></h4>
		<div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: flex-end;">
			<div>
				<label for="atomicedge-ad-block-ip"><?php esc_html_e( 'IP Address', 'atomic-edge-security' ); ?></label><br>
				<input type="text" id="atomicedge-ad-block-ip" placeholder="192.168.1.1" style="width: 200px;">
			</div>
			<div>
				<label for="atomicedge-ad-block-duration"><?php esc_html_e( 'Duration', 'atomic-edge-security' ); ?></label><br>
				<select id="atomicedge-ad-block-duration">
					<option value="1"><?php esc_html_e( '1 hour', 'atomic-edge-security' ); ?></option>
					<option value="6"><?php esc_html_e( '6 hours', 'atomic-edge-security' ); ?></option>
					<option value="24" selected><?php esc_html_e( '24 hours', 'atomic-edge-security' ); ?></option>
					<option value="168"><?php esc_html_e( '7 days', 'atomic-edge-security' ); ?></option>
					<option value="720"><?php esc_html_e( '30 days', 'atomic-edge-security' ); ?></option>
					<option value="permanent"><?php esc_html_e( 'Permanent', 'atomic-edge-security' ); ?></option>
				</select>
			</div>
			<button type="button" id="atomicedge-ad-block-btn" class="button button-primary">
				<span class="dashicons dashicons-lock" style="margin-top: 3px;"></span>
				<?php esc_html_e( 'Block IP', 'atomic-edge-security' ); ?>
			</button>
		</div>
	</div>

	<!-- Loading State -->
	<div class="atomicedge-ad-loading" id="atomicedge-ad-blocked-loading">
		<span class="spinner is-active"></span>
		<span><?php esc_html_e( 'Loading blocked IPs...', 'atomic-edge-security' ); ?></span>
	</div>

	<!-- Blocked IPs Table -->
	<div class="atomicedge-ad-table-wrapper" id="atomicedge-ad-blocked-table-wrapper" style="display: none;">
		<table class="wp-list-table widefat fixed striped" id="atomicedge-ad-blocked-table">
			<thead>
				<tr>
					<th style="width: 180px;"><?php esc_html_e( 'IP Address', 'atomic-edge-security' ); ?></th>
					<th style="width: 80px;"><?php esc_html_e( 'Threat Score', 'atomic-edge-security' ); ?></th>
					<th style="width: 80px;"><?php esc_html_e( 'WAF Hits', 'atomic-edge-security' ); ?></th>
					<th style="width: 90px;"><?php esc_html_e( 'Type', 'atomic-edge-security' ); ?></th>
					<th style="width: 110px;"><?php esc_html_e( 'Blocked', 'atomic-edge-security' ); ?></th>
					<th style="width: 110px;"><?php esc_html_e( 'Expires', 'atomic-edge-security' ); ?></th>
					<th style="width: 200px;"><?php esc_html_e( 'Actions', 'atomic-edge-security' ); ?></th>
				</tr>
			</thead>
			<tbody id="atomicedge-ad-blocked-body">
				<!-- Populated via JS -->
			</tbody>
		</table>

		<!-- Empty State -->
		<div class="atomicedge-ad-empty" id="atomicedge-ad-blocked-empty" style="display: none; text-align: center; padding: 40px 20px;">
			<span class="dashicons dashicons-yes-alt" style="font-size: 48px; color: #00a32a; display: block; margin: 0 auto 15px auto;"></span>
			<p style="font-size: 16px; color: #646970; margin: 0;"><?php esc_html_e( 'No IP addresses are currently blocked.', 'atomic-edge-security' ); ?></p>
		</div>

		<!-- Pagination -->
		<div class="atomicedge-ad-pagination" id="atomicedge-ad-blocked-pagination" style="margin-top: 15px;">
			<!-- Populated via JS -->
		</div>
	</div>
</div>

<style>
.atomicedge-ad-loading {
	text-align: center;
	padding: 40px;
}
.atomicedge-ad-loading .spinner {
	float: none;
	margin-right: 10px;
}
.atomicedge-ad-pagination {
	display: flex;
	justify-content: space-between;
	align-items: center;
	flex-wrap: wrap;
	gap: 10px;
}
.atomicedge-ad-pagination-info {
	color: #646970;
	font-size: 13px;
}
.atomicedge-ad-pagination-buttons {
	display: flex;
	gap: 5px;
}
</style>
