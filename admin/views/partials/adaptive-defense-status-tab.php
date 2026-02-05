<?php
/**
 * Adaptive Defense Status Tab
 *
 * Shows current status, settings overview, and quick stats.
 *
 * @package AtomicEdge
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="atomicedge-card" id="atomicedge-ad-status-card">
	<div id="atomicedge-ad-status-loading" class="atomicedge-ad-loading">
		<span class="spinner is-active"></span>
		<span><?php esc_html_e( 'Loading Adaptive Defense status...', 'atomic-edge-security' ); ?></span>
	</div>
	<div id="atomicedge-ad-status-content" class="atomicedge-ad-content" style="display: none;">
		<!-- Status Header -->
		<div class="atomicedge-ad-header">
			<div class="atomicedge-ad-status-badge-wrapper">
				<span class="atomicedge-status-badge" id="atomicedge-ad-status-badge">
					<span class="atomicedge-status-indicator"></span>
					<span id="atomicedge-ad-status-text"><?php esc_html_e( 'Loading...', 'atomic-edge-security' ); ?></span>
				</span>
			</div>
			<button type="button" id="atomicedge-ad-status-refresh" class="button">
				<span class="dashicons dashicons-update" style="margin-top: 3px;"></span>
				<?php esc_html_e( 'Refresh', 'atomic-edge-security' ); ?>
			</button>
		</div>

		<!-- Quick Stats Grid -->
		<div class="atomicedge-ad-stats-grid">
			<div class="atomicedge-ad-stat-box">
				<span class="atomicedge-ad-stat-number" id="atomicedge-ad-stat-actors">0</span>
				<span class="atomicedge-ad-stat-label"><?php esc_html_e( 'Actor Profiles', 'atomic-edge-security' ); ?></span>
			</div>
			<div class="atomicedge-ad-stat-box">
				<span class="atomicedge-ad-stat-number" id="atomicedge-ad-stat-blocked">0</span>
				<span class="atomicedge-ad-stat-label"><?php esc_html_e( 'Blocked IPs', 'atomic-edge-security' ); ?></span>
			</div>
			<div class="atomicedge-ad-stat-box">
				<span class="atomicedge-ad-stat-number" id="atomicedge-ad-stat-pending">0</span>
				<span class="atomicedge-ad-stat-label"><?php esc_html_e( 'Pending Reviews', 'atomic-edge-security' ); ?></span>
			</div>
			<div class="atomicedge-ad-stat-box">
				<span class="atomicedge-ad-stat-number" id="atomicedge-ad-stat-high-risk">0</span>
				<span class="atomicedge-ad-stat-label"><?php esc_html_e( 'High Risk Actors', 'atomic-edge-security' ); ?></span>
			</div>
		</div>

		<!-- Settings Overview (Read-Only) -->
		<div class="atomicedge-ad-settings-section">
			<h3>
				<span class="dashicons dashicons-admin-settings" style="margin-right: 5px;"></span>
				<?php esc_html_e( 'Current Settings', 'atomic-edge-security' ); ?>
			</h3>
			<p class="description"><?php esc_html_e( 'These settings are configured in your Atomic Edge dashboard.', 'atomic-edge-security' ); ?></p>
			<table class="form-table atomicedge-ad-settings-table">
				<tr>
					<th scope="row"><?php esc_html_e( 'Operating Mode', 'atomic-edge-security' ); ?></th>
					<td id="atomicedge-ad-mode">—</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Sensitivity', 'atomic-edge-security' ); ?></th>
					<td id="atomicedge-ad-sensitivity">—</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'AI Budget Used', 'atomic-edge-security' ); ?></th>
					<td>
						<span id="atomicedge-ad-budget-used">0</span> / <span id="atomicedge-ad-budget-total">0</span>
						<span class="description"><?php esc_html_e( 'today', 'atomic-edge-security' ); ?></span>
					</td>
				</tr>
			</table>
		</div>

		<!-- High Risk Actors Preview -->
		<div class="atomicedge-ad-high-risk-section" id="atomicedge-ad-high-risk-section" style="display: none;">
			<h3>
				<span class="dashicons dashicons-warning" style="margin-right: 5px; color: #d63638;"></span>
				<?php esc_html_e( 'High Risk Actors', 'atomic-edge-security' ); ?>
			</h3>
			<table class="wp-list-table widefat fixed striped" id="atomicedge-ad-high-risk-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'IP Address', 'atomic-edge-security' ); ?></th>
						<th><?php esc_html_e( 'Score', 'atomic-edge-security' ); ?></th>
						<th><?php esc_html_e( 'Requests', 'atomic-edge-security' ); ?></th>
						<th><?php esc_html_e( 'WAF Hits', 'atomic-edge-security' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'atomic-edge-security' ); ?></th>
					</tr>
				</thead>
				<tbody id="atomicedge-ad-high-risk-body">
					<!-- Populated via JS -->
				</tbody>
			</table>
		</div>

		<!-- Not Enabled Notice -->
		<div class="atomicedge-ad-not-enabled" id="atomicedge-ad-not-enabled" style="display: none;">
			<div class="atomicedge-notice atomicedge-notice-info">
				<span class="dashicons dashicons-info"></span>
				<div>
					<p><strong><?php esc_html_e( 'Adaptive Defense is Not Enabled', 'atomic-edge-security' ); ?></strong></p>
					<p><?php esc_html_e( 'Enable Adaptive Defense in your Atomic Edge dashboard to start using AI-powered threat detection.', 'atomic-edge-security' ); ?></p>
					<p style="margin-top: 10px;">
						<a href="https://dashboard.atomicedge.io" target="_blank" rel="noopener noreferrer" class="button button-primary">
							<?php esc_html_e( 'Open Dashboard', 'atomic-edge-security' ); ?>
							<span class="dashicons dashicons-external" style="margin-top: 3px;"></span>
						</a>
					</p>
				</div>
			</div>
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
.atomicedge-ad-header {
	display: flex;
	justify-content: space-between;
	align-items: center;
	margin-bottom: 20px;
	padding-bottom: 15px;
	border-bottom: 1px solid #dcdcde;
}
.atomicedge-ad-stats-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
	gap: 15px;
	margin-bottom: 25px;
}
.atomicedge-ad-stat-box {
	background: #f6f7f7;
	border: 1px solid #dcdcde;
	border-radius: 4px;
	padding: 15px;
	text-align: center;
}
.atomicedge-ad-stat-number {
	display: block;
	font-size: 28px;
	font-weight: 600;
	color: #1d2327;
}
.atomicedge-ad-stat-label {
	display: block;
	font-size: 12px;
	color: #646970;
	margin-top: 5px;
}
.atomicedge-ad-settings-section {
	margin-bottom: 25px;
}
.atomicedge-ad-settings-table th {
	width: 200px;
	font-weight: 400;
}
.atomicedge-ad-high-risk-section {
	margin-top: 25px;
}
</style>
