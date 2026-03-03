<?php
/**
 * Adaptive Defense Threat Detections Tab
 *
 * Shows AI-detected threats with ability to view details, block, or dismiss.
 * Uses WordPress admin pattern: clicking "View Details" shows inline expanded row.
 *
 * @package AtomicEdge
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="atomicedge-card" id="atomicedge-ad-detections-card">
	<h3>
		<span class="dashicons dashicons-warning" style="margin-right: 8px; color: #dba617;"></span>
		<?php esc_html_e( 'Threat Detections', 'atomic-edge-security' ); ?>
	</h3>
	<p class="description"><?php esc_html_e( 'AI-analyzed threats detected on your site. Review each detection and take action as needed.', 'atomic-edge-security' ); ?></p>

	<!-- Filters -->
	<div class="atomicedge-ad-filters" style="margin: 15px 0; display: flex; gap: 15px; flex-wrap: wrap; align-items: center;">
		<div>
			<label for="atomicedge-ad-detections-status"><?php esc_html_e( 'Status', 'atomic-edge-security' ); ?>:</label>
			<select id="atomicedge-ad-detections-status">
				<option value="all"><?php esc_html_e( 'All', 'atomic-edge-security' ); ?></option>
				<option value="pending_review"><?php esc_html_e( 'Pending Review', 'atomic-edge-security' ); ?></option>
				<option value="blocked"><?php esc_html_e( 'Blocked', 'atomic-edge-security' ); ?></option>
				<option value="dismissed"><?php esc_html_e( 'Dismissed', 'atomic-edge-security' ); ?></option>
			</select>
		</div>
		<button type="button" id="atomicedge-ad-detections-refresh" class="button">
			<span class="dashicons dashicons-update" style="margin-top: 3px;"></span>
			<?php esc_html_e( 'Refresh', 'atomic-edge-security' ); ?>
		</button>
	</div>

	<!-- Loading State -->
	<div class="atomicedge-ad-loading" id="atomicedge-ad-detections-loading">
		<span class="spinner is-active"></span>
		<span><?php esc_html_e( 'Loading threat detections...', 'atomic-edge-security' ); ?></span>
	</div>

	<!-- Detections Table -->
	<div class="atomicedge-ad-table-wrapper" id="atomicedge-ad-detections-table-wrapper" style="display: none;">
		<table class="wp-list-table widefat fixed striped" id="atomicedge-ad-detections-table">
			<thead>
				<tr>
					<th style="width: 160px;"><?php esc_html_e( 'IP Address', 'atomic-edge-security' ); ?></th>
					<th style="width: 80px;"><?php esc_html_e( 'Score', 'atomic-edge-security' ); ?></th>
					<th style="width: 100px;"><?php esc_html_e( 'Threat Level', 'atomic-edge-security' ); ?></th>
					<th><?php esc_html_e( 'Key Indicators', 'atomic-edge-security' ); ?></th>
					<th style="width: 100px;"><?php esc_html_e( 'Status', 'atomic-edge-security' ); ?></th>
					<th style="width: 130px;"><?php esc_html_e( 'Detected', 'atomic-edge-security' ); ?></th>
					<th style="width: 200px;"><?php esc_html_e( 'Actions', 'atomic-edge-security' ); ?></th>
				</tr>
			</thead>
			<tbody id="atomicedge-ad-detections-body">
				<!-- Populated via JS -->
			</tbody>
		</table>

		<!-- Empty State -->
		<div class="atomicedge-ad-empty" id="atomicedge-ad-detections-empty" style="display: none; text-align: center; padding: 40px 20px;">
			<span class="dashicons dashicons-yes-alt" style="font-size: 48px; color: #00a32a; display: block; margin: 0 auto 40px auto;"></span>
			<p style="font-size: 16px; color: #646970; margin: 0;"><?php esc_html_e( 'No threat detections found.', 'atomic-edge-security' ); ?></p>
		</div>

		<!-- Pagination -->
		<div class="atomicedge-ad-pagination" id="atomicedge-ad-detections-pagination" style="margin-top: 15px;">
			<!-- Populated via JS -->
		</div>
	</div>
</div>

<!-- Detection Detail Panel (inline expandable row approach per WordPress patterns) -->
<!-- Uses <template> so the browser doesn't strip <tr>/<td> during HTML parsing -->
<template id="atomicedge-ad-detection-detail-template">
	<tr class="atomicedge-ad-detail-row">
		<td colspan="7">
			<div class="atomicedge-ad-detail-panel">
				<div class="atomicedge-ad-detail-loading">
					<span class="spinner is-active"></span>
					<span><?php esc_html_e( 'Loading details...', 'atomic-edge-security' ); ?></span>
				</div>
				<div class="atomicedge-ad-detail-content" style="display: none;">
					<div class="atomicedge-ad-detail-grid">
						<!-- Detection Info -->
						<div class="atomicedge-ad-detail-section">
							<h4><?php esc_html_e( 'Detection Details', 'atomic-edge-security' ); ?></h4>
							<table class="atomicedge-ad-detail-table">
								<tr>
									<th><?php esc_html_e( 'Score', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-score">—</td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Confidence', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-confidence">—</td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Status', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-status">—</td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Detected At', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-detected-at">—</td>
								</tr>
							</table>
						</div>

						<!-- Actor Info -->
						<div class="atomicedge-ad-detail-section">
							<h4><?php esc_html_e( 'Actor Profile', 'atomic-edge-security' ); ?></h4>
							<table class="atomicedge-ad-detail-table">
								<tr>
									<th><?php esc_html_e( 'IP Address', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-ip">—</td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Total Requests', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-requests">—</td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'WAF Hits', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-waf-hits">—</td>
								</tr>
								<tr>
									<th><?php esc_html_e( '4xx/5xx Errors', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-errors">—</td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'First Seen', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-first-seen">—</td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Last Seen', 'atomic-edge-security' ); ?></th>
									<td class="atomicedge-ad-detail-last-seen">—</td>
								</tr>
							</table>
						</div>
					</div>

					<!-- Detection Reasons -->
					<div class="atomicedge-ad-detail-reasons-section">
						<h4><?php esc_html_e( 'Detection Reasons', 'atomic-edge-security' ); ?></h4>
						<ul class="atomicedge-ad-detail-reasons">
							<!-- Populated via JS -->
						</ul>
					</div>

					<!-- AI Analysis (if available) -->
					<div class="atomicedge-ad-detail-ai-section" style="display: none;">
						<h4><?php esc_html_e( 'AI Analysis', 'atomic-edge-security' ); ?></h4>
						<div class="atomicedge-ad-detail-ai-content">
							<!-- Populated via JS -->
						</div>
					</div>

					<!-- Close Button -->
					<div class="atomicedge-ad-detail-actions" style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #dcdcde;">
						<button type="button" class="button atomicedge-ad-detail-close">
							<?php esc_html_e( 'Close Details', 'atomic-edge-security' ); ?>
						</button>
					</div>
				</div>
			</div>
		</td>
	</tr>
</template>

<style>
.atomicedge-ad-loading {
	text-align: center;
	padding: 40px;
}
.atomicedge-ad-loading .spinner {
	float: none;
	margin-right: 10px;
}
.atomicedge-ad-threat-level {
	display: inline-block;
	padding: 2px 8px;
	border-radius: 3px;
	font-weight: 600;
	font-size: 11px;
	text-transform: uppercase;
}
.atomicedge-ad-threat-critical {
	background: #d63638;
	color: #fff;
}
.atomicedge-ad-threat-high {
	background: #dba617;
	color: #fff;
}
.atomicedge-ad-threat-medium {
	background: #f0c33c;
	color: #1d2327;
}
.atomicedge-ad-threat-low {
	background: #c3c4c7;
	color: #1d2327;
}
.atomicedge-ad-threat-minimal {
	background: #e7e8ea;
	color: #646970;
}
.atomicedge-ad-status-badge {
	display: inline-block;
	padding: 2px 8px;
	border-radius: 3px;
	font-size: 11px;
	text-transform: uppercase;
}
.atomicedge-ad-status-pending {
	background: #f0c33c;
	color: #1d2327;
}
.atomicedge-ad-status-blocked {
	background: #d63638;
	color: #fff;
}
.atomicedge-ad-status-dismissed {
	background: #c3c4c7;
	color: #1d2327;
}
.atomicedge-ad-detail-row {
	background: #f9f9f9 !important;
}
.atomicedge-ad-detail-panel {
	padding: 20px;
	border: 1px solid #dcdcde;
	border-radius: 4px;
	margin: 10px 0;
}
.atomicedge-ad-detail-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
	gap: 25px;
	margin-bottom: 20px;
}
.atomicedge-ad-detail-section h4 {
	margin: 0 0 10px 0;
	padding-bottom: 5px;
	border-bottom: 1px solid #dcdcde;
}
.atomicedge-ad-detail-table {
	width: 100%;
	border-collapse: collapse;
}
.atomicedge-ad-detail-table th {
	text-align: left;
	padding: 5px 10px 5px 0;
	font-weight: 400;
	color: #646970;
	width: 120px;
}
.atomicedge-ad-detail-table td {
	padding: 5px 0;
}
.atomicedge-ad-detail-reasons {
	list-style: none;
	margin: 0;
	padding: 0;
}
.atomicedge-ad-detail-reasons li {
	padding: 8px 12px;
	background: #fff;
	border: 1px solid #dcdcde;
	border-radius: 3px;
	margin-bottom: 5px;
}
.atomicedge-ad-detail-reasons li strong {
	display: block;
	margin-bottom: 3px;
}
.atomicedge-ad-detail-ai-content {
	background: #fff;
	border: 1px solid #dcdcde;
	border-radius: 4px;
	padding: 15px;
	font-family: monospace;
	font-size: 13px;
	white-space: pre-wrap;
}
</style>
