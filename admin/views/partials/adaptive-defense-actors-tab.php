<?php
/**
 * Adaptive Defense Actor Profiles Tab
 *
 * Shows all actor profiles with filtering and ability to block/delete.
 *
 * @package AtomicEdge
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="atomicedge-card" id="atomicedge-ad-actors-card">
	<h3>
		<span class="dashicons dashicons-admin-users" style="margin-right: 8px;"></span>
		<?php esc_html_e( 'Actor Profiles', 'atomic-edge-security' ); ?>
	</h3>
	<p class="description"><?php esc_html_e( 'Behavioral profiles of IP addresses that have accessed your site. Higher scores indicate more suspicious behavior.', 'atomic-edge-security' ); ?></p>

	<!-- Filters -->
	<div class="atomicedge-ad-filters" style="margin: 15px 0; display: flex; gap: 15px; flex-wrap: wrap; align-items: center;">
		<div>
			<label for="atomicedge-ad-actors-filter"><?php esc_html_e( 'Filter', 'atomic-edge-security' ); ?>:</label>
			<select id="atomicedge-ad-actors-filter">
				<option value="all"><?php esc_html_e( 'All Actors', 'atomic-edge-security' ); ?></option>
				<option value="blocked"><?php esc_html_e( 'Blocked Only', 'atomic-edge-security' ); ?></option>
				<option value="high_risk"><?php esc_html_e( 'High Risk Only', 'atomic-edge-security' ); ?></option>
			</select>
		</div>
		<div>
			<label for="atomicedge-ad-actors-search"><?php esc_html_e( 'Search IP', 'atomic-edge-security' ); ?>:</label>
			<input type="text" id="atomicedge-ad-actors-search" placeholder="e.g., 192.168" style="width: 150px;">
			<button type="button" id="atomicedge-ad-actors-search-btn" class="button">
				<span class="dashicons dashicons-search" style="margin-top: 3px;"></span>
			</button>
		</div>
		<button type="button" id="atomicedge-ad-actors-refresh" class="button">
			<span class="dashicons dashicons-update" style="margin-top: 3px;"></span>
			<?php esc_html_e( 'Refresh', 'atomic-edge-security' ); ?>
		</button>
	</div>

	<!-- Loading State -->
	<div class="atomicedge-ad-loading" id="atomicedge-ad-actors-loading">
		<span class="spinner is-active"></span>
		<span><?php esc_html_e( 'Loading actor profiles...', 'atomic-edge-security' ); ?></span>
	</div>

	<!-- Actors Table -->
	<div class="atomicedge-ad-table-wrapper" id="atomicedge-ad-actors-table-wrapper" style="display: none;">
		<table class="wp-list-table widefat fixed striped" id="atomicedge-ad-actors-table">
			<thead>
				<tr>
					<th style="width: 160px;"><?php esc_html_e( 'IP Address', 'atomic-edge-security' ); ?></th>
					<th style="width: 80px;"><?php esc_html_e( 'Score', 'atomic-edge-security' ); ?></th>
					<th style="width: 90px;"><?php esc_html_e( 'Requests', 'atomic-edge-security' ); ?></th>
					<th style="width: 80px;"><?php esc_html_e( 'WAF Hits', 'atomic-edge-security' ); ?></th>
					<th style="width: 80px;"><?php esc_html_e( 'Errors', 'atomic-edge-security' ); ?></th>
					<th style="width: 100px;"><?php esc_html_e( 'Status', 'atomic-edge-security' ); ?></th>
					<th><?php esc_html_e( 'Last Seen', 'atomic-edge-security' ); ?></th>
					<th style="width: 180px;"><?php esc_html_e( 'Actions', 'atomic-edge-security' ); ?></th>
				</tr>
			</thead>
			<tbody id="atomicedge-ad-actors-body">
				<!-- Populated via JS -->
			</tbody>
		</table>

		<!-- Empty State -->
		<div class="atomicedge-ad-empty" id="atomicedge-ad-actors-empty" style="display: none; text-align: center; padding: 40px;">
			<span class="dashicons dashicons-admin-users" style="font-size: 48px; color: #dcdcde;"></span>
			<p style="font-size: 16px; color: #646970; margin-top: 10px;"><?php esc_html_e( 'No actor profiles found.', 'atomic-edge-security' ); ?></p>
		</div>

		<!-- Pagination -->
		<div class="atomicedge-ad-pagination" id="atomicedge-ad-actors-pagination" style="margin-top: 15px;">
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
.atomicedge-ad-score {
	display: inline-block;
	padding: 2px 8px;
	border-radius: 3px;
	font-weight: 600;
	font-size: 12px;
}
.atomicedge-ad-score-critical {
	background: #d63638;
	color: #fff;
}
.atomicedge-ad-score-high {
	background: #dba617;
	color: #fff;
}
.atomicedge-ad-score-medium {
	background: #f0c33c;
	color: #1d2327;
}
.atomicedge-ad-score-low {
	background: #c3c4c7;
	color: #1d2327;
}
.atomicedge-ad-score-minimal {
	background: #e7e8ea;
	color: #646970;
}
/* Actor status badges */
.atomicedge-ad-status-blocked {
	display: inline-block;
	padding: 2px 8px;
	border-radius: 3px;
	font-size: 11px;
	font-weight: 600;
	background: #d63638;
	color: #fff;
}
.atomicedge-ad-status-high-risk {
	display: inline-block;
	padding: 2px 8px;
	border-radius: 3px;
	font-size: 11px;
	font-weight: 600;
	background: #dba617;
	color: #fff;
}
.atomicedge-ad-status-normal {
	color: #646970;
}
</style>
