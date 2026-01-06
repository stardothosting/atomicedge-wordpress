<?php
/**
 * Analytics Page View
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap atomicedge-wrap">
	<h1><?php esc_html_e( 'AtomicEdge Analytics', 'atomicedge' ); ?></h1>

	<div class="atomicedge-analytics">
		<!-- Period Selector -->
		<div class="atomicedge-period-selector">
			<label for="atomicedge-period"><?php esc_html_e( 'Time Period:', 'atomicedge' ); ?></label>
			<select id="atomicedge-period">
				<option value="24h"><?php esc_html_e( 'Last 24 Hours', 'atomicedge' ); ?></option>
				<option value="7d"><?php esc_html_e( 'Last 7 Days', 'atomicedge' ); ?></option>
				<option value="30d"><?php esc_html_e( 'Last 30 Days', 'atomicedge' ); ?></option>
			</select>
			<button type="button" id="atomicedge-refresh-analytics" class="button">
				<span class="dashicons dashicons-update"></span>
				<?php esc_html_e( 'Refresh', 'atomicedge' ); ?>
			</button>
		</div>

		<!-- Summary Stats -->
		<div class="atomicedge-stats-grid" id="atomicedge-stats-grid">
			<div class="atomicedge-stat-box">
				<span class="atomicedge-stat-icon dashicons dashicons-visibility"></span>
				<div class="atomicedge-stat-content">
					<span class="atomicedge-stat-value" id="stat-total-requests">-</span>
					<span class="atomicedge-stat-label"><?php esc_html_e( 'Total Requests', 'atomicedge' ); ?></span>
				</div>
			</div>
			<div class="atomicedge-stat-box">
				<span class="atomicedge-stat-icon dashicons dashicons-groups"></span>
				<div class="atomicedge-stat-content">
					<span class="atomicedge-stat-value" id="stat-unique-visitors">-</span>
					<span class="atomicedge-stat-label"><?php esc_html_e( 'Unique Visitors', 'atomicedge' ); ?></span>
				</div>
			</div>
			<div class="atomicedge-stat-box">
				<span class="atomicedge-stat-icon dashicons dashicons-shield-alt"></span>
				<div class="atomicedge-stat-content">
					<span class="atomicedge-stat-value" id="stat-blocked-requests">-</span>
					<span class="atomicedge-stat-label"><?php esc_html_e( 'Requests Blocked', 'atomicedge' ); ?></span>
				</div>
			</div>
			<div class="atomicedge-stat-box">
				<span class="atomicedge-stat-icon dashicons dashicons-chart-line"></span>
				<div class="atomicedge-stat-content">
					<span class="atomicedge-stat-value" id="stat-block-rate">-</span>
					<span class="atomicedge-stat-label"><?php esc_html_e( 'Block Rate', 'atomicedge' ); ?></span>
				</div>
			</div>
		</div>

		<!-- Charts -->
		<div class="atomicedge-charts">
			<div class="atomicedge-chart-container">
				<h3><?php esc_html_e( 'Traffic Over Time', 'atomicedge' ); ?></h3>
				<div class="atomicedge-chart-wrapper">
					<canvas id="atomicedge-traffic-chart"></canvas>
				</div>
			</div>

			<div class="atomicedge-chart-container">
				<h3><?php esc_html_e( 'Blocked Requests Over Time', 'atomicedge' ); ?></h3>
				<div class="atomicedge-chart-wrapper">
					<canvas id="atomicedge-blocked-chart"></canvas>
				</div>
			</div>
		</div>

		<!-- Loading State -->
		<div id="atomicedge-analytics-loading" class="atomicedge-loading" style="display: none;">
			<span class="spinner is-active"></span>
			<span><?php esc_html_e( 'Loading analytics...', 'atomicedge' ); ?></span>
		</div>

		<!-- Error State -->
		<div id="atomicedge-analytics-error" class="atomicedge-error" style="display: none;">
			<span class="dashicons dashicons-warning"></span>
			<span><?php esc_html_e( 'Failed to load analytics. Please try again.', 'atomicedge' ); ?></span>
		</div>
	</div>
</div>
