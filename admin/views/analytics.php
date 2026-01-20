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
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-analytics">
		<!-- Period Selector -->
		<div class="atomicedge-period-selector">
			<label for="atomicedge-period"><?php esc_html_e( 'Time Period:', 'atomic-edge-security' ); ?></label>
			<select id="atomicedge-period">
				<option value="24h"><?php esc_html_e( 'Last 24 Hours', 'atomic-edge-security' ); ?></option>
				<option value="7d"><?php esc_html_e( 'Last 7 Days', 'atomic-edge-security' ); ?></option>
				<option value="30d"><?php esc_html_e( 'Last 30 Days', 'atomic-edge-security' ); ?></option>
			</select>
			<button type="button" id="atomicedge-refresh-analytics" class="button">
				<span class="dashicons dashicons-update"></span>
				<?php esc_html_e( 'Refresh', 'atomic-edge-security' ); ?>
			</button>
		</div>

		<!-- Summary Stats -->
		<div class="atomicedge-stats-grid" id="atomicedge-stats-grid">
			<div class="atomicedge-stat-box">
				<span class="atomicedge-stat-icon dashicons dashicons-visibility"></span>
				<div class="atomicedge-stat-content">
					<span class="atomicedge-stat-value" id="stat-total-requests">-</span>
					<span class="atomicedge-stat-label"><?php esc_html_e( 'Total Requests', 'atomic-edge-security' ); ?></span>
				</div>
			</div>
			<div class="atomicedge-stat-box">
				<span class="atomicedge-stat-icon dashicons dashicons-groups"></span>
				<div class="atomicedge-stat-content">
					<span class="atomicedge-stat-value" id="stat-unique-visitors">-</span>
					<span class="atomicedge-stat-label"><?php esc_html_e( 'Unique Visitors', 'atomic-edge-security' ); ?></span>
				</div>
			</div>
			<div class="atomicedge-stat-box">
				<span class="atomicedge-stat-icon dashicons dashicons-shield-alt"></span>
				<div class="atomicedge-stat-content">
					<span class="atomicedge-stat-value" id="stat-blocked-requests">-</span>
					<span class="atomicedge-stat-label"><?php esc_html_e( 'Requests Blocked', 'atomic-edge-security' ); ?></span>
				</div>
			</div>
			<div class="atomicedge-stat-box">
				<span class="atomicedge-stat-icon dashicons dashicons-chart-line"></span>
				<div class="atomicedge-stat-content">
					<span class="atomicedge-stat-value" id="stat-block-rate">-</span>
					<span class="atomicedge-stat-label"><?php esc_html_e( 'Block Rate', 'atomic-edge-security' ); ?></span>
				</div>
			</div>
		</div>

		<!-- Charts -->
		<div class="atomicedge-charts">
			<div class="atomicedge-chart-container">
				<h3><?php esc_html_e( 'Traffic Over Time', 'atomic-edge-security' ); ?></h3>
				<div class="atomicedge-chart-wrapper">
					<canvas id="atomicedge-traffic-chart"></canvas>
				</div>
			</div>

			<div class="atomicedge-chart-container">
				<h3><?php esc_html_e( 'Blocked Requests Over Time', 'atomic-edge-security' ); ?></h3>
				<div class="atomicedge-chart-wrapper">
					<canvas id="atomicedge-blocked-chart"></canvas>
				</div>
			</div>
		</div>

		<!-- Loading State -->
		<div id="atomicedge-analytics-loading" class="atomicedge-loading" style="display: none;">
			<span class="spinner is-active"></span>
			<span><?php esc_html_e( 'Loading analytics...', 'atomic-edge-security' ); ?></span>
		</div>

		<!-- Error State -->
		<div id="atomicedge-analytics-error" class="atomicedge-error" style="display: none;">
			<span class="dashicons dashicons-warning"></span>
			<span><?php esc_html_e( 'Failed to load analytics. Please try again.', 'atomic-edge-security' ); ?></span>
		</div>
	</div>
</div>
