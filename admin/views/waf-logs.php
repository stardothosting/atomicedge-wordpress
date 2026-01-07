<?php
/**
 * WAF Logs Page View
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomicedge' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-waf-logs">
		<!-- Filters -->
		<div class="atomicedge-filters">
			<div class="atomicedge-filter-group">
				<label for="atomicedge-waf-search"><?php esc_html_e( 'Search:', 'atomicedge' ); ?></label>
				<input type="text"
					   id="atomicedge-waf-search"
					   placeholder="<?php esc_attr_e( 'IP, URI, or Rule ID...', 'atomicedge' ); ?>" />
			</div>
			<div class="atomicedge-filter-group">
				<label for="atomicedge-waf-per-page"><?php esc_html_e( 'Per Page:', 'atomicedge' ); ?></label>
				<select id="atomicedge-waf-per-page">
					<option value="25">25</option>
					<option value="50" selected>50</option>
					<option value="100">100</option>
				</select>
			</div>
			<button type="button" id="atomicedge-waf-refresh" class="button">
				<span class="dashicons dashicons-update"></span>
				<?php esc_html_e( 'Refresh', 'atomicedge' ); ?>
			</button>
		</div>

		<!-- Logs Table -->
		<div class="atomicedge-table-container">
			<table class="wp-list-table widefat fixed striped" id="atomicedge-waf-table">
				<thead>
					<tr>
						<th class="column-time"><?php esc_html_e( 'Time', 'atomicedge' ); ?></th>
						<th class="column-ip"><?php esc_html_e( 'IP Address', 'atomicedge' ); ?></th>
						<th class="column-uri"><?php esc_html_e( 'URI', 'atomicedge' ); ?></th>
						<th class="column-rule"><?php esc_html_e( 'Rule ID', 'atomicedge' ); ?></th>
						<th class="column-group"><?php esc_html_e( 'Rule Group', 'atomicedge' ); ?></th>
						<th class="column-actions"><?php esc_html_e( 'Actions', 'atomicedge' ); ?></th>
					</tr>
				</thead>
				<tbody id="atomicedge-waf-logs-body">
					<tr class="atomicedge-loading-row">
						<td colspan="6">
							<span class="spinner is-active"></span>
							<?php esc_html_e( 'Loading logs...', 'atomicedge' ); ?>
						</td>
					</tr>
				</tbody>
			</table>
		</div>

		<!-- Pagination -->
		<div class="atomicedge-pagination" id="atomicedge-waf-pagination">
			<button type="button" id="atomicedge-waf-prev" class="button" disabled>
				<?php esc_html_e( '← Previous', 'atomicedge' ); ?>
			</button>
			<span id="atomicedge-waf-page-info"><?php esc_html_e( 'Page 1', 'atomicedge' ); ?></span>
			<button type="button" id="atomicedge-waf-next" class="button" disabled>
				<?php esc_html_e( 'Next →', 'atomicedge' ); ?>
			</button>
		</div>

		<!-- No Results -->
		<div id="atomicedge-waf-no-results" class="atomicedge-no-results" style="display: none;">
			<span class="dashicons dashicons-shield-alt"></span>
			<h3><?php esc_html_e( 'No WAF Events', 'atomicedge' ); ?></h3>
			<p><?php esc_html_e( 'No security events have been logged in this time period.', 'atomicedge' ); ?></p>
		</div>

		<!-- Error State -->
		<div id="atomicedge-waf-error" class="atomicedge-error" style="display: none;">
			<span class="dashicons dashicons-warning"></span>
			<span><?php esc_html_e( 'Failed to load WAF logs. Please try again.', 'atomicedge' ); ?></span>
		</div>
	</div>
</div>
