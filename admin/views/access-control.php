<?php
/**
 * Access Control Page View
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap atomicedge-wrap">
	<h1><?php esc_html_e( 'Access Control', 'atomicedge' ); ?></h1>

	<div class="atomicedge-access-control">
		<!-- Tabs -->
		<nav class="nav-tab-wrapper atomicedge-tabs">
			<a href="#ip-whitelist" class="nav-tab nav-tab-active" data-tab="ip-whitelist">
				<?php esc_html_e( 'IP Whitelist', 'atomicedge' ); ?>
			</a>
			<a href="#ip-blacklist" class="nav-tab" data-tab="ip-blacklist">
				<?php esc_html_e( 'IP Blacklist', 'atomicedge' ); ?>
			</a>
			<a href="#geo-access" class="nav-tab" data-tab="geo-access">
				<?php esc_html_e( 'Geographic Access', 'atomicedge' ); ?>
			</a>
		</nav>

		<!-- IP Whitelist Tab -->
		<div id="ip-whitelist" class="atomicedge-tab-content atomicedge-tab-active">
			<div class="atomicedge-section-header">
				<h2><?php esc_html_e( 'IP Whitelist', 'atomicedge' ); ?></h2>
				<p><?php esc_html_e( 'Whitelisted IPs bypass WAF, bot blocking, and geographic restrictions.', 'atomicedge' ); ?></p>
			</div>

			<form id="atomicedge-add-whitelist-form" class="atomicedge-ip-form">
				<div class="atomicedge-form-row">
					<input type="text"
						   id="whitelist-ip"
						   name="ip"
						   placeholder="<?php esc_attr_e( 'IP address or CIDR (e.g., 192.168.1.1 or 10.0.0.0/24)', 'atomicedge' ); ?>"
						   required />
					<input type="text"
						   id="whitelist-description"
						   name="description"
						   placeholder="<?php esc_attr_e( 'Description (optional)', 'atomicedge' ); ?>" />
					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Add to Whitelist', 'atomicedge' ); ?>
					</button>
				</div>
			</form>

			<table class="wp-list-table widefat fixed striped" id="atomicedge-whitelist-table">
				<thead>
					<tr>
						<th class="column-ip"><?php esc_html_e( 'IP/CIDR', 'atomicedge' ); ?></th>
						<th class="column-description"><?php esc_html_e( 'Description', 'atomicedge' ); ?></th>
						<th class="column-actions"><?php esc_html_e( 'Actions', 'atomicedge' ); ?></th>
					</tr>
				</thead>
				<tbody id="atomicedge-whitelist-body">
					<tr class="atomicedge-loading-row">
						<td colspan="3">
							<span class="spinner is-active"></span>
							<?php esc_html_e( 'Loading...', 'atomicedge' ); ?>
						</td>
					</tr>
				</tbody>
			</table>
		</div>

		<!-- IP Blacklist Tab -->
		<div id="ip-blacklist" class="atomicedge-tab-content">
			<div class="atomicedge-section-header">
				<h2><?php esc_html_e( 'IP Blacklist', 'atomicedge' ); ?></h2>
				<p><?php esc_html_e( 'Blacklisted IPs are blocked from accessing your site entirely.', 'atomicedge' ); ?></p>
			</div>

			<form id="atomicedge-add-blacklist-form" class="atomicedge-ip-form">
				<div class="atomicedge-form-row">
					<input type="text"
						   id="blacklist-ip"
						   name="ip"
						   placeholder="<?php esc_attr_e( 'IP address or CIDR (e.g., 192.168.1.1 or 10.0.0.0/24)', 'atomicedge' ); ?>"
						   required />
					<input type="text"
						   id="blacklist-description"
						   name="description"
						   placeholder="<?php esc_attr_e( 'Description (optional)', 'atomicedge' ); ?>" />
					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Add to Blacklist', 'atomicedge' ); ?>
					</button>
				</div>
			</form>

			<table class="wp-list-table widefat fixed striped" id="atomicedge-blacklist-table">
				<thead>
					<tr>
						<th class="column-ip"><?php esc_html_e( 'IP/CIDR', 'atomicedge' ); ?></th>
						<th class="column-description"><?php esc_html_e( 'Description', 'atomicedge' ); ?></th>
						<th class="column-actions"><?php esc_html_e( 'Actions', 'atomicedge' ); ?></th>
					</tr>
				</thead>
				<tbody id="atomicedge-blacklist-body">
					<tr class="atomicedge-loading-row">
						<td colspan="3">
							<span class="spinner is-active"></span>
							<?php esc_html_e( 'Loading...', 'atomicedge' ); ?>
						</td>
					</tr>
				</tbody>
			</table>
		</div>

		<!-- Geographic Access Tab -->
		<div id="geo-access" class="atomicedge-tab-content">
			<div class="atomicedge-section-header">
				<h2><?php esc_html_e( 'Geographic Access Control', 'atomicedge' ); ?></h2>
				<p><?php esc_html_e( 'Block or allow access based on visitor country.', 'atomicedge' ); ?></p>
			</div>

			<form id="atomicedge-geo-form" class="atomicedge-geo-form">
				<div class="atomicedge-form-section">
					<label>
						<input type="checkbox" id="geo-enabled" name="enabled" />
						<?php esc_html_e( 'Enable Geographic Access Control', 'atomicedge' ); ?>
					</label>
				</div>

				<div class="atomicedge-form-section" id="geo-options" style="display: none;">
					<label for="geo-mode"><?php esc_html_e( 'Mode:', 'atomicedge' ); ?></label>
					<select id="geo-mode" name="mode">
						<option value="blacklist"><?php esc_html_e( 'Blacklist (block selected countries)', 'atomicedge' ); ?></option>
						<option value="whitelist"><?php esc_html_e( 'Whitelist (only allow selected countries)', 'atomicedge' ); ?></option>
					</select>

					<div class="atomicedge-country-selector">
						<label><?php esc_html_e( 'Countries:', 'atomicedge' ); ?></label>
						<select id="geo-countries" name="countries" multiple size="10">
							<!-- Countries will be populated by JavaScript -->
						</select>
						<p class="description">
							<?php esc_html_e( 'Hold Ctrl (Cmd on Mac) to select multiple countries.', 'atomicedge' ); ?>
						</p>
					</div>

					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Save Geographic Rules', 'atomicedge' ); ?>
					</button>
				</div>
			</form>
		</div>
	</div>
</div>
