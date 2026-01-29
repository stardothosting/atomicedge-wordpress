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

// Use dev mode for local environments.
$atomicedge_dev_mode = AtomicEdge_Dev_Mode::is_enabled();
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'admin/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<?php
	// Show dev mode notice.
	// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML is escaped in the method.
	echo AtomicEdge_Dev_Mode::get_admin_notice();
	?>

	<div class="atomicedge-access-control">
		<!-- Tabs -->
		<nav class="nav-tab-wrapper atomicedge-tabs">
			<a href="#ip-whitelist" class="nav-tab nav-tab-active" data-tab="ip-whitelist">
				<?php esc_html_e( 'IP Whitelist', 'atomic-edge-security' ); ?>
			</a>
			<a href="#ip-blacklist" class="nav-tab" data-tab="ip-blacklist">
				<?php esc_html_e( 'IP Blacklist', 'atomic-edge-security' ); ?>
			</a>
			<a href="#geo-access" class="nav-tab" data-tab="geo-access">
				<?php esc_html_e( 'Geographic Access', 'atomic-edge-security' ); ?>
			</a>
		</nav>

		<!-- IP Whitelist Tab -->
		<div id="ip-whitelist" class="atomicedge-tab-content atomicedge-tab-active">
			<div class="atomicedge-section-header">
				<h2><?php esc_html_e( 'IP Whitelist', 'atomic-edge-security' ); ?></h2>
				<p><?php esc_html_e( 'Whitelisted IPs bypass WAF, bot blocking, and geographic restrictions.', 'atomic-edge-security' ); ?></p>
			</div>

			<form id="atomicedge-add-whitelist-form" class="atomicedge-ip-form">
				<div class="atomicedge-form-row">
					<input type="text"
						   id="whitelist-ip"
						   name="ip"
						   placeholder="<?php esc_attr_e( 'IP address or CIDR (e.g., 192.168.1.1 or 10.0.0.0/24)', 'atomic-edge-security' ); ?>"
						   required />
					<input type="text"
						   id="whitelist-description"
						   name="description"
						   placeholder="<?php esc_attr_e( 'Description (optional)', 'atomic-edge-security' ); ?>" />
					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Add to Whitelist', 'atomic-edge-security' ); ?>
					</button>
				</div>
			</form>

			<table class="wp-list-table widefat fixed striped" id="atomicedge-whitelist-table">
				<thead>
					<tr>
						<th class="column-ip"><?php esc_html_e( 'IP/CIDR', 'atomic-edge-security' ); ?></th>
						<th class="column-description"><?php esc_html_e( 'Description', 'atomic-edge-security' ); ?></th>
						<th class="column-actions"><?php esc_html_e( 'Actions', 'atomic-edge-security' ); ?></th>
					</tr>
				</thead>
				<tbody id="atomicedge-whitelist-body">
					<tr class="atomicedge-loading-row">
						<td colspan="3">
							<span class="spinner is-active"></span>
							<?php esc_html_e( 'Loading...', 'atomic-edge-security' ); ?>
						</td>
					</tr>
				</tbody>
			</table>
		</div>

		<!-- IP Blacklist Tab -->
		<div id="ip-blacklist" class="atomicedge-tab-content">
			<div class="atomicedge-section-header">
				<h2><?php esc_html_e( 'IP Blacklist', 'atomic-edge-security' ); ?></h2>
				<p><?php esc_html_e( 'Blacklisted IPs are blocked from accessing your site entirely.', 'atomic-edge-security' ); ?></p>
			</div>

			<form id="atomicedge-add-blacklist-form" class="atomicedge-ip-form">
				<div class="atomicedge-form-row">
					<input type="text"
						   id="blacklist-ip"
						   name="ip"
						   placeholder="<?php esc_attr_e( 'IP address or CIDR (e.g., 192.168.1.1 or 10.0.0.0/24)', 'atomic-edge-security' ); ?>"
						   required />
					<input type="text"
						   id="blacklist-description"
						   name="description"
						   placeholder="<?php esc_attr_e( 'Description (optional)', 'atomic-edge-security' ); ?>" />
					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Add to Blacklist', 'atomic-edge-security' ); ?>
					</button>
				</div>
			</form>

			<table class="wp-list-table widefat fixed striped" id="atomicedge-blacklist-table">
				<thead>
					<tr>
						<th class="column-ip"><?php esc_html_e( 'IP/CIDR', 'atomic-edge-security' ); ?></th>
						<th class="column-description"><?php esc_html_e( 'Description', 'atomic-edge-security' ); ?></th>
						<th class="column-actions"><?php esc_html_e( 'Actions', 'atomic-edge-security' ); ?></th>
					</tr>
				</thead>
				<tbody id="atomicedge-blacklist-body">
					<tr class="atomicedge-loading-row">
						<td colspan="3">
							<span class="spinner is-active"></span>
							<?php esc_html_e( 'Loading...', 'atomic-edge-security' ); ?>
						</td>
					</tr>
				</tbody>
			</table>
		</div>

		<!-- Geographic Access Tab -->
		<div id="geo-access" class="atomicedge-tab-content">
			<div class="atomicedge-section-header">
				<h2><?php esc_html_e( 'Geographic Access Control', 'atomic-edge-security' ); ?></h2>
				<p><?php esc_html_e( 'Block or allow access based on visitor country.', 'atomic-edge-security' ); ?></p>
			</div>

			<form id="atomicedge-geo-form" class="atomicedge-geo-form">
				<div class="atomicedge-form-section">
					<label>
						<input type="checkbox" id="geo-enabled" name="enabled" />
						<?php esc_html_e( 'Enable Geographic Access Control', 'atomic-edge-security' ); ?>
					</label>
				</div>

				<div class="atomicedge-form-section" id="geo-options" style="display: none;">
					<label for="geo-mode"><?php esc_html_e( 'Mode:', 'atomic-edge-security' ); ?></label>
					<select id="geo-mode" name="mode">
						<option value="blacklist"><?php esc_html_e( 'Blacklist (block selected countries)', 'atomic-edge-security' ); ?></option>
						<option value="whitelist"><?php esc_html_e( 'Whitelist (only allow selected countries)', 'atomic-edge-security' ); ?></option>
					</select>

					<div class="atomicedge-country-selector">
						<label><?php esc_html_e( 'Countries:', 'atomic-edge-security' ); ?></label>
						<select id="geo-countries" name="countries" multiple size="10">
							<!-- Countries will be populated by JavaScript -->
						</select>
						<p class="description">
							<?php esc_html_e( 'Hold Ctrl (Cmd on Mac) to select multiple countries.', 'atomic-edge-security' ); ?>
						</p>
					</div>

					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Save Geographic Rules', 'atomic-edge-security' ); ?>
					</button>
				</div>
			</form>
		</div>
	</div>
</div>
