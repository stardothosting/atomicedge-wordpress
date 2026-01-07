<?php
/**
 * Dashboard Page View
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$is_connected = $this->api->is_connected();
$site_data    = get_option( 'atomicedge_site_data', array() );
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomicedge' ); ?>" class="atomicedge-logo" /></h1>

	<?php if ( ! $is_connected ) : ?>
		<div class="atomicedge-welcome">
			<div class="atomicedge-welcome-header">
				<h2><?php esc_html_e( 'Welcome to Atomic Edge Security', 'atomicedge' ); ?></h2>
				<p><?php esc_html_e( 'Protect your WordPress site with enterprise-grade WAF protection, analytics, and security tools.', 'atomicedge' ); ?></p>
			</div>

			<div class="atomicedge-connect-box">
				<h3><?php esc_html_e( 'Connect Your Site', 'atomicedge' ); ?></h3>
				<p><?php esc_html_e( 'Enter your Atomic Edge API key to get started.', 'atomicedge' ); ?></p>

				<form method="post" action="">
					<?php wp_nonce_field( 'atomicedge_connect' ); ?>
					<table class="form-table">
						<tr>
							<th scope="row">
								<label for="atomicedge_api_key"><?php esc_html_e( 'API Key', 'atomicedge' ); ?></label>
							</th>
							<td>
								<input type="text"
									   id="atomicedge_api_key"
									   name="atomicedge_api_key"
									   class="regular-text"
									   placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
									   required />
								<p class="description">
									<?php esc_html_e( 'Paste the API key exactly as shown in the Atomic Edge dashboard (32–64 letters/numbers, no prefix).', 'atomicedge' ); ?>
									<br />
									<?php
									printf(
										/* translators: %s: AtomicEdge dashboard URL */
										esc_html__( 'Get your API key from your %s.', 'atomicedge' ),
										'<a href="https://dashboard.atomicedge.io" target="_blank">' . esc_html__( 'Atomic Edge dashboard', 'atomicedge' ) . '</a>'
									);
									?>
								</p>
							</td>
						</tr>
					</table>
					<p class="submit">
						<button type="submit" name="atomicedge_connect" class="button button-primary button-hero">
							<?php esc_html_e( 'Connect to Atomic Edge', 'atomicedge' ); ?>
						</button>
					</p>
				</form>
			</div>

			<div class="atomicedge-features">
				<h3><?php esc_html_e( 'Features', 'atomicedge' ); ?></h3>
				<div class="atomicedge-feature-grid">
					<div class="atomicedge-feature">
						<span class="dashicons dashicons-shield"></span>
						<h4><?php esc_html_e( 'WAF Protection', 'atomicedge' ); ?></h4>
						<p><?php esc_html_e( 'Enterprise-grade Web Application Firewall with OWASP rules.', 'atomicedge' ); ?></p>
					</div>
					<div class="atomicedge-feature">
						<span class="dashicons dashicons-chart-area"></span>
						<h4><?php esc_html_e( 'Real-time Analytics', 'atomicedge' ); ?></h4>
						<p><?php esc_html_e( 'Monitor traffic, threats, and security events in real-time.', 'atomicedge' ); ?></p>
					</div>
					<div class="atomicedge-feature">
						<span class="dashicons dashicons-admin-network"></span>
						<h4><?php esc_html_e( 'Access Control', 'atomicedge' ); ?></h4>
						<p><?php esc_html_e( 'Block or allow IPs and countries with ease.', 'atomicedge' ); ?></p>
					</div>
					<div class="atomicedge-feature">
						<span class="dashicons dashicons-search"></span>
						<h4><?php esc_html_e( 'Malware Scanner', 'atomicedge' ); ?></h4>
						<p><?php esc_html_e( 'Scan your WordPress files for malware and modifications.', 'atomicedge' ); ?></p>
					</div>
				</div>
			</div>
		</div>

	<?php else : ?>
		<div class="atomicedge-dashboard">
			<div class="atomicedge-status-bar">
				<div class="atomicedge-status atomicedge-status-connected">
					<span class="dashicons dashicons-yes-alt"></span>
					<?php esc_html_e( 'Connected to Atomic Edge', 'atomicedge' ); ?>
				</div>
				<?php if ( ! empty( $site_data['domain'] ) ) : ?>
					<div class="atomicedge-domain">
						<strong><?php esc_html_e( 'Domain:', 'atomicedge' ); ?></strong>
						<?php echo esc_html( $site_data['domain'] ); ?>
					</div>
				<?php endif; ?>
				<?php if ( ! empty( $site_data['plan'] ) ) : ?>
					<div class="atomicedge-plan">
						<strong><?php esc_html_e( 'Plan:', 'atomicedge' ); ?></strong>
						<?php echo esc_html( ucfirst( $site_data['plan'] ) ); ?>
					</div>
				<?php endif; ?>
			</div>

			<div class="atomicedge-dashboard-widgets">
				<div class="atomicedge-widget atomicedge-widget-summary" id="atomicedge-summary-widget">
					<h3><?php esc_html_e( 'Security Summary', 'atomicedge' ); ?></h3>
					<div class="atomicedge-widget-content atomicedge-loading">
						<span class="spinner is-active"></span>
						<?php esc_html_e( 'Loading...', 'atomicedge' ); ?>
					</div>
				</div>

				<div class="atomicedge-widget atomicedge-widget-chart">
					<h3><?php esc_html_e( 'Traffic (Last 24 Hours)', 'atomicedge' ); ?></h3>
					<div class="atomicedge-widget-content">
						<canvas id="atomicedge-traffic-chart"></canvas>
					</div>
				</div>

				<div class="atomicedge-widget atomicedge-widget-chart">
					<h3><?php esc_html_e( 'Attacks Blocked (Last 24 Hours)', 'atomicedge' ); ?></h3>
					<div class="atomicedge-widget-content">
						<canvas id="atomicedge-attacks-chart"></canvas>
					</div>
				</div>
			</div>

			<div class="atomicedge-quick-actions">
				<h3><?php esc_html_e( 'Quick Actions', 'atomicedge' ); ?></h3>
				<div class="atomicedge-action-buttons">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-analytics' ) ); ?>" class="button">
						<span class="dashicons dashicons-chart-area"></span>
						<?php esc_html_e( 'Analytics', 'atomicedge' ); ?>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-waf-logs' ) ); ?>" class="button">
						<span class="dashicons dashicons-shield"></span>
						<?php esc_html_e( 'WAF Logs', 'atomicedge' ); ?>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-access-control' ) ); ?>" class="button">
						<span class="dashicons dashicons-admin-network"></span>
						<?php esc_html_e( 'Access Control', 'atomicedge' ); ?>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-scanner' ) ); ?>" class="button">
						<span class="dashicons dashicons-search"></span>
						<?php esc_html_e( 'Malware Scanner', 'atomicedge' ); ?>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-vulnerabilities' ) ); ?>" class="button">
						<span class="dashicons dashicons-shield-alt"></span>
						<?php esc_html_e( 'Vulnerability Scanner', 'atomicedge' ); ?>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-settings' ) ); ?>" class="button">
						<span class="dashicons dashicons-admin-generic"></span>
						<?php esc_html_e( 'Settings', 'atomicedge' ); ?>
					</a>
				</div>
			</div>
		</div>
	<?php endif; ?>
</div>
