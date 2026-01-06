<?php
/**
 * Settings Page View
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$is_connected = $this->api->is_connected();
$api_url      = get_option( 'atomicedge_api_url', 'https://atomicedge.io/api/v1' );
$site_data    = get_option( 'atomicedge_site_data', array() );
$masked_key   = $this->get_masked_api_key();
?>
<div class="wrap atomicedge-wrap">
	<h1><?php esc_html_e( 'AtomicEdge Settings', 'atomicedge' ); ?></h1>

	<div class="atomicedge-settings">
		<!-- Connection Status -->
		<div class="atomicedge-settings-section">
			<h2><?php esc_html_e( 'Connection Status', 'atomicedge' ); ?></h2>

			<?php if ( $is_connected ) : ?>
				<div class="atomicedge-connection-status atomicedge-connected">
					<span class="dashicons dashicons-yes-alt"></span>
					<div class="atomicedge-connection-info">
						<strong><?php esc_html_e( 'Connected', 'atomicedge' ); ?></strong>
						<?php if ( ! empty( $site_data['domain'] ) ) : ?>
							<span class="atomicedge-connection-domain">
								<?php echo esc_html( $site_data['domain'] ); ?>
							</span>
						<?php endif; ?>
						<?php if ( ! empty( $masked_key ) ) : ?>
							<span class="atomicedge-connection-key">
								<?php
								printf(
									/* translators: %s: masked API key */
									esc_html__( 'API Key: %s', 'atomicedge' ),
									'<code>' . esc_html( $masked_key ) . '</code>'
								);
								?>
							</span>
						<?php endif; ?>
					</div>
				</div>

				<form method="post" action="" style="margin-top: 15px;">
					<?php wp_nonce_field( 'atomicedge_disconnect' ); ?>
					<button type="submit"
							name="atomicedge_disconnect"
							class="button button-secondary"
							onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to disconnect from AtomicEdge?', 'atomicedge' ); ?>');">
						<?php esc_html_e( 'Disconnect', 'atomicedge' ); ?>
					</button>
				</form>

			<?php else : ?>
				<div class="atomicedge-connection-status atomicedge-disconnected">
					<span class="dashicons dashicons-warning"></span>
					<div class="atomicedge-connection-info">
						<strong><?php esc_html_e( 'Not Connected', 'atomicedge' ); ?></strong>
						<span><?php esc_html_e( 'Enter your API key to connect to AtomicEdge.', 'atomicedge' ); ?></span>
					</div>
				</div>

				<form method="post" action="" style="margin-top: 15px;">
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
									   placeholder="ae_xxxxxxxxxxxxxxxxxxxx"
									   required />
								<p class="description">
									<?php
									printf(
										/* translators: %s: AtomicEdge dashboard URL */
										esc_html__( 'Get your API key from your %s.', 'atomicedge' ),
										'<a href="https://atomicedge.io/dashboard" target="_blank">' . esc_html__( 'AtomicEdge dashboard', 'atomicedge' ) . '</a>'
									);
									?>
								</p>
							</td>
						</tr>
					</table>
					<p class="submit">
						<button type="submit" name="atomicedge_connect" class="button button-primary">
							<?php esc_html_e( 'Connect', 'atomicedge' ); ?>
						</button>
					</p>
				</form>
			<?php endif; ?>
		</div>

		<!-- Advanced Settings -->
		<div class="atomicedge-settings-section">
			<h2><?php esc_html_e( 'Advanced Settings', 'atomicedge' ); ?></h2>

			<form method="post" action="">
				<?php wp_nonce_field( 'atomicedge_settings' ); ?>
				<table class="form-table">
					<tr>
						<th scope="row">
							<label for="atomicedge_api_url"><?php esc_html_e( 'API URL', 'atomicedge' ); ?></label>
						</th>
						<td>
							<input type="url"
								   id="atomicedge_api_url"
								   name="atomicedge_api_url"
								   class="regular-text"
								   value="<?php echo esc_attr( $api_url ); ?>" />
							<p class="description">
								<?php esc_html_e( 'Only change this if instructed by AtomicEdge support.', 'atomicedge' ); ?>
							</p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="submit" name="atomicedge_save_settings" class="button button-primary">
						<?php esc_html_e( 'Save Settings', 'atomicedge' ); ?>
					</button>
				</p>
			</form>
		</div>

		<!-- Cache Management -->
		<div class="atomicedge-settings-section">
			<h2><?php esc_html_e( 'Cache Management', 'atomicedge' ); ?></h2>
			<p><?php esc_html_e( 'Clear cached API data if you are experiencing issues with outdated information.', 'atomicedge' ); ?></p>
			<button type="button" id="atomicedge-clear-cache" class="button">
				<?php esc_html_e( 'Clear Cache', 'atomicedge' ); ?>
			</button>
			<span id="atomicedge-cache-status"></span>
		</div>

		<!-- Plugin Info -->
		<div class="atomicedge-settings-section">
			<h2><?php esc_html_e( 'Plugin Information', 'atomicedge' ); ?></h2>
			<table class="form-table atomicedge-info-table">
				<tr>
					<th><?php esc_html_e( 'Plugin Version', 'atomicedge' ); ?></th>
					<td><?php echo esc_html( ATOMICEDGE_VERSION ); ?></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'WordPress Version', 'atomicedge' ); ?></th>
					<td><?php echo esc_html( get_bloginfo( 'version' ) ); ?></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'PHP Version', 'atomicedge' ); ?></th>
					<td><?php echo esc_html( PHP_VERSION ); ?></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Site URL', 'atomicedge' ); ?></th>
					<td><?php echo esc_html( home_url() ); ?></td>
				</tr>
			</table>
		</div>
	</div>
</div>
