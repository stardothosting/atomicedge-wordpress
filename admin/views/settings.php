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

$atomicedge_is_connected = $this->api->is_connected();
$atomicedge_api_url      = get_option( 'atomicedge_api_url', 'https://dashboard.atomicedge.io/api/v1' );
$atomicedge_site_data    = get_option( 'atomicedge_site_data', array() );
$atomicedge_masked_key   = $this->get_masked_api_key();
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'admin/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-settings">
		<!-- Connection Status -->
		<div class="atomicedge-settings-section">
			<h2><?php esc_html_e( 'Connection Status', 'atomic-edge-security' ); ?></h2>

			<?php if ( $atomicedge_is_connected ) : ?>
				<div class="atomicedge-connection-status atomicedge-connected">
					<span class="dashicons dashicons-yes-alt"></span>
					<div class="atomicedge-connection-info">
						<strong><?php esc_html_e( 'Connected', 'atomic-edge-security' ); ?></strong>
						<?php if ( ! empty( $atomicedge_site_data['domain'] ) ) : ?>
							<span class="atomicedge-connection-domain">
								<?php echo esc_html( $atomicedge_site_data['domain'] ); ?>
							</span>
						<?php endif; ?>
						<?php if ( ! empty( $atomicedge_masked_key ) ) : ?>
							<span class="atomicedge-connection-key">
								<?php
								printf(
									/* translators: %s: masked API key */
									esc_html__( 'API Key: %s', 'atomic-edge-security' ),
									'<code>' . esc_html( $atomicedge_masked_key ) . '</code>'
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
							onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to disconnect from Atomic Edge?', 'atomic-edge-security' ); ?>');">
						<?php esc_html_e( 'Disconnect', 'atomic-edge-security' ); ?>
					</button>
				</form>

			<?php else : ?>
				<div class="atomicedge-connection-status atomicedge-disconnected">
					<span class="dashicons dashicons-warning"></span>
					<div class="atomicedge-connection-info">
						<strong><?php esc_html_e( 'Not Connected', 'atomic-edge-security' ); ?></strong>
						<span><?php esc_html_e( 'Enter your API key to connect to Atomic Edge.', 'atomic-edge-security' ); ?></span>
					</div>
				</div>

				<form method="post" action="" style="margin-top: 15px;">
					<?php wp_nonce_field( 'atomicedge_connect' ); ?>
					<table class="form-table">
						<tr>
							<th scope="row">
								<label for="atomicedge_api_key"><?php esc_html_e( 'API Key', 'atomic-edge-security' ); ?></label>
							</th>
							<td>
								<input type="text"
									   id="atomicedge_api_key"
									   name="atomicedge_api_key"
									   class="regular-text"
									   placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
									   required />
								<p class="description">
									<?php esc_html_e( 'Paste the API key exactly as shown in the Atomic Edge dashboard (32–64 letters/numbers, no prefix).', 'atomic-edge-security' ); ?>
									<br />
									<?php
									printf(
										/* translators: %s: AtomicEdge dashboard URL */
										esc_html__( 'Get your API key from your %s.', 'atomic-edge-security' ),
										'<a href="https://dashboard.atomicedge.io" target="_blank">' . esc_html__( 'Atomic Edge dashboard', 'atomic-edge-security' ) . '</a>'
									);
									?>
								</p>
							</td>
						</tr>
					</table>
					<p class="submit">
						<button type="submit" name="atomicedge_connect" class="button button-primary">
							<?php esc_html_e( 'Connect', 'atomic-edge-security' ); ?>
						</button>
					</p>
				</form>
			<?php endif; ?>
		</div>

		<!-- Advanced Settings -->
		<div class="atomicedge-settings-section">
			<h2><?php esc_html_e( 'Advanced Settings', 'atomic-edge-security' ); ?></h2>

			<form method="post" action="">
				<?php wp_nonce_field( 'atomicedge_settings' ); ?>
				<table class="form-table">
					<tr>
						<th scope="row">
							<label for="atomicedge_api_url"><?php esc_html_e( 'API URL', 'atomic-edge-security' ); ?></label>
						</th>
						<td>
							<input type="url"
								   id="atomicedge_api_url"
								   name="atomicedge_api_url"
								   class="regular-text"
								value="<?php echo esc_attr( $atomicedge_api_url ); ?>" />
							<p class="description">
								<?php esc_html_e( 'Only change this if instructed by Atomic Edge support.', 'atomic-edge-security' ); ?>
							</p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="submit" name="atomicedge_save_settings" class="button button-primary">
						<?php esc_html_e( 'Save Settings', 'atomic-edge-security' ); ?>
					</button>
				</p>
			</form>
		</div>

		<!-- Plugin Info -->
		<div class="atomicedge-settings-section">
			<h2><?php esc_html_e( 'Plugin Information', 'atomic-edge-security' ); ?></h2>
			<table class="form-table atomicedge-info-table">
				<tr>
					<th><?php esc_html_e( 'Plugin Version', 'atomic-edge-security' ); ?></th>
					<td><?php echo esc_html( ATOMICEDGE_VERSION ); ?></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'WordPress Version', 'atomic-edge-security' ); ?></th>
					<td><?php echo esc_html( get_bloginfo( 'version' ) ); ?></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'PHP Version', 'atomic-edge-security' ); ?></th>
					<td><?php echo esc_html( PHP_VERSION ); ?></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Site URL', 'atomic-edge-security' ); ?></th>
					<td><?php echo esc_html( home_url() ); ?></td>
				</tr>
			</table>
		</div>
	</div>
</div>
