<?php
/**
 * Two-Factor Authentication User Profile Section
 *
 * Displays 2FA settings and enrollment UI on the user profile page.
 *
 * @package AtomicEdge
 * @since   1.7.0
 *
 * @var WP_User $user   User object.
 * @var array   $status 2FA status array from AtomicEdge_2FA::get_user_status().
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check if encryption is available.
$is_available = AtomicEdge_2FA::is_available();
?>

<div class="atomicedge-2fa-section" id="atomicedge-2fa">
	<h2>
		<span class="dashicons dashicons-lock"></span>
		<?php esc_html_e( 'Two-Factor Authentication', 'atomic-edge-security' ); ?>
		<?php if ( $status['enabled'] ) : ?>
			<span class="atomicedge-2fa-badge active"><?php esc_html_e( 'Active', 'atomic-edge-security' ); ?></span>
		<?php else : ?>
			<span class="atomicedge-2fa-badge inactive"><?php esc_html_e( 'Inactive', 'atomic-edge-security' ); ?></span>
		<?php endif; ?>
	</h2>

	<?php if ( ! $is_available ) : ?>
		<div class="notice notice-error inline">
			<p>
				<?php esc_html_e( 'Two-factor authentication requires PHP 7.2+ with the Sodium extension. Please contact your hosting provider.', 'atomic-edge-security' ); ?>
			</p>
		</div>
	<?php elseif ( $status['enabled'] ) : ?>
		<!-- 2FA is enabled - show status and management options -->
		<div id="atomicedge-2fa-enabled">
			<dl class="atomicedge-2fa-status">
				<dt><?php esc_html_e( 'Method', 'atomic-edge-security' ); ?></dt>
				<dd><?php esc_html_e( 'Authenticator App (TOTP)', 'atomic-edge-security' ); ?></dd>

				<?php if ( $status['setup_date'] ) : ?>
					<dt><?php esc_html_e( 'Enabled', 'atomic-edge-security' ); ?></dt>
					<dd><?php echo esc_html( $status['setup_date'] ); ?></dd>
				<?php endif; ?>

				<?php if ( $status['last_used'] ) : ?>
					<dt><?php esc_html_e( 'Last Used', 'atomic-edge-security' ); ?></dt>
					<dd><?php echo esc_html( $status['last_used'] ); ?></dd>
				<?php endif; ?>

				<dt><?php esc_html_e( 'Backup Codes', 'atomic-edge-security' ); ?></dt>
				<dd>
					<?php
					printf(
						/* translators: 1: Remaining codes count, 2: Total codes count */
						esc_html__( '%1$d of %2$d remaining', 'atomic-edge-security' ),
						(int) $status['codes_remaining'],
						(int) $status['codes_total']
					);
					?>
					<?php if ( $status['codes_remaining'] <= 2 ) : ?>
						<span style="color: #d63638;">
							<?php esc_html_e( '(Low - consider regenerating)', 'atomic-edge-security' ); ?>
						</span>
					<?php endif; ?>
				</dd>
			</dl>

			<p class="submit">
				<button type="button" class="button" id="atomicedge-2fa-regenerate-codes">
					<?php esc_html_e( 'Regenerate Backup Codes', 'atomic-edge-security' ); ?>
				</button>
				<button type="button" class="button button-link-delete" id="atomicedge-2fa-disable">
					<?php esc_html_e( 'Disable Two-Factor', 'atomic-edge-security' ); ?>
				</button>
			</p>
		</div>

		<!-- Backup codes display (shown after regeneration) -->
		<div id="atomicedge-2fa-codes-display" style="display: none;">
			<div class="atomicedge-2fa-warning">
				<p><strong><?php esc_html_e( '⚠️ Save These Backup Codes', 'atomic-edge-security' ); ?></strong></p>
				<p><?php esc_html_e( 'Each code can only be used once. Store them in a safe place.', 'atomic-edge-security' ); ?></p>
			</div>

			<div class="atomicedge-2fa-codes" id="atomicedge-2fa-codes-list">
				<!-- Codes inserted by JavaScript -->
			</div>

			<p class="submit">
				<button type="button" class="button button-primary" id="atomicedge-2fa-download-codes">
					<span class="dashicons dashicons-download" style="vertical-align: middle;"></span>
					<?php esc_html_e( 'Download Backup Codes', 'atomic-edge-security' ); ?>
				</button>
				<button type="button" class="button" id="atomicedge-2fa-codes-done">
					<?php esc_html_e( 'I\'ve Saved My Codes', 'atomic-edge-security' ); ?>
				</button>
			</p>
		</div>

		<!-- Password confirmation dialog for disable -->
		<div id="atomicedge-2fa-disable-confirm" style="display: none;">
			<p><?php esc_html_e( 'Enter your password to disable two-factor authentication:', 'atomic-edge-security' ); ?></p>
			<p>
				<label for="atomicedge-2fa-password"><?php esc_html_e( 'Password', 'atomic-edge-security' ); ?></label>
				<input type="password" id="atomicedge-2fa-password" class="regular-text" />
			</p>
			<p class="submit">
				<button type="button" class="button button-link-delete" id="atomicedge-2fa-disable-confirm-btn">
					<?php esc_html_e( 'Disable Two-Factor', 'atomic-edge-security' ); ?>
				</button>
				<button type="button" class="button" id="atomicedge-2fa-disable-cancel">
					<?php esc_html_e( 'Cancel', 'atomic-edge-security' ); ?>
				</button>
			</p>
		</div>

	<?php else : ?>
		<!-- 2FA is not enabled - show enrollment UI -->
		
		<!-- Step 1: Introduction -->
		<div class="atomicedge-2fa-step active" id="atomicedge-2fa-step-intro">
			<p>
				<?php esc_html_e( 'Two-factor authentication adds an extra layer of security to your account by requiring a code from your authenticator app in addition to your password.', 'atomic-edge-security' ); ?>
			</p>
			<p class="submit">
				<button type="button" class="button button-primary button-hero" id="atomicedge-2fa-start">
					<?php esc_html_e( 'Enable Two-Factor Authentication', 'atomic-edge-security' ); ?>
				</button>
			</p>
		</div>

		<!-- Step 2: QR Code and Secret -->
		<div class="atomicedge-2fa-step" id="atomicedge-2fa-step-setup">
			<p><strong><?php esc_html_e( 'Step 1:', 'atomic-edge-security' ); ?></strong> <?php esc_html_e( 'Scan this QR code with your authenticator app:', 'atomic-edge-security' ); ?></p>

			<div class="atomicedge-2fa-qr">
				<canvas id="atomicedge-2fa-qrcode"></canvas>
				<p>
					<?php esc_html_e( 'Or enter this code manually:', 'atomic-edge-security' ); ?><br>
					<code class="atomicedge-2fa-secret" id="atomicedge-2fa-secret-display"></code>
				</p>
			</div>

			<p><strong><?php esc_html_e( 'Step 2:', 'atomic-edge-security' ); ?></strong> <?php esc_html_e( 'Enter the 6-digit code from your app to verify:', 'atomic-edge-security' ); ?></p>

			<div class="atomicedge-2fa-verify-form">
				<input type="text" id="atomicedge-2fa-verify-code" class="regular-text" placeholder="000000" maxlength="6" pattern="[0-9]*" inputmode="numeric" autocomplete="one-time-code" />
				<p id="atomicedge-2fa-verify-error" class="description" style="color: #d63638; display: none;"></p>
			</div>

			<p class="submit">
				<button type="button" class="button button-primary" id="atomicedge-2fa-verify">
					<?php esc_html_e( 'Verify & Enable', 'atomic-edge-security' ); ?>
				</button>
				<button type="button" class="button" id="atomicedge-2fa-cancel">
					<?php esc_html_e( 'Cancel', 'atomic-edge-security' ); ?>
				</button>
			</p>
		</div>

		<!-- Step 3: Backup Codes -->
		<div class="atomicedge-2fa-step" id="atomicedge-2fa-step-codes">
			<div class="notice notice-success inline">
				<p><strong><?php esc_html_e( '✓ Two-factor authentication is now enabled!', 'atomic-edge-security' ); ?></strong></p>
			</div>

			<div class="atomicedge-2fa-warning">
				<p><strong><?php esc_html_e( '⚠️ Save These Backup Codes', 'atomic-edge-security' ); ?></strong></p>
				<p><?php esc_html_e( 'If you lose access to your authenticator app, you can use these codes to log in. Each code can only be used once.', 'atomic-edge-security' ); ?></p>
			</div>

			<div class="atomicedge-2fa-codes" id="atomicedge-2fa-new-codes">
				<!-- Codes inserted by JavaScript -->
			</div>

			<p class="submit">
				<button type="button" class="button button-primary" id="atomicedge-2fa-download-new-codes">
					<span class="dashicons dashicons-download" style="vertical-align: middle;"></span>
					<?php esc_html_e( 'Download Backup Codes', 'atomic-edge-security' ); ?>
				</button>
				<button type="button" class="button" id="atomicedge-2fa-finish">
					<?php esc_html_e( 'I\'ve Saved My Codes', 'atomic-edge-security' ); ?>
				</button>
			</p>
		</div>
	<?php endif; ?>

	<!-- Loading indicator -->
	<div id="atomicedge-2fa-loading" style="display: none;">
		<span class="spinner is-active" style="float: none; margin: 0;"></span>
		<?php esc_html_e( 'Please wait...', 'atomic-edge-security' ); ?>
	</div>
</div>
