<?php
/**
 * 2FA Policy Tab Content
 *
 * @package AtomicEdge
 * @since   1.9.1
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Handle form submission.
if ( isset( $_POST['atomicedge_2fa_policy_submit'] ) ) {
	// Verify nonce.
	if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'atomicedge_2fa_policy_save' ) ) {
		wp_die( esc_html__( 'Security check failed.', 'atomic-edge-security' ) );
	}

	// Sanitize and save settings.
	$settings = array(
		'enabled'            => ! empty( $_POST['atomicedge_2fa_enabled'] ),
		'enforced_roles'     => isset( $_POST['atomicedge_2fa_roles'] ) && is_array( $_POST['atomicedge_2fa_roles'] )
			? array_map( 'sanitize_key', $_POST['atomicedge_2fa_roles'] )
			: array(),
		'grace_period_days'  => isset( $_POST['atomicedge_2fa_grace_days'] )
			? absint( $_POST['atomicedge_2fa_grace_days'] )
			: 7,
		'allow_grace_bypass' => ! empty( $_POST['atomicedge_2fa_allow_grace_bypass'] ),
		'show_reminders'     => ! empty( $_POST['atomicedge_2fa_show_reminders'] ),
	);

	AtomicEdge_2FA_Policy::update_settings( $settings );

	// Log policy change.
	AtomicEdge_2FA::log_event( get_current_user_id(), 'policy_updated', $settings );

	$success_message = __( '2FA policy settings saved successfully.', 'atomic-edge-security' );
}

// Get current settings.
$settings = AtomicEdge_2FA_Policy::get_settings();
$available_roles = AtomicEdge_2FA_Policy::get_available_roles();
$non_compliant_users = AtomicEdge_2FA_Policy::get_non_compliant_users();
?>

<?php if ( ! empty( $success_message ) ) : ?>
	<div class="notice notice-success is-dismissible" style="margin: 0 0 20px;">
		<p><?php echo esc_html( $success_message ); ?></p>
	</div>
<?php endif; ?>

<?php if ( ! AtomicEdge_2FA::is_available() ) : ?>
	<div class="notice notice-error" style="margin: 0 0 20px;">
		<p>
			<strong><?php esc_html_e( 'Warning:', 'atomic-edge-security' ); ?></strong>
			<?php esc_html_e( 'Two-factor authentication encryption is not available. Please ensure OpenSSL is installed and WordPress security keys are configured.', 'atomic-edge-security' ); ?>
		</p>
	</div>
<?php endif; ?>

<div class="atomicedge-2fa-policy-container">
	<!-- Settings Form -->
	<div class="atomicedge-2fa-policy-form">
		<form method="post" action="">
			<?php wp_nonce_field( 'atomicedge_2fa_policy_save' ); ?>

			<!-- Enable Policy -->
			<div class="atomicedge-setting-card">
				<h3><?php esc_html_e( 'Policy Status', 'atomic-edge-security' ); ?></h3>
				<p class="description">
					<?php esc_html_e( 'Enable role-based 2FA enforcement to require specific user roles to set up two-factor authentication.', 'atomic-edge-security' ); ?>
				</p>
				<label class="atomicedge-toggle">
					<input type="checkbox" name="atomicedge_2fa_enabled" value="1" <?php checked( $settings['enabled'] ); ?> />
					<span class="atomicedge-toggle-slider"></span>
					<span class="atomicedge-toggle-label">
						<?php esc_html_e( 'Enable 2FA enforcement policy', 'atomic-edge-security' ); ?>
					</span>
				</label>
			</div>

			<!-- Role Selection -->
			<div class="atomicedge-setting-card" id="role-selection">
				<h3><?php esc_html_e( 'Required Roles', 'atomic-edge-security' ); ?></h3>
				<p class="description">
					<?php esc_html_e( 'Select which user roles must have 2FA enabled. Users with these roles who don\'t have 2FA will be prompted to set it up.', 'atomic-edge-security' ); ?>
				</p>
				<div class="atomicedge-role-checkboxes">
					<?php foreach ( $available_roles as $role_slug => $role_name ) : ?>
						<label class="atomicedge-checkbox-label">
							<input type="checkbox" 
								name="atomicedge_2fa_roles[]" 
								value="<?php echo esc_attr( $role_slug ); ?>" 
								<?php checked( in_array( $role_slug, $settings['enforced_roles'], true ) ); ?> />
							<span class="checkmark"></span>
							<?php echo esc_html( $role_name ); ?>
							<?php if ( 'administrator' === $role_slug ) : ?>
								<span class="atomicedge-badge recommended"><?php esc_html_e( 'Recommended', 'atomic-edge-security' ); ?></span>
							<?php endif; ?>
						</label>
					<?php endforeach; ?>
				</div>
			</div>

			<!-- Grace Period -->
			<div class="atomicedge-setting-card" id="grace-period">
				<h3><?php esc_html_e( 'Grace Period', 'atomic-edge-security' ); ?></h3>
				<p class="description">
					<?php esc_html_e( 'Give users time to set up 2FA before enforcement. During the grace period, users can log in without 2FA but will see reminders.', 'atomic-edge-security' ); ?>
				</p>
				<div class="atomicedge-inline-field">
					<input type="number" 
						name="atomicedge_2fa_grace_days" 
						value="<?php echo esc_attr( $settings['grace_period_days'] ); ?>" 
						min="0" 
						max="90" 
						class="small-text" />
					<span><?php esc_html_e( 'days', 'atomic-edge-security' ); ?></span>
				</div>
				<p class="description" style="margin-top: 8px;">
					<?php esc_html_e( 'Set to 0 for immediate enforcement (users must set up 2FA on their first login).', 'atomic-edge-security' ); ?>
				</p>

				<div class="atomicedge-sub-options" style="margin-top: 16px;">
					<label class="atomicedge-checkbox-label">
						<input type="checkbox" 
							name="atomicedge_2fa_allow_grace_bypass" 
							value="1" 
							<?php checked( $settings['allow_grace_bypass'] ); ?> />
						<span class="checkmark"></span>
						<?php esc_html_e( 'Allow login during grace period (users can log in without 2FA until grace period expires)', 'atomic-edge-security' ); ?>
					</label>

					<label class="atomicedge-checkbox-label">
						<input type="checkbox" 
							name="atomicedge_2fa_show_reminders" 
							value="1" 
							<?php checked( $settings['show_reminders'] ); ?> />
						<span class="checkmark"></span>
						<?php esc_html_e( 'Show setup reminders (display admin notices prompting users to set up 2FA)', 'atomic-edge-security' ); ?>
					</label>
				</div>
			</div>

			<p class="submit" style="margin: 0; padding: 0;">
				<input type="submit" 
					name="atomicedge_2fa_policy_submit" 
					class="button button-primary button-large" 
					value="<?php esc_attr_e( 'Save Policy Settings', 'atomic-edge-security' ); ?>" />
			</p>
		</form>
	</div>

	<!-- Compliance Status Sidebar -->
	<?php if ( $settings['enabled'] && ! empty( $settings['enforced_roles'] ) ) : ?>
	<div class="atomicedge-2fa-policy-sidebar">
		<div class="atomicedge-setting-card atomicedge-compliance-card">
			<h3><?php esc_html_e( 'Compliance Status', 'atomic-edge-security' ); ?></h3>
			
			<?php if ( empty( $non_compliant_users ) ) : ?>
				<div class="atomicedge-compliance-success">
					<span class="dashicons dashicons-yes-alt"></span>
					<p><?php esc_html_e( 'All users in enforced roles have 2FA enabled!', 'atomic-edge-security' ); ?></p>
				</div>
			<?php else : ?>
				<div class="atomicedge-compliance-warning">
					<span class="dashicons dashicons-warning"></span>
					<p>
						<?php
						printf(
							/* translators: %d: Number of users without 2FA */
							esc_html(
								_n(
									'%d user needs to set up 2FA',
									'%d users need to set up 2FA',
									count( $non_compliant_users ),
									'atomic-edge-security'
								)
							),
							count( $non_compliant_users )
						);
						?>
					</p>
				</div>

				<table class="atomicedge-users-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'User', 'atomic-edge-security' ); ?></th>
							<th><?php esc_html_e( 'Grace Period', 'atomic-edge-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( array_slice( $non_compliant_users, 0, 10 ) as $nc_user ) : ?>
							<tr>
								<td>
									<strong><?php echo esc_html( $nc_user->display_name ); ?></strong><br>
									<small><?php echo esc_html( $nc_user->user_email ); ?></small>
								</td>
								<td>
									<?php if ( $nc_user->grace_days_left > 0 ) : ?>
										<span class="grace-active">
											<?php
											printf(
												/* translators: %d: Days remaining */
												esc_html__( '%d days left', 'atomic-edge-security' ),
												$nc_user->grace_days_left
											);
											?>
										</span>
									<?php else : ?>
										<span class="grace-expired">
											<?php esc_html_e( 'Expired', 'atomic-edge-security' ); ?>
										</span>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						<?php if ( count( $non_compliant_users ) > 10 ) : ?>
							<tr>
								<td colspan="2" class="more-users">
									<?php
									printf(
										/* translators: %d: Number of additional users */
										esc_html__( '+ %d more users...', 'atomic-edge-security' ),
										count( $non_compliant_users ) - 10
									);
									?>
								</td>
							</tr>
						<?php endif; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
	</div>
	<?php endif; ?>
</div>

<style>
.atomicedge-2fa-policy-container {
	display: flex;
	gap: 24px;
	flex-wrap: wrap;
}
.atomicedge-2fa-policy-form {
	flex: 1;
	min-width: 400px;
}
.atomicedge-2fa-policy-sidebar {
	width: 350px;
}
.atomicedge-setting-card {
	background: #f9f9f9;
	border: 1px solid #dcdcde;
	border-radius: 4px;
	padding: 20px;
	margin-bottom: 20px;
	color: #3c434a;
}
.atomicedge-setting-card h3 {
	margin: 0 0 8px;
	font-size: 15px;
	font-weight: 600;
	color: #3c434a;
}
.atomicedge-setting-card p,
.atomicedge-setting-card .description,
.atomicedge-setting-card p.description {
	color: #3c434a !important;
	margin: 0 0 16px;
	font-size: 13px;
	line-height: 1.5;
}
.atomicedge-setting-card label,
.atomicedge-setting-card span {
	color: #3c434a;
}
/* Toggle Switch */
.atomicedge-toggle {
	display: inline-flex;
	align-items: center;
	cursor: pointer;
	gap: 12px;
}
.atomicedge-toggle input {
	position: absolute;
	opacity: 0;
	width: 0;
	height: 0;
}
.atomicedge-toggle-slider {
	flex-shrink: 0;
	width: 48px;
	height: 24px;
	background: #ccc;
	border-radius: 24px;
	position: relative;
	transition: background 0.3s;
}
.atomicedge-toggle-slider::after {
	content: '';
	position: absolute;
	width: 18px;
	height: 18px;
	background: #fff;
	border-radius: 50%;
	top: 3px;
	left: 3px;
	transition: left 0.3s;
}
.atomicedge-toggle input:checked + .atomicedge-toggle-slider {
	background: #666AE5;
}
.atomicedge-toggle input:checked + .atomicedge-toggle-slider::after {
	left: 27px;
}
.atomicedge-toggle-label {
	font-weight: 500;
	color: #3c434a;
}
/* Role Checkboxes */
.atomicedge-role-checkboxes {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
	gap: 8px;
}
.atomicedge-checkbox-label {
	display: flex;
	align-items: center;
	flex-wrap: nowrap;
	padding: 10px 12px;
	background: #fff;
	border-radius: 4px;
	cursor: pointer;
	transition: background 0.2s;
	border: 1px solid #dcdcde;
	white-space: nowrap;
	color: #3c434a;
}
.atomicedge-checkbox-label:hover {
	background: #f0f0f1;
}
.atomicedge-checkbox-label input[type="checkbox"] {
	flex-shrink: 0;
	margin-right: 8px;
}
.atomicedge-badge {
	flex-shrink: 0;
	font-size: 9px;
	padding: 2px 6px;
	border-radius: 3px;
	margin-left: 6px;
	text-transform: uppercase;
	font-weight: 600;
	letter-spacing: 0.3px;
}
.atomicedge-badge.recommended {
	background: #d1e7dd;
	color: #0a3622;
}
/* Inline Field */
.atomicedge-inline-field {
	display: flex;
	align-items: center;
	gap: 8px;
	color: #3c434a;
}
.atomicedge-inline-field input[type="number"] {
	width: 80px;
}
/* Sub Options */
.atomicedge-sub-options {
	border-top: 1px solid #dcdcde;
	padding-top: 16px;
}
.atomicedge-sub-options .atomicedge-checkbox-label {
	background: none;
	padding: 4px 0;
	border: none;
	color: #3c434a;
}
/* Compliance Card */
.atomicedge-compliance-success,
.atomicedge-compliance-warning {
	display: flex;
	align-items: center;
	padding: 16px;
	border-radius: 4px;
	margin-bottom: 16px;
}
.atomicedge-compliance-success {
	background: #d1e7dd;
	color: #0a3622;
}
.atomicedge-compliance-warning {
	background: #fef3cd;
	color: #856404;
}
.atomicedge-compliance-success .dashicons,
.atomicedge-compliance-warning .dashicons {
	font-size: 32px;
	width: 32px;
	height: 32px;
	margin-right: 12px;
}
.atomicedge-compliance-success p,
.atomicedge-compliance-warning p {
	margin: 0;
	font-weight: 500;
}
/* Users Table */
.atomicedge-users-table {
	width: 100%;
	border-collapse: collapse;
}
.atomicedge-users-table th,
.atomicedge-users-table td {
	padding: 8px;
	text-align: left;
	border-bottom: 1px solid #dcdcde;
}
.atomicedge-users-table th {
	font-weight: 600;
	background: #f6f7f7;
}
.atomicedge-users-table small {
	color: #646970;
}
.grace-active {
	color: #856404;
	background: #fef3cd;
	padding: 2px 8px;
	border-radius: 3px;
	font-size: 12px;
}
.grace-expired {
	color: #58151c;
	background: #f8d7da;
	padding: 2px 8px;
	border-radius: 3px;
	font-size: 12px;
}
.more-users {
	color: #646970;
	font-style: italic;
	text-align: center !important;
}
@media screen and (max-width: 960px) {
	.atomicedge-2fa-policy-sidebar {
		width: 100%;
	}
}
</style>


