<?php
/**
 * AtomicEdge 2FA Login Flow Handler
 *
 * Intercepts the WordPress login flow to enforce 2FA verification.
 *
 * @package AtomicEdge
 * @since   1.7.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_2FA_Login
 *
 * Handles login flow interception for 2FA enforcement.
 */
class AtomicEdge_2FA_Login {

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->init_hooks();
	}

	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	private function init_hooks() {
		// Block auth cookies during password validation for 2FA users.
		add_filter( 'authenticate', array( $this, 'filter_authenticate_block_cookies' ), PHP_INT_MAX );

		// Intercept after successful password auth to show 2FA form.
		add_action( 'wp_login', array( $this, 'wp_login' ), 10, 2 );

		// Handle 2FA validation form submission.
		add_action( 'login_form_atomicedge_2fa', array( $this, 'handle_2fa_validation' ) );

		// Add 2FA session marker to authenticated sessions.
		add_filter( 'attach_session_information', array( $this, 'attach_session_info' ), 10, 2 );
	}

	/**
	 * Block auth cookies from being sent if user has 2FA enabled.
	 *
	 * This filter runs at PHP_INT_MAX priority, after password validation.
	 *
	 * @param WP_User|WP_Error $user User object or error.
	 * @return WP_User|WP_Error Unchanged user object/error.
	 */
	public function filter_authenticate_block_cookies( $user ) {
		if ( ! $user instanceof WP_User ) {
			return $user;
		}

		// Only intercept on login page (not programmatic auth).
		if ( ! did_action( 'login_init' ) ) {
			return $user;
		}

		// Check if user has 2FA enabled.
		if ( AtomicEdge_2FA::is_enabled_for_user( $user->ID ) ) {
			// Block cookies from being sent prematurely.
			add_filter( 'send_auth_cookies', '__return_false', PHP_INT_MAX );
		}

		return $user;
	}

	/**
	 * Intercept successful login to show 2FA form if needed.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 * @return void
	 */
	public function wp_login( $user_login, $user ) {
		// Check policy enforcement first.
		if ( class_exists( 'AtomicEdge_2FA_Policy' ) ) {
			// Start or check grace period for users who need 2FA.
			if ( AtomicEdge_2FA_Policy::is_required_for_user( $user->ID ) &&
				! AtomicEdge_2FA::is_enabled_for_user( $user->ID ) ) {

				// Initialize grace period if not started.
				AtomicEdge_2FA_Policy::start_grace_period( $user->ID );

				// Check if user should be blocked (grace period expired).
				if ( AtomicEdge_2FA_Policy::should_block_login( $user->ID ) ) {
					// Destroy the session WordPress just created.
					$this->destroy_current_session( $user );

					// Show the enforcement block page.
					$this->show_enforcement_block( $user );
					exit;
				}
			}
		}

		// Check if user has 2FA enabled.
		if ( ! AtomicEdge_2FA::is_enabled_for_user( $user->ID ) ) {
			return;
		}

		// Destroy the session that WordPress just created (we haven't verified 2FA yet).
		$this->destroy_current_session( $user );

		// Get redirect URL from the login form.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading redirect_to is safe.
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? sanitize_url( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading rememberme is safe.
		$rememberme = ! empty( $_REQUEST['rememberme'] );

		// Create a login nonce for the 2FA step.
		$login_nonce = AtomicEdge_2FA::create_login_nonce( $user->ID );

		// Show the 2FA form.
		$this->show_2fa_form( $user, $login_nonce['key'], $redirect_to, $rememberme );

		// Prevent further processing.
		exit;
	}

	/**
	 * Destroy the current session for a user.
	 *
	 * Called before 2FA verification to invalidate the premature session.
	 *
	 * @param WP_User $user User object.
	 * @return void
	 */
	private function destroy_current_session( $user ) {
		$manager = WP_Session_Tokens::get_instance( $user->ID );

		// Get the token from the auth cookie that was just set.
		$cookie = wp_parse_auth_cookie( '', 'logged_in' );
		if ( $cookie && isset( $cookie['token'] ) ) {
			$manager->destroy( $cookie['token'] );
		}

		// Clear the auth cookies.
		wp_clear_auth_cookie();
	}

	/**
	 * Display the 2FA verification form.
	 *
	 * @param WP_User $user        User object.
	 * @param string  $nonce_key   Login nonce key.
	 * @param string  $redirect_to Redirect URL after successful login.
	 * @param bool    $rememberme  Remember me checkbox value.
	 * @return void
	 */
	private function show_2fa_form( $user, $nonce_key, $redirect_to, $rememberme ) {
		// Check rate limiting.
		$lockout_remaining = AtomicEdge_2FA::is_rate_limited( $user->ID );

		// Determine available methods.
		$backup_codes    = get_user_meta( $user->ID, AtomicEdge_2FA::META_BACKUP_CODES, true );
		$has_backup      = ! empty( $backup_codes ) && AtomicEdge_2FA_Backup::count_remaining( $backup_codes ) > 0;
		$use_backup_code = isset( $_GET['backup'] ) && '1' === $_GET['backup'];

		// Get error message if any.
		$error = isset( $_GET['error'] ) ? sanitize_text_field( wp_unslash( $_GET['error'] ) ) : '';

		// Start output.
		login_header(
			__( 'Two-Factor Authentication', 'atomic-edge-security' ),
			$error ? '<p class="message">' . esc_html( $error ) . '</p>' : ''
		);

		?>
		<form name="2fa_form" id="2fa_form" action="<?php echo esc_url( site_url( 'wp-login.php?action=atomicedge_2fa', 'login_post' ) ); ?>" method="post" autocomplete="off">
			<input type="hidden" name="wp-auth-id" value="<?php echo esc_attr( $user->ID ); ?>" />
			<input type="hidden" name="wp-auth-nonce" value="<?php echo esc_attr( $nonce_key ); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
			<input type="hidden" name="rememberme" value="<?php echo esc_attr( $rememberme ? '1' : '' ); ?>" />

			<?php if ( $lockout_remaining ) : ?>
				<p class="message" style="border-left-color: #d63638;">
					<?php
					printf(
						/* translators: %s: Time remaining */
						esc_html__( 'Too many failed attempts. Please wait %s before trying again.', 'atomic-edge-security' ),
						esc_html( human_time_diff( time(), time() + $lockout_remaining ) )
					);
					?>
				</p>
			<?php else : ?>

				<?php if ( $use_backup_code ) : ?>
					<p>
						<?php esc_html_e( 'Enter one of your backup codes:', 'atomic-edge-security' ); ?>
					</p>
					<p>
						<label for="backup_code"><?php esc_html_e( 'Backup Code', 'atomic-edge-security' ); ?></label>
						<input type="text" name="backup_code" id="backup_code" class="input" size="20" autocomplete="off" autofocus />
					</p>
				<?php else : ?>
					<p>
						<?php esc_html_e( 'Enter the 6-digit code from your authenticator app:', 'atomic-edge-security' ); ?>
					</p>
					<p>
						<label for="authcode"><?php esc_html_e( 'Authentication Code', 'atomic-edge-security' ); ?></label>
						<input type="text" name="authcode" id="authcode" class="input" size="20" pattern="[0-9]*" inputmode="numeric" autocomplete="one-time-code" autofocus />
					</p>
				<?php endif; ?>

				<p class="submit">
					<input type="submit" name="submit" id="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Log In', 'atomic-edge-security' ); ?>" />
				</p>

			<?php endif; ?>
		</form>

		<?php if ( ! $lockout_remaining ) : ?>
			<p id="nav">
				<?php if ( $use_backup_code ) : ?>
					<a href="<?php echo esc_url( add_query_arg( 'backup', '0', site_url( 'wp-login.php?action=atomicedge_2fa', 'login' ) ) ); ?>">
						<?php esc_html_e( '&larr; Use authenticator app', 'atomic-edge-security' ); ?>
					</a>
				<?php elseif ( $has_backup ) : ?>
					<a href="<?php echo esc_url( add_query_arg( 'backup', '1', site_url( 'wp-login.php?action=atomicedge_2fa', 'login' ) ) ); ?>">
						<?php esc_html_e( 'Use a backup code', 'atomic-edge-security' ); ?>
					</a>
				<?php endif; ?>
			</p>
		<?php endif; ?>

		<script type="text/javascript">
			document.getElementById('<?php echo $use_backup_code ? 'backup_code' : 'authcode'; ?>').focus();
		</script>
		<?php

		login_footer();
	}

	/**
	 * Handle 2FA form submission.
	 *
	 * @return void
	 */
	public function handle_2fa_validation() {
		// Verify required fields.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Using custom nonce below.
		$user_id = isset( $_POST['wp-auth-id'] ) ? absint( $_POST['wp-auth-id'] ) : 0;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Using custom nonce below.
		$nonce_key = isset( $_POST['wp-auth-nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['wp-auth-nonce'] ) ) : '';

		if ( ! $user_id || ! $nonce_key ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Verify the login nonce.
		if ( ! AtomicEdge_2FA::verify_login_nonce( $user_id, $nonce_key ) ) {
			wp_safe_redirect( add_query_arg( 'error', rawurlencode( __( 'Session expired. Please log in again.', 'atomic-edge-security' ) ), wp_login_url() ) );
			exit;
		}

		// Check rate limiting.
		if ( AtomicEdge_2FA::is_rate_limited( $user_id ) ) {
			$this->redirect_to_2fa_form( $user_id, $nonce_key, __( 'Too many failed attempts. Please wait before trying again.', 'atomic-edge-security' ) );
		}

		// Get the code to verify.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Using custom nonce.
		$authcode    = isset( $_POST['authcode'] ) ? sanitize_text_field( wp_unslash( $_POST['authcode'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Using custom nonce.
		$backup_code = isset( $_POST['backup_code'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_code'] ) ) : '';

		$verified = false;

		if ( ! empty( $backup_code ) ) {
			// Verify backup code.
			$verified = AtomicEdge_2FA::verify_backup_code( $user_id, $backup_code );
		} elseif ( ! empty( $authcode ) ) {
			// Verify TOTP code.
			$verified = AtomicEdge_2FA::verify_totp( $user_id, $authcode );
		}

		if ( ! $verified ) {
			// Record failed attempt.
			AtomicEdge_2FA::record_failed_attempt( $user_id );
			AtomicEdge_2FA::log_event( $user_id, 'verification_failed' );

			$this->redirect_to_2fa_form( $user_id, $nonce_key, __( 'Invalid code. Please try again.', 'atomic-edge-security' ) );
		}

		// Success! Clean up and complete login.
		AtomicEdge_2FA::delete_login_nonce( $user_id );
		AtomicEdge_2FA::record_success( $user_id );
		AtomicEdge_2FA::log_event( $user_id, 'login_success' );

		// Remove the cookie filter we added earlier.
		remove_filter( 'send_auth_cookies', '__return_false', PHP_INT_MAX );

		// Get login options.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Using custom nonce.
		$redirect_to = isset( $_POST['redirect_to'] ) ? sanitize_url( wp_unslash( $_POST['redirect_to'] ) ) : admin_url();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Using custom nonce.
		$rememberme = ! empty( $_POST['rememberme'] );

		// Set auth cookie (this is the real login).
		wp_set_auth_cookie( $user_id, $rememberme );

		// Apply login redirect filter.
		$redirect_to = apply_filters( 'login_redirect', $redirect_to, $redirect_to, get_user_by( 'id', $user_id ) );

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Redirect back to 2FA form with error.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $nonce_key Login nonce key.
	 * @param string $error     Error message.
	 * @return void
	 */
	private function redirect_to_2fa_form( $user_id, $nonce_key, $error ) {
		// We need to regenerate the nonce since this is a new request.
		// Actually, we keep using the same nonce until it expires or is used successfully.
		$url = add_query_arg(
			array(
				'action' => 'atomicedge_2fa',
				'error'  => rawurlencode( $error ),
			),
			wp_login_url()
		);

		// Include backup parameter if it was set.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Just checking if backup mode was used.
		if ( ! empty( $_POST['backup_code'] ) ) {
			$url = add_query_arg( 'backup', '1', $url );
		}

		// Re-show the form (this is a redirect, so user must re-enter data).
		// We need to pass the nonce back somehow - let's use a transient.
		set_transient( 'atomicedge_2fa_retry_' . $user_id, $nonce_key, 5 * MINUTE_IN_SECONDS );

		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Attach 2FA verification status to session info.
	 *
	 * @param array $info    Session information.
	 * @param int   $user_id User ID.
	 * @return array Modified session information.
	 */
	public function attach_session_info( $info, $user_id ) {
		if ( AtomicEdge_2FA::is_enabled_for_user( $user_id ) ) {
			$info['atomicedge_2fa_verified'] = true;
		}
		return $info;
	}

	/**
	 * Display the enforcement block page.
	 *
	 * Shown when a user's role requires 2FA and their grace period has expired.
	 *
	 * @param WP_User $user User object.
	 * @return void
	 */
	private function show_enforcement_block( $user ) {
		login_header(
			__( 'Two-Factor Authentication Required', 'atomic-edge-security' ),
			''
		);

		?>
		<div style="margin: 0 auto; max-width: 400px; text-align: center;">
			<div style="background: #fef3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 16px; margin-bottom: 20px;">
				<span class="dashicons dashicons-shield-alt" style="font-size: 48px; color: #856404; display: block; margin-bottom: 12px;"></span>
				<h2 style="margin: 0 0 12px; color: #856404;">
					<?php esc_html_e( 'Two-Factor Authentication Required', 'atomic-edge-security' ); ?>
				</h2>
				<p style="margin: 0; color: #856404;">
					<?php esc_html_e( 'Your account role requires two-factor authentication to be enabled. Please set up 2FA before you can log in.', 'atomic-edge-security' ); ?>
				</p>
			</div>

			<p>
				<?php esc_html_e( 'Two-factor authentication adds an extra layer of security to your account by requiring a code from your phone in addition to your password.', 'atomic-edge-security' ); ?>
			</p>

			<p>
				<?php
				$grace_days = AtomicEdge_2FA_Policy::get_grace_days_remaining( $user->ID );
				if ( $grace_days > 0 ) {
					printf(
						/* translators: %d: Number of days remaining */
						esc_html(
							_n(
								'Your grace period has ended. You originally had %d day to set up 2FA.',
								'Your grace period has ended. You originally had %d days to set up 2FA.',
								$grace_days,
								'atomic-edge-security'
							)
						),
						esc_html( $grace_days )
					);
				} else {
					esc_html_e( 'Your grace period has ended. Please contact your site administrator to set up 2FA.', 'atomic-edge-security' );
				}
				?>
			</p>

			<p style="margin-top: 20px;">
				<a href="<?php echo esc_url( wp_login_url() ); ?>" class="button button-secondary">
					<?php esc_html_e( '&larr; Back to Login', 'atomic-edge-security' ); ?>
				</a>
			</p>

			<p class="description" style="margin-top: 20px;">
				<?php
				printf(
					/* translators: %s: User's email address */
					esc_html__( 'If you need assistance, please contact your site administrator. Your account email is: %s', 'atomic-edge-security' ),
					'<code>' . esc_html( $user->user_email ) . '</code>'
				);
				?>
			</p>
		</div>
		<?php

		login_footer();
	}
}
