<?php
/**
 * AtomicEdge 2FA Main Controller
 *
 * Coordinates all 2FA functionality including user management,
 * policy enforcement, and hook registration.
 *
 * @package AtomicEdge
 * @since   1.7.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_2FA
 *
 * Main 2FA controller class.
 */
class AtomicEdge_2FA {

	/**
	 * User meta key for TOTP secret (encrypted).
	 *
	 * @var string
	 */
	const META_TOTP_SECRET = '_atomicedge_2fa_totp_secret';

	/**
	 * User meta key for 2FA enabled status.
	 *
	 * @var string
	 */
	const META_ENABLED = '_atomicedge_2fa_enabled';

	/**
	 * User meta key for backup codes (serialized).
	 *
	 * @var string
	 */
	const META_BACKUP_CODES = '_atomicedge_2fa_backup_codes';

	/**
	 * User meta key for failed attempt count.
	 *
	 * @var string
	 */
	const META_FAILED_ATTEMPTS = '_atomicedge_2fa_failed_attempts';

	/**
	 * User meta key for lockout timestamp.
	 *
	 * @var string
	 */
	const META_LOCKOUT_UNTIL = '_atomicedge_2fa_lockout_until';

	/**
	 * User meta key for last successful 2FA timestamp.
	 *
	 * @var string
	 */
	const META_LAST_USED = '_atomicedge_2fa_last_used';

	/**
	 * User meta key for setup date.
	 *
	 * @var string
	 */
	const META_SETUP_DATE = '_atomicedge_2fa_setup_date';

	/**
	 * User meta key for pending setup secret (temporary).
	 *
	 * @var string
	 */
	const META_PENDING_SECRET = '_atomicedge_2fa_pending_secret';

	/**
	 * Login nonce meta key.
	 *
	 * @var string
	 */
	const META_LOGIN_NONCE = '_atomicedge_2fa_login_nonce';

	/**
	 * Rate limiting thresholds.
	 *
	 * @var array
	 */
	const RATE_LIMITS = array(
		3  => 60,      // 3 failures = 1 minute cooldown.
		5  => 900,     // 5 failures = 15 minute cooldown.
		10 => 3600,    // 10 failures = 1 hour lockout.
	);

	/**
	 * Singleton instance.
	 *
	 * @var AtomicEdge_2FA|null
	 */
	private static $instance = null;

	/**
	 * Login handler instance.
	 *
	 * @var AtomicEdge_2FA_Login|null
	 */
	private $login_handler = null;

	/**
	 * Debug log helper - only logs when WP_DEBUG is true.
	 *
	 * @param string $message Log message.
	 * @return void
	 */
	private static function debug_log( $message ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'AtomicEdge 2FA: ' . $message );
		}
	}

	/**
	 * Get singleton instance.
	 *
	 * @return AtomicEdge_2FA
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->init_hooks();
	}

	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	private function init_hooks() {
		// User profile section.
		add_action( 'show_user_profile', array( $this, 'render_user_profile_section' ), 20 );
		add_action( 'edit_user_profile', array( $this, 'render_user_profile_section' ), 20 );

		// Enqueue scripts for user profile.
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_scripts' ) );

		// Initialize login handler.
		$this->login_handler = new AtomicEdge_2FA_Login();

		// Clean up on user deletion.
		add_action( 'delete_user', array( $this, 'cleanup_user_data' ) );

		// Admin notices for conflicts.
		add_action( 'admin_notices', array( $this, 'display_conflict_notice' ) );

		// Admin notices for policy enforcement reminders.
		add_action( 'admin_notices', array( $this, 'display_enforcement_reminder' ) );

		// AJAX handler for dismissing the reminder.
		add_action( 'wp_ajax_atomicedge_dismiss_2fa_reminder', array( $this, 'ajax_dismiss_reminder' ) );
	}

	/**
	 * Check if 2FA is enabled for a user.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if 2FA is enabled.
	 */
	public static function is_enabled_for_user( $user_id ) {
		return (bool) get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/**
	 * Get the decrypted TOTP secret for a user.
	 *
	 * @param int $user_id User ID.
	 * @return string|false Decrypted secret, or false if not found/decryption fails.
	 */
	public static function get_user_secret( $user_id ) {
		$encrypted = get_user_meta( $user_id, self::META_TOTP_SECRET, true );
		if ( empty( $encrypted ) ) {
			return false;
		}
		return AtomicEdge_2FA_Crypto::decrypt( $encrypted );
	}

	/**
	 * Start 2FA enrollment for a user.
	 *
	 * Generates a new secret and stores it temporarily until verified.
	 *
	 * @param int $user_id User ID.
	 * @return array|WP_Error {
	 *     @type string $secret          Base32-encoded secret (for display).
	 *     @type string $provisioning_uri URI for QR code.
	 * }
	 */
	public static function start_enrollment( $user_id ) {
		self::debug_log( 'start_enrollment() called for user_id: ' . $user_id );

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			self::debug_log( 'start_enrollment() failed: invalid user' );
			return new \WP_Error( 'invalid_user', __( 'Invalid user.', 'atomic-edge-security' ) );
		}
		self::debug_log( 'start_enrollment() user found: ' . $user->user_login );

		// Verify encryption is available before starting.
		self::debug_log( 'start_enrollment() checking encryption availability...' );
		if ( ! AtomicEdge_2FA_Crypto::is_available() ) {
			self::debug_log( 'start_enrollment() failed: encryption not available' );
			AtomicEdge::log( '2FA enrollment failed: encryption not available', array( 'user_id' => $user_id ) );
			return new \WP_Error(
				'encryption_unavailable',
				__( 'Two-factor authentication requires libsodium encryption which is not available on this server.', 'atomic-edge-security' )
			);
		}
		self::debug_log( 'start_enrollment() encryption is available' );

		self::debug_log( 'start_enrollment() generating secret...' );
		$secret = AtomicEdge_2FA_TOTP::generate_secret();
		self::debug_log( 'start_enrollment() secret generated, length: ' . strlen( $secret ) );

		// Store encrypted pending secret.
		self::debug_log( 'start_enrollment() encrypting secret...' );
		$encrypted = AtomicEdge_2FA_Crypto::encrypt( $secret );
		if ( is_wp_error( $encrypted ) ) {
			self::debug_log( 'start_enrollment() encryption failed: ' . $encrypted->get_error_message() );
			AtomicEdge::log( '2FA enrollment failed: encryption failed', array(
				'user_id' => $user_id,
				'error'   => $encrypted->get_error_message(),
			) );
			return new \WP_Error(
				'encryption_failed',
				/* translators: %s: specific error message */
				sprintf( __( 'Encryption failed: %s', 'atomic-edge-security' ), $encrypted->get_error_message() )
			);
		}
		self::debug_log( 'start_enrollment() encryption successful, encrypted length: ' . strlen( $encrypted ) );

		// Clear any existing pending secret first (for clean state).
		self::debug_log( 'start_enrollment() clearing old pending secret...' );
		delete_user_meta( $user_id, self::META_PENDING_SECRET );

		// Store the encrypted secret.
		self::debug_log( 'start_enrollment() storing encrypted secret...' );
		$result = update_user_meta( $user_id, self::META_PENDING_SECRET, $encrypted );
		self::debug_log( 'start_enrollment() update_user_meta result: ' . var_export( $result, true ) );

		// Verify it was actually saved (handles object cache issues).
		// Force a fresh read from database by cleaning the cache.
		if ( function_exists( 'wp_cache_delete' ) ) {
			self::debug_log( 'start_enrollment() clearing user_meta cache...' );
			wp_cache_delete( $user_id, 'user_meta' );
		}
		$verify = get_user_meta( $user_id, self::META_PENDING_SECRET, true );
		self::debug_log( 'start_enrollment() verification read, length: ' . ( $verify ? strlen( $verify ) : 'empty/false' ) );

		if ( empty( $verify ) ) {
			self::debug_log( 'start_enrollment() failed: meta not persisted after write' );
			AtomicEdge::log( '2FA enrollment failed: meta not persisted', array(
				'user_id'       => $user_id,
				'update_result' => $result,
			) );
			return new \WP_Error(
				'meta_not_saved',
				__( 'Failed to save enrollment data. This may be caused by database issues or object caching. Please try again or contact support.', 'atomic-edge-security' )
			);
		}
		self::debug_log( 'start_enrollment() meta verified, generating provisioning URI...' );

		// Generate provisioning URI.
		$provisioning_uri = AtomicEdge_2FA_TOTP::get_provisioning_uri(
			$secret,
			$user->user_login,
			get_bloginfo( 'name' )
		);
		self::debug_log( 'start_enrollment() provisioning URI generated' );

		self::log_event( $user_id, 'enrollment_started' );
		self::debug_log( 'start_enrollment() SUCCESS' );

		return array(
			'secret'           => $secret,
			'provisioning_uri' => $provisioning_uri,
		);
	}

	/**
	 * Complete 2FA enrollment by verifying a TOTP code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    TOTP code to verify.
	 * @return array {
	 *     @type bool   $success      Whether enrollment succeeded.
	 *     @type string $error        Error message if failed.
	 *     @type array  $backup_codes Plaintext backup codes (on success).
	 * }
	 */
	public static function complete_enrollment( $user_id, $code ) {
		// Force fresh read from database (bypass object cache).
		if ( function_exists( 'wp_cache_delete' ) ) {
			wp_cache_delete( $user_id, 'user_meta' );
		}

		// Get pending secret.
		$encrypted = get_user_meta( $user_id, self::META_PENDING_SECRET, true );
		if ( empty( $encrypted ) ) {
			AtomicEdge::log( '2FA verify failed: no pending secret', array(
				'user_id'    => $user_id,
				'meta_key'   => self::META_PENDING_SECRET,
				'meta_value' => $encrypted,
			) );
			return array(
				'success' => false,
				'error'   => __( 'No pending enrollment found. Please start setup again.', 'atomic-edge-security' ),
			);
		}

		$secret = AtomicEdge_2FA_Crypto::decrypt( $encrypted );
		if ( false === $secret ) {
			return array(
				'success' => false,
				'error'   => __( 'Failed to decrypt secret. Please start setup again.', 'atomic-edge-security' ),
			);
		}

		// Verify the code.
		if ( ! AtomicEdge_2FA_TOTP::verify( $secret, $code ) ) {
			return array(
				'success' => false,
				'error'   => __( 'Invalid verification code. Please check your authenticator app and try again.', 'atomic-edge-security' ),
			);
		}

		// Code is valid - enable 2FA.
		$encrypted_secret = AtomicEdge_2FA_Crypto::encrypt( $secret );
		update_user_meta( $user_id, self::META_TOTP_SECRET, $encrypted_secret );
		update_user_meta( $user_id, self::META_ENABLED, '1' );
		update_user_meta( $user_id, self::META_SETUP_DATE, time() );

		// Generate backup codes.
		$backup = AtomicEdge_2FA_Backup::generate();
		update_user_meta( $user_id, self::META_BACKUP_CODES, $backup['hashed_codes'] );

		// Clean up pending secret.
		delete_user_meta( $user_id, self::META_PENDING_SECRET );

		// Reset any rate limiting.
		self::reset_rate_limit( $user_id );

		// End grace period since user is now enrolled.
		if ( class_exists( 'AtomicEdge_2FA_Policy' ) ) {
			AtomicEdge_2FA_Policy::end_grace_period( $user_id );
		}

		self::log_event( $user_id, 'enrollment_completed' );

		return array(
			'success'      => true,
			'backup_codes' => $backup['codes'],
		);
	}

	/**
	 * Cancel pending enrollment.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public static function cancel_enrollment( $user_id ) {
		delete_user_meta( $user_id, self::META_PENDING_SECRET );
		self::log_event( $user_id, 'enrollment_cancelled' );
	}

	/**
	 * Disable 2FA for a user.
	 *
	 * @param int $user_id User ID.
	 * @return bool True on success.
	 */
	public static function disable( $user_id ) {
		delete_user_meta( $user_id, self::META_TOTP_SECRET );
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_BACKUP_CODES );
		delete_user_meta( $user_id, self::META_PENDING_SECRET );
		delete_user_meta( $user_id, self::META_LAST_USED );
		self::reset_rate_limit( $user_id );

		// Reset grace period so it starts fresh if policy still enforces.
		if ( class_exists( 'AtomicEdge_2FA_Policy' ) ) {
			delete_user_meta( $user_id, AtomicEdge_2FA_Policy::META_GRACE_START );
			delete_user_meta( $user_id, AtomicEdge_2FA_Policy::META_NOTICE_DISMISSED );
		}

		self::log_event( $user_id, '2fa_disabled' );

		return true;
	}

	/**
	 * Regenerate backup codes for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array|false Array of new plaintext codes, or false on failure.
	 */
	public static function regenerate_backup_codes( $user_id ) {
		if ( ! self::is_enabled_for_user( $user_id ) ) {
			return false;
		}

		$backup = AtomicEdge_2FA_Backup::generate();
		update_user_meta( $user_id, self::META_BACKUP_CODES, $backup['hashed_codes'] );

		self::log_event( $user_id, 'backup_codes_regenerated' );

		return $backup['codes'];
	}

	/**
	 * Verify a TOTP code for a user.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Code to verify.
	 * @return bool True if valid.
	 */
	public static function verify_totp( $user_id, $code ) {
		$secret = self::get_user_secret( $user_id );
		if ( false === $secret ) {
			return false;
		}
		return AtomicEdge_2FA_TOTP::verify( $secret, $code );
	}

	/**
	 * Verify a backup code for a user.
	 *
	 * Marks the code as used if valid.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Backup code to verify.
	 * @return bool True if valid.
	 */
	public static function verify_backup_code( $user_id, $code ) {
		$hashed_codes = get_user_meta( $user_id, self::META_BACKUP_CODES, true );
		if ( empty( $hashed_codes ) ) {
			return false;
		}

		$index = AtomicEdge_2FA_Backup::verify( $code, $hashed_codes );
		if ( false === $index ) {
			return false;
		}

		// Mark as used.
		$hashed_codes = AtomicEdge_2FA_Backup::mark_used( $hashed_codes, $index );
		update_user_meta( $user_id, self::META_BACKUP_CODES, $hashed_codes );

		self::log_event( $user_id, 'backup_code_used' );

		return true;
	}

	/**
	 * Check if a user is currently rate-limited.
	 *
	 * @param int $user_id User ID.
	 * @return int|false Seconds until lockout expires, or false if not locked.
	 */
	public static function is_rate_limited( $user_id ) {
		$lockout_until = (int) get_user_meta( $user_id, self::META_LOCKOUT_UNTIL, true );
		if ( $lockout_until > time() ) {
			return $lockout_until - time();
		}
		return false;
	}

	/**
	 * Record a failed verification attempt.
	 *
	 * @param int $user_id User ID.
	 * @return int|false Lockout duration in seconds, or false if not locked.
	 */
	public static function record_failed_attempt( $user_id ) {
		$attempts = (int) get_user_meta( $user_id, self::META_FAILED_ATTEMPTS, true );
		$attempts++;
		update_user_meta( $user_id, self::META_FAILED_ATTEMPTS, $attempts );

		// Check if we should apply rate limiting.
		$lockout_duration = 0;
		foreach ( self::RATE_LIMITS as $threshold => $duration ) {
			if ( $attempts >= $threshold ) {
				$lockout_duration = $duration;
			}
		}

		if ( $lockout_duration > 0 ) {
			$lockout_until = time() + $lockout_duration;
			update_user_meta( $user_id, self::META_LOCKOUT_UNTIL, $lockout_until );
			self::log_event( $user_id, 'rate_limited', array( 'attempts' => $attempts, 'duration' => $lockout_duration ) );
			return $lockout_duration;
		}

		return false;
	}

	/**
	 * Reset rate limiting for a user.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public static function reset_rate_limit( $user_id ) {
		delete_user_meta( $user_id, self::META_FAILED_ATTEMPTS );
		delete_user_meta( $user_id, self::META_LOCKOUT_UNTIL );
	}

	/**
	 * Record a successful verification.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public static function record_success( $user_id ) {
		update_user_meta( $user_id, self::META_LAST_USED, time() );
		self::reset_rate_limit( $user_id );
	}

	/**
	 * Get 2FA status information for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array Status information.
	 */
	public static function get_user_status( $user_id ) {
		$enabled    = self::is_enabled_for_user( $user_id );
		$setup_date = (int) get_user_meta( $user_id, self::META_SETUP_DATE, true );
		$last_used  = (int) get_user_meta( $user_id, self::META_LAST_USED, true );

		$backup_codes    = get_user_meta( $user_id, self::META_BACKUP_CODES, true );
		$codes_remaining = $backup_codes ? AtomicEdge_2FA_Backup::count_remaining( $backup_codes ) : 0;

		return array(
			'enabled'         => $enabled,
			'setup_date'      => $setup_date ? wp_date( 'F j, Y', $setup_date ) : null,
			'last_used'       => $last_used ? wp_date( 'F j, Y g:i A', $last_used ) : null,
			'codes_remaining' => $codes_remaining,
			'codes_total'     => AtomicEdge_2FA_Backup::CODE_COUNT,
		);
	}

	/**
	 * Create a login nonce for 2FA validation.
	 *
	 * @param int $user_id User ID.
	 * @return array {
	 *     @type string $key        Nonce key (for form).
	 *     @type int    $expiration Expiration timestamp.
	 * }
	 */
	public static function create_login_nonce( $user_id ) {
		$nonce = array(
			'key'        => AtomicEdge_2FA_Crypto::random_hex( 32 ),
			'expiration' => time() + ( 10 * MINUTE_IN_SECONDS ),
		);

		// Store hashed nonce.
		$stored = array(
			'key'        => wp_hash( $nonce['key'], 'nonce' ),
			'expiration' => $nonce['expiration'],
		);
		update_user_meta( $user_id, self::META_LOGIN_NONCE, $stored );

		return $nonce;
	}

	/**
	 * Verify a login nonce.
	 *
	 * @param int    $user_id User ID.
	 * @param string $key     Nonce key to verify.
	 * @return bool True if valid and not expired.
	 */
	public static function verify_login_nonce( $user_id, $key ) {
		$stored = get_user_meta( $user_id, self::META_LOGIN_NONCE, true );
		if ( empty( $stored ) ) {
			return false;
		}

		// Check expiration.
		if ( time() > $stored['expiration'] ) {
			self::delete_login_nonce( $user_id );
			return false;
		}

		// Verify key.
		$provided_hash = wp_hash( $key, 'nonce' );
		return AtomicEdge_2FA_Crypto::hash_equals( $stored['key'], $provided_hash );
	}

	/**
	 * Delete login nonce.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public static function delete_login_nonce( $user_id ) {
		delete_user_meta( $user_id, self::META_LOGIN_NONCE );
	}

	/**
	 * Log a 2FA event.
	 *
	 * @param int    $user_id User ID.
	 * @param string $event   Event type.
	 * @param array  $context Additional context.
	 * @return void
	 */
	public static function log_event( $user_id, $event, $context = array() ) {
		$user = get_userdata( $user_id );
		$log  = sprintf(
			'AtomicEdge 2FA: %s for user %s (ID: %d)',
			$event,
			$user ? $user->user_login : 'unknown',
			$user_id
		);

		if ( ! empty( $context ) ) {
			$log .= ' - ' . wp_json_encode( $context );
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( $log );
		}

		/**
		 * Fires when a 2FA event occurs.
		 *
		 * @param int    $user_id User ID.
		 * @param string $event   Event type.
		 * @param array  $context Event context.
		 */
		do_action( 'atomicedge_2fa_event', $user_id, $event, $context );
	}

	/**
	 * Render the 2FA section on user profile page.
	 *
	 * @param WP_User $user User object.
	 * @return void
	 */
	public function render_user_profile_section( $user ) {
		// Only show to the user themselves or admins.
		if ( get_current_user_id() !== $user->ID && ! current_user_can( 'edit_users' ) ) {
			return;
		}

		// Include the view.
		$status = self::get_user_status( $user->ID );
		include ATOMICEDGE_PLUGIN_DIR . 'admin/views/two-factor.php';
	}

	/**
	 * Enqueue scripts for user profile page.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_profile_scripts( $hook ) {
		if ( 'profile.php' !== $hook && 'user-edit.php' !== $hook ) {
			return;
		}

		// QR code generator (client-side).
		wp_enqueue_script(
			'atomicedge-qrcode',
			ATOMICEDGE_PLUGIN_URL . 'assets/js/qrcode.min.js',
			array(),
			ATOMICEDGE_VERSION,
			true
		);

		// 2FA enrollment script.
		wp_enqueue_script(
			'atomicedge-2fa',
			ATOMICEDGE_PLUGIN_URL . 'admin/js/two-factor.js',
			array( 'jquery', 'atomicedge-qrcode' ),
			ATOMICEDGE_VERSION,
			true
		);

		wp_localize_script( 'atomicedge-2fa', 'atomicedge2fa', array(
			'ajax_url' => admin_url( 'admin-ajax.php' ),
			'nonce'    => wp_create_nonce( 'atomicedge_2fa' ),
			'user_id'  => isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : get_current_user_id(),
			'strings'  => array(
				'confirm_disable'     => __( 'Are you sure you want to disable two-factor authentication? This will make your account less secure.', 'atomic-edge-security' ),
				'confirm_regenerate'  => __( 'This will invalidate all existing backup codes. Are you sure?', 'atomic-edge-security' ),
				'verification_failed' => __( 'Verification failed. Please try again.', 'atomic-edge-security' ),
				'download_codes'      => __( 'Download Backup Codes', 'atomic-edge-security' ),
			),
		) );

		// Add styles.
		wp_add_inline_style( 'wp-admin', $this->get_profile_styles() );
	}

	/**
	 * Get inline styles for 2FA profile section.
	 *
	 * @return string CSS styles.
	 */
	private function get_profile_styles() {
		return '
			.atomicedge-2fa-section {
				background: #fff;
				border: 1px solid #c3c4c7;
				border-left: 4px solid #2271b1;
				padding: 20px;
				margin: 20px 0;
			}
			.atomicedge-2fa-section h2 {
				margin-top: 0;
				display: flex;
				align-items: center;
				gap: 8px;
			}
			.atomicedge-2fa-status {
				margin: 15px 0;
			}
			.atomicedge-2fa-status dt {
				font-weight: 600;
				margin-top: 10px;
			}
			.atomicedge-2fa-status dd {
				margin-left: 0;
				color: #50575e;
			}
			.atomicedge-2fa-qr {
				text-align: center;
				padding: 20px;
				background: #f6f7f7;
				border-radius: 4px;
				margin: 15px 0;
			}
			.atomicedge-2fa-qr canvas {
				margin: 10px auto;
				display: block;
			}
			.atomicedge-2fa-secret {
				font-family: monospace;
				font-size: 14px;
				background: #fff;
				padding: 8px 12px;
				border: 1px solid #c3c4c7;
				border-radius: 4px;
				word-break: break-all;
			}
			.atomicedge-2fa-codes {
				display: grid;
				grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
				gap: 10px;
				margin: 15px 0;
			}
			.atomicedge-2fa-codes code {
				display: block;
				text-align: center;
				padding: 8px;
				background: #f6f7f7;
				border: 1px solid #c3c4c7;
				border-radius: 4px;
				font-size: 14px;
			}
			.atomicedge-2fa-verify-form {
				max-width: 300px;
			}
			.atomicedge-2fa-verify-form input[type="text"] {
				font-size: 18px;
				text-align: center;
				letter-spacing: 4px;
			}
			.atomicedge-2fa-warning {
				background: #fcf9e8;
				border-left-color: #dba617;
				padding: 12px;
				margin: 15px 0;
			}
			.atomicedge-2fa-badge {
				display: inline-block;
				padding: 2px 8px;
				border-radius: 10px;
				font-size: 11px;
				font-weight: 600;
				text-transform: uppercase;
			}
			.atomicedge-2fa-badge.active {
				background: #d1e7dd;
				color: #0a3622;
			}
			.atomicedge-2fa-badge.inactive {
				background: #f8d7da;
				color: #58151c;
			}
			.atomicedge-2fa-step {
				display: none;
			}
			.atomicedge-2fa-step.active {
				display: block;
			}
		';
	}

	/**
	 * Clean up user data on deletion.
	 *
	 * @param int $user_id User ID being deleted.
	 * @return void
	 */
	public function cleanup_user_data( $user_id ) {
		delete_user_meta( $user_id, self::META_TOTP_SECRET );
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_BACKUP_CODES );
		delete_user_meta( $user_id, self::META_PENDING_SECRET );
		delete_user_meta( $user_id, self::META_FAILED_ATTEMPTS );
		delete_user_meta( $user_id, self::META_LOCKOUT_UNTIL );
		delete_user_meta( $user_id, self::META_LAST_USED );
		delete_user_meta( $user_id, self::META_SETUP_DATE );
		delete_user_meta( $user_id, self::META_LOGIN_NONCE );

		// Clean up policy-related meta.
		if ( class_exists( 'AtomicEdge_2FA_Policy' ) ) {
			delete_user_meta( $user_id, AtomicEdge_2FA_Policy::META_GRACE_START );
			delete_user_meta( $user_id, AtomicEdge_2FA_Policy::META_NOTICE_DISMISSED );
		}
	}

	/**
	 * Display conflict notice if another 2FA plugin is detected.
	 *
	 * @return void
	 */
	public function display_conflict_notice() {
		// Only show on relevant pages.
		$screen = get_current_screen();
		if ( ! $screen || ! in_array( $screen->id, array( 'profile', 'user-edit' ), true ) ) {
			return;
		}

		// Check for known 2FA plugins.
		$conflicts = array();

		if ( class_exists( 'Two_Factor' ) || class_exists( 'Two_Factor_Core' ) ) {
			$conflicts[] = 'Two-Factor';
		}
		if ( defined( 'WORDFENCE_VERSION' ) && class_exists( 'wordfence' ) ) {
			// Check if Wordfence 2FA is enabled.
			if ( get_option( 'wf2FAEnabled', false ) ) {
				$conflicts[] = 'Wordfence';
			}
		}
		if ( class_exists( 'Google_Authenticator' ) ) {
			$conflicts[] = 'Google Authenticator';
		}

		if ( empty( $conflicts ) ) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
			esc_html__( 'AtomicEdge 2FA:', 'atomic-edge-security' ),
			sprintf(
				/* translators: %s: List of conflicting plugins */
				esc_html__( 'Another two-factor authentication plugin is active (%s). Using multiple 2FA solutions may cause login conflicts.', 'atomic-edge-security' ),
				esc_html( implode( ', ', $conflicts ) )
			)
		);
	}

	/**
	 * Check if encryption is available.
	 *
	 * @return bool True if 2FA can be used.
	 */
	public static function is_available() {
		return AtomicEdge_2FA_Crypto::is_available();
	}

	/**
	 * Display admin notice reminding users to set up 2FA if required.
	 *
	 * @return void
	 */
	public function display_enforcement_reminder() {
		// Only check if policy class exists and user is logged in.
		if ( ! class_exists( 'AtomicEdge_2FA_Policy' ) ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			return;
		}

		// Get policy settings.
		$settings = AtomicEdge_2FA_Policy::get_settings();

		// Check if reminders are enabled and policy is active.
		if ( empty( $settings['enabled'] ) || empty( $settings['show_reminders'] ) ) {
			return;
		}

		// Check if user needs 2FA but doesn't have it.
		if ( ! AtomicEdge_2FA_Policy::is_required_for_user( $user_id ) ) {
			return;
		}

		if ( self::is_enabled_for_user( $user_id ) ) {
			return;
		}

		// Check if reminder was recently dismissed.
		if ( AtomicEdge_2FA_Policy::is_reminder_dismissed( $user_id ) ) {
			return;
		}

		// Get grace period info.
		$grace_days = AtomicEdge_2FA_Policy::get_grace_days_remaining( $user_id );
		$is_urgent  = $grace_days <= 2 && $grace_days > 0;
		$is_expired = $grace_days <= 0;

		// Build the message.
		if ( $is_expired ) {
			$notice_class = 'notice-error';
			$message      = __( 'Your grace period has expired. Please set up two-factor authentication immediately to maintain access to your account.', 'atomic-edge-security' );
		} elseif ( $is_urgent ) {
			$notice_class = 'notice-warning';
			$message      = sprintf(
				/* translators: %d: Number of days remaining */
				_n(
					'Your grace period expires in %d day! Please set up two-factor authentication now.',
					'Your grace period expires in %d days! Please set up two-factor authentication now.',
					$grace_days,
					'atomic-edge-security'
				),
				$grace_days
			);
		} else {
			$notice_class = 'notice-info';
			$message      = sprintf(
				/* translators: %d: Number of days remaining */
				_n(
					'Two-factor authentication is required for your role. You have %d day to set it up.',
					'Two-factor authentication is required for your role. You have %d days to set it up.',
					$grace_days,
					'atomic-edge-security'
				),
				$grace_days
			);
		}

		$profile_url = admin_url( 'profile.php#atomicedge-2fa-section' );

		?>
		<div class="notice <?php echo esc_attr( $notice_class ); ?> is-dismissible atomicedge-2fa-reminder" data-nonce="<?php echo esc_attr( wp_create_nonce( 'atomicedge_dismiss_2fa_reminder' ) ); ?>">
			<p>
				<span class="dashicons dashicons-shield-alt" style="vertical-align: middle; margin-right: 4px;"></span>
				<strong><?php esc_html_e( 'AtomicEdge Security:', 'atomic-edge-security' ); ?></strong>
				<?php echo esc_html( $message ); ?>
				<a href="<?php echo esc_url( $profile_url ); ?>" class="button button-primary button-small" style="margin-left: 10px;">
					<?php esc_html_e( 'Set Up 2FA', 'atomic-edge-security' ); ?>
				</a>
			</p>
		</div>
		<script>
		jQuery(document).ready(function($) {
			$('.atomicedge-2fa-reminder').on('click', '.notice-dismiss', function() {
				var $notice = $(this).closest('.atomicedge-2fa-reminder');
				$.post(ajaxurl, {
					action: 'atomicedge_dismiss_2fa_reminder',
					nonce: $notice.data('nonce')
				});
			});
		});
		</script>
		<?php
	}

	/**
	 * AJAX handler for dismissing the 2FA reminder notice.
	 *
	 * @return void
	 */
	public function ajax_dismiss_reminder() {
		// Verify nonce.
		if ( ! isset( $_POST['nonce'] ) ||
			! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nonce'] ) ), 'atomicedge_dismiss_2fa_reminder' ) ) {
			wp_send_json_error( 'Invalid nonce' );
		}

		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			wp_send_json_error( 'Not logged in' );
		}

		AtomicEdge_2FA_Policy::dismiss_reminder( $user_id );
		wp_send_json_success();
	}
}
