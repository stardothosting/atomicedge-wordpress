<?php
/**
 * AtomicEdge 2FA Audit Logging
 *
 * Stores and retrieves 2FA audit logs for security monitoring.
 *
 * @package AtomicEdge
 * @since   1.8.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_2FA_Audit
 *
 * Handles 2FA audit logging and retrieval.
 */
class AtomicEdge_2FA_Audit {

	/**
	 * Option key for audit log storage.
	 *
	 * Using options for simplicity; could migrate to custom table for high-volume sites.
	 *
	 * @var string
	 */
	const OPTION_KEY = 'atomicedge_2fa_audit_log';

	/**
	 * Maximum number of log entries to retain.
	 *
	 * @var int
	 */
	const MAX_ENTRIES = 500;

	/**
	 * Log retention period in days.
	 *
	 * @var int
	 */
	const RETENTION_DAYS = 90;

	/**
	 * Event type labels for display.
	 *
	 * @var array
	 */
	private static $event_labels = array(
		'enrollment_started'       => 'Started 2FA setup',
		'enrollment_completed'     => 'Completed 2FA setup',
		'enrollment_cancelled'     => 'Cancelled 2FA setup',
		'2fa_disabled'             => 'Disabled 2FA',
		'backup_codes_regenerated' => 'Regenerated backup codes',
		'backup_code_used'         => 'Used a backup code',
		'totp_verified'            => 'Verified with authenticator',
		'login_success'            => 'Logged in with 2FA',
		'login_failed'             => 'Failed 2FA verification',
		'rate_limited'             => 'Rate limited (too many attempts)',
		'grace_period_started'     => 'Grace period started',
		'admin_reset'              => 'Admin reset 2FA',
		'policy_updated'           => 'Policy settings updated',
	);

	/**
	 * Event severity levels.
	 *
	 * @var array
	 */
	private static $event_severity = array(
		'enrollment_completed'     => 'success',
		'2fa_disabled'             => 'warning',
		'login_success'            => 'success',
		'login_failed'             => 'danger',
		'rate_limited'             => 'danger',
		'backup_code_used'         => 'warning',
		'admin_reset'              => 'warning',
	);

	/**
	 * Initialize the audit system.
	 *
	 * @return void
	 */
	public static function init() {
		// Hook into the 2FA event action.
		add_action( 'atomicedge_2fa_event', array( __CLASS__, 'log_event' ), 10, 3 );

		// Schedule cleanup.
		if ( ! wp_next_scheduled( 'atomicedge_2fa_audit_cleanup' ) ) {
			wp_schedule_event( time(), 'daily', 'atomicedge_2fa_audit_cleanup' );
		}
		add_action( 'atomicedge_2fa_audit_cleanup', array( __CLASS__, 'cleanup_old_entries' ) );
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
		$log = self::get_log();

		// Get user info.
		$user = get_userdata( $user_id );

		// Get IP address (sanitized).
		$ip_address = self::get_client_ip();

		// Create log entry.
		$entry = array(
			'timestamp'  => time(),
			'user_id'    => $user_id,
			'user_login' => $user ? $user->user_login : 'unknown',
			'user_email' => $user ? $user->user_email : '',
			'event'      => $event,
			'ip_address' => $ip_address,
			'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] )
				? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 200 )
				: '',
			'context'    => $context,
		);

		// Add admin info if this was an admin action.
		$current_user_id = get_current_user_id();
		if ( $current_user_id && $current_user_id !== $user_id ) {
			$admin = get_userdata( $current_user_id );
			$entry['admin_id']    = $current_user_id;
			$entry['admin_login'] = $admin ? $admin->user_login : 'unknown';
		}

		// Prepend to log (newest first).
		array_unshift( $log, $entry );

		// Trim to max entries.
		$log = array_slice( $log, 0, self::MAX_ENTRIES );

		self::save_log( $log );
	}

	/**
	 * Get the audit log.
	 *
	 * @return array Array of log entries.
	 */
	public static function get_log() {
		$log = get_option( self::OPTION_KEY, array() );
		return is_array( $log ) ? $log : array();
	}

	/**
	 * Save the audit log.
	 *
	 * @param array $log Log entries.
	 * @return bool True on success.
	 */
	private static function save_log( $log ) {
		return update_option( self::OPTION_KEY, $log, false ); // Don't autoload.
	}

	/**
	 * Get filtered audit log entries.
	 *
	 * @param array $args {
	 *     Optional. Filter arguments.
	 *
	 *     @type int    $user_id Filter by user ID.
	 *     @type string $event   Filter by event type.
	 *     @type int    $limit   Maximum entries to return.
	 *     @type int    $offset  Offset for pagination.
	 *     @type int    $since   Only entries after this timestamp.
	 * }
	 * @return array {
	 *     @type array $entries Log entries.
	 *     @type int   $total   Total matching entries.
	 * }
	 */
	public static function get_entries( $args = array() ) {
		$defaults = array(
			'user_id' => 0,
			'event'   => '',
			'limit'   => 50,
			'offset'  => 0,
			'since'   => 0,
		);
		$args = wp_parse_args( $args, $defaults );

		$log     = self::get_log();
		$entries = array();

		foreach ( $log as $entry ) {
			// Filter by user.
			if ( $args['user_id'] && $entry['user_id'] !== $args['user_id'] ) {
				continue;
			}

			// Filter by event.
			if ( $args['event'] && $entry['event'] !== $args['event'] ) {
				continue;
			}

			// Filter by timestamp.
			if ( $args['since'] && $entry['timestamp'] < $args['since'] ) {
				continue;
			}

			$entries[] = $entry;
		}

		$total = count( $entries );

		// Apply pagination.
		$entries = array_slice( $entries, $args['offset'], $args['limit'] );

		return array(
			'entries' => $entries,
			'total'   => $total,
		);
	}

	/**
	 * Get entries for a specific user.
	 *
	 * @param int $user_id User ID.
	 * @param int $limit   Maximum entries.
	 * @return array Log entries.
	 */
	public static function get_user_entries( $user_id, $limit = 20 ) {
		$result = self::get_entries( array(
			'user_id' => $user_id,
			'limit'   => $limit,
		) );
		return $result['entries'];
	}

	/**
	 * Get recent security events (failures, rate limits, etc.).
	 *
	 * @param int $limit Maximum entries.
	 * @return array Log entries.
	 */
	public static function get_security_events( $limit = 50 ) {
		$security_events = array( 'login_failed', 'rate_limited', 'admin_reset', '2fa_disabled' );
		$log             = self::get_log();
		$entries         = array();

		foreach ( $log as $entry ) {
			if ( in_array( $entry['event'], $security_events, true ) ) {
				$entries[] = $entry;
				if ( count( $entries ) >= $limit ) {
					break;
				}
			}
		}

		return $entries;
	}

	/**
	 * Clean up old entries.
	 *
	 * @return int Number of entries removed.
	 */
	public static function cleanup_old_entries() {
		$log      = self::get_log();
		$cutoff   = time() - ( self::RETENTION_DAYS * DAY_IN_SECONDS );
		$original = count( $log );

		$log = array_filter(
			$log,
			function ( $entry ) use ( $cutoff ) {
				return $entry['timestamp'] >= $cutoff;
			}
		);

		// Re-index array.
		$log = array_values( $log );

		self::save_log( $log );

		return $original - count( $log );
	}

	/**
	 * Clear all audit logs.
	 *
	 * @return bool True on success.
	 */
	public static function clear_log() {
		return delete_option( self::OPTION_KEY );
	}

	/**
	 * Get human-readable event label.
	 *
	 * @param string $event Event type.
	 * @return string Label.
	 */
	public static function get_event_label( $event ) {
		return isset( self::$event_labels[ $event ] ) ? self::$event_labels[ $event ] : $event;
	}

	/**
	 * Get event severity for styling.
	 *
	 * @param string $event Event type.
	 * @return string Severity level (success, warning, danger, info).
	 */
	public static function get_event_severity( $event ) {
		return isset( self::$event_severity[ $event ] ) ? self::$event_severity[ $event ] : 'info';
	}

	/**
	 * Get client IP address.
	 *
	 * @return string IP address.
	 */
	private static function get_client_ip() {
		$ip = '';

		// Check for proxy headers first.
		$headers = array(
			'HTTP_CF_CONNECTING_IP', // Cloudflare.
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		);

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				// X-Forwarded-For can contain multiple IPs; take the first.
				if ( strpos( $ip, ',' ) !== false ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
				break;
			}
		}

		// Validate IP.
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			$ip = '0.0.0.0';
		}

		return $ip;
	}

	/**
	 * Get audit statistics.
	 *
	 * @param int $days Number of days to analyze.
	 * @return array Statistics.
	 */
	public static function get_statistics( $days = 30 ) {
		$since  = time() - ( $days * DAY_IN_SECONDS );
		$result = self::get_entries( array(
			'since' => $since,
			'limit' => self::MAX_ENTRIES,
		) );

		$stats = array(
			'total_events'     => $result['total'],
			'login_success'    => 0,
			'login_failed'     => 0,
			'enrollments'      => 0,
			'disabled'         => 0,
			'backup_code_used' => 0,
			'rate_limited'     => 0,
			'admin_resets'     => 0,
		);

		foreach ( $result['entries'] as $entry ) {
			switch ( $entry['event'] ) {
				case 'login_success':
					$stats['login_success']++;
					break;
				case 'login_failed':
					$stats['login_failed']++;
					break;
				case 'enrollment_completed':
					$stats['enrollments']++;
					break;
				case '2fa_disabled':
					$stats['disabled']++;
					break;
				case 'backup_code_used':
					$stats['backup_code_used']++;
					break;
				case 'rate_limited':
					$stats['rate_limited']++;
					break;
				case 'admin_reset':
					$stats['admin_resets']++;
					break;
			}
		}

		return $stats;
	}

	/**
	 * Export audit log to array (for JSON/CSV export).
	 *
	 * @param int $limit Maximum entries.
	 * @return array Export data.
	 */
	public static function export( $limit = 1000 ) {
		$result  = self::get_entries( array( 'limit' => $limit ) );
		$entries = array();

		foreach ( $result['entries'] as $entry ) {
			$entries[] = array(
				'date'       => wp_date( 'Y-m-d H:i:s', $entry['timestamp'] ),
				'user'       => $entry['user_login'],
				'user_email' => $entry['user_email'],
				'event'      => self::get_event_label( $entry['event'] ),
				'ip_address' => $entry['ip_address'],
				'admin'      => isset( $entry['admin_login'] ) ? $entry['admin_login'] : '',
			);
		}

		return $entries;
	}
}
