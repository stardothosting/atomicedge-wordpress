<?php
/**
 * AtomicEdge 2FA Enforcement Policy
 *
 * Manages role-based 2FA enforcement settings and grace periods.
 *
 * @package AtomicEdge
 * @since   1.8.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_2FA_Policy
 *
 * Handles 2FA enforcement policies for different user roles.
 */
class AtomicEdge_2FA_Policy {

	/**
	 * Option key for policy settings.
	 *
	 * @var string
	 */
	const OPTION_KEY = 'atomicedge_2fa_policy';

	/**
	 * User meta key for grace period start.
	 *
	 * @var string
	 */
	const META_GRACE_START = '_atomicedge_2fa_grace_start';

	/**
	 * User meta key for enforcement notice dismissed.
	 *
	 * @var string
	 */
	const META_NOTICE_DISMISSED = '_atomicedge_2fa_notice_dismissed';

	/**
	 * Default policy settings.
	 *
	 * @var array
	 */
	private static $defaults = array(
		'enabled'            => false,
		'enforced_roles'     => array(),
		'grace_period_days'  => 7,
		'allow_grace_bypass' => true,
		'show_reminders'     => true,
	);

	/**
	 * Get policy settings.
	 *
	 * @return array Policy settings array.
	 */
	public static function get_settings() {
		$settings = get_option( self::OPTION_KEY, array() );
		return wp_parse_args( $settings, self::$defaults );
	}

	/**
	 * Update policy settings.
	 *
	 * @param array $settings Settings to save.
	 * @return bool True on success.
	 */
	public static function update_settings( $settings ) {
		$sanitized = self::sanitize_settings( $settings );
		return update_option( self::OPTION_KEY, $sanitized );
	}

	/**
	 * Sanitize policy settings.
	 *
	 * @param array $settings Raw settings.
	 * @return array Sanitized settings.
	 */
	private static function sanitize_settings( $settings ) {
		$sanitized = array();

		$sanitized['enabled'] = ! empty( $settings['enabled'] );

		// Sanitize roles array.
		$sanitized['enforced_roles'] = array();
		if ( ! empty( $settings['enforced_roles'] ) && is_array( $settings['enforced_roles'] ) ) {
			$valid_roles = array_keys( wp_roles()->roles );
			foreach ( $settings['enforced_roles'] as $role ) {
				$role = sanitize_key( $role );
				if ( in_array( $role, $valid_roles, true ) ) {
					$sanitized['enforced_roles'][] = $role;
				}
			}
		}

		// Sanitize grace period (1-90 days, or 0 for no grace).
		$grace_days = isset( $settings['grace_period_days'] ) ? absint( $settings['grace_period_days'] ) : 7;
		$sanitized['grace_period_days'] = min( 90, max( 0, $grace_days ) );

		$sanitized['allow_grace_bypass'] = ! empty( $settings['allow_grace_bypass'] );
		$sanitized['show_reminders'] = ! empty( $settings['show_reminders'] );

		return $sanitized;
	}

	/**
	 * Check if 2FA is required for a user.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if 2FA is required for this user.
	 */
	public static function is_required_for_user( $user_id ) {
		$settings = self::get_settings();

		// Policy not enabled.
		if ( empty( $settings['enabled'] ) ) {
			return false;
		}

		// No roles enforced.
		if ( empty( $settings['enforced_roles'] ) ) {
			return false;
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}

		// Check if user has any enforced role.
		$user_roles = (array) $user->roles;
		foreach ( $settings['enforced_roles'] as $role ) {
			if ( in_array( $role, $user_roles, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if user is within grace period.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if user is in grace period.
	 */
	public static function is_in_grace_period( $user_id ) {
		$settings = self::get_settings();

		// Grace period disabled.
		if ( empty( $settings['grace_period_days'] ) ) {
			return false;
		}

		// Check if grace period started.
		$grace_start = (int) get_user_meta( $user_id, self::META_GRACE_START, true );
		if ( ! $grace_start ) {
			return false;
		}

		$grace_end = $grace_start + ( $settings['grace_period_days'] * DAY_IN_SECONDS );
		return time() < $grace_end;
	}

	/**
	 * Get remaining grace period days.
	 *
	 * @param int $user_id User ID.
	 * @return int Days remaining, or 0 if not in grace period.
	 */
	public static function get_grace_days_remaining( $user_id ) {
		$settings = self::get_settings();

		if ( empty( $settings['grace_period_days'] ) ) {
			return 0;
		}

		$grace_start = (int) get_user_meta( $user_id, self::META_GRACE_START, true );
		if ( ! $grace_start ) {
			return 0;
		}

		$grace_end = $grace_start + ( $settings['grace_period_days'] * DAY_IN_SECONDS );
		$remaining = $grace_end - time();

		return $remaining > 0 ? (int) ceil( $remaining / DAY_IN_SECONDS ) : 0;
	}

	/**
	 * Start grace period for a user.
	 *
	 * @param int $user_id User ID.
	 * @return bool True on success.
	 */
	public static function start_grace_period( $user_id ) {
		// Only start if not already started and not already enrolled.
		if ( get_user_meta( $user_id, self::META_GRACE_START, true ) ) {
			return false;
		}

		if ( AtomicEdge_2FA::is_enabled_for_user( $user_id ) ) {
			return false;
		}

		update_user_meta( $user_id, self::META_GRACE_START, time() );
		AtomicEdge_2FA::log_event( $user_id, 'grace_period_started' );

		return true;
	}

	/**
	 * End grace period for a user (called when 2FA is enabled).
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public static function end_grace_period( $user_id ) {
		delete_user_meta( $user_id, self::META_GRACE_START );
		delete_user_meta( $user_id, self::META_NOTICE_DISMISSED );
	}

	/**
	 * Check if user should be blocked from login.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if user should be blocked.
	 */
	public static function should_block_login( $user_id ) {
		// Not required for this user.
		if ( ! self::is_required_for_user( $user_id ) ) {
			return false;
		}

		// Already has 2FA enabled.
		if ( AtomicEdge_2FA::is_enabled_for_user( $user_id ) ) {
			return false;
		}

		$settings = self::get_settings();

		// Grace bypass allowed and in grace period.
		if ( $settings['allow_grace_bypass'] && self::is_in_grace_period( $user_id ) ) {
			return false;
		}

		// If no grace period started yet, start it now.
		if ( ! get_user_meta( $user_id, self::META_GRACE_START, true ) ) {
			self::start_grace_period( $user_id );
			// Allow this login to proceed (first time).
			if ( $settings['allow_grace_bypass'] ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Get enforcement status for a user (for admin display).
	 *
	 * @param int $user_id User ID.
	 * @return array Status information.
	 */
	public static function get_user_enforcement_status( $user_id ) {
		$required    = self::is_required_for_user( $user_id );
		$has_2fa     = AtomicEdge_2FA::is_enabled_for_user( $user_id );
		$in_grace    = self::is_in_grace_period( $user_id );
		$grace_days  = self::get_grace_days_remaining( $user_id );
		$should_block = self::should_block_login( $user_id );

		return array(
			'required'         => $required,
			'has_2fa'          => $has_2fa,
			'compliant'        => ! $required || $has_2fa,
			'in_grace_period'  => $in_grace,
			'grace_days_left'  => $grace_days,
			'would_block'      => $should_block,
		);
	}

	/**
	 * Get all users who are required but not enrolled.
	 *
	 * @return array Array of user objects.
	 */
	public static function get_non_compliant_users() {
		$settings = self::get_settings();

		if ( empty( $settings['enabled'] ) || empty( $settings['enforced_roles'] ) ) {
			return array();
		}

		$users = get_users( array(
			'role__in' => $settings['enforced_roles'],
			'fields'   => 'all',
		) );

		$non_compliant = array();
		foreach ( $users as $user ) {
			if ( ! AtomicEdge_2FA::is_enabled_for_user( $user->ID ) ) {
				$user->grace_days_left = self::get_grace_days_remaining( $user->ID );
				$non_compliant[] = $user;
			}
		}

		return $non_compliant;
	}

	/**
	 * Dismiss enforcement reminder for user.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public static function dismiss_reminder( $user_id ) {
		update_user_meta( $user_id, self::META_NOTICE_DISMISSED, time() );
	}

	/**
	 * Check if reminder was recently dismissed.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if dismissed within last 24 hours.
	 */
	public static function is_reminder_dismissed( $user_id ) {
		$dismissed = (int) get_user_meta( $user_id, self::META_NOTICE_DISMISSED, true );
		if ( ! $dismissed ) {
			return false;
		}

		// Reset after 24 hours.
		return ( time() - $dismissed ) < DAY_IN_SECONDS;
	}

	/**
	 * Get available roles for enforcement selection.
	 *
	 * @return array Role slug => Role name.
	 */
	public static function get_available_roles() {
		$roles = wp_roles()->roles;
		$available = array();

		foreach ( $roles as $slug => $role ) {
			$available[ $slug ] = translate_user_role( $role['name'] );
		}

		return $available;
	}
}
