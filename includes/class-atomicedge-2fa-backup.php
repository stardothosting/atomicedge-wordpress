<?php
/**
 * AtomicEdge 2FA Backup Codes Provider
 *
 * Generates and manages single-use backup/recovery codes.
 *
 * @package AtomicEdge
 * @since   1.7.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_2FA_Backup
 *
 * Manages backup codes for 2FA recovery.
 */
class AtomicEdge_2FA_Backup {

	/**
	 * Number of backup codes to generate.
	 *
	 * @var int
	 */
	const CODE_COUNT = 8;

	/**
	 * Length of each code segment (format: XXXX-XXXX).
	 *
	 * @var int
	 */
	const SEGMENT_LENGTH = 4;

	/**
	 * Characters used in backup codes (alphanumeric, no confusing chars).
	 *
	 * @var string
	 */
	const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

	/**
	 * Generate a new set of backup codes.
	 *
	 * @return array {
	 *     @type array  $codes        Array of plaintext codes (show to user ONCE).
	 *     @type array  $hashed_codes Array of code data for storage.
	 * }
	 */
	public static function generate() {
		$codes        = array();
		$hashed_codes = array();

		for ( $i = 0; $i < self::CODE_COUNT; $i++ ) {
			$code = self::generate_single_code();

			$codes[] = $code;

			$hashed_codes[] = array(
				'hash'       => self::hash_code( $code ),
				'used'       => false,
				'created_at' => time(),
			);
		}

		return array(
			'codes'        => $codes,
			'hashed_codes' => $hashed_codes,
		);
	}

	/**
	 * Generate a single backup code.
	 *
	 * @return string Code in format XXXX-XXXX.
	 */
	private static function generate_single_code() {
		$chars  = self::CODE_CHARS;
		$length = strlen( $chars );

		$segment1 = '';
		$segment2 = '';

		for ( $i = 0; $i < self::SEGMENT_LENGTH; $i++ ) {
			$segment1 .= $chars[ random_int( 0, $length - 1 ) ];
			$segment2 .= $chars[ random_int( 0, $length - 1 ) ];
		}

		return $segment1 . '-' . $segment2;
	}

	/**
	 * Hash a backup code for storage.
	 *
	 * Uses WordPress's wp_hash for consistent hashing.
	 *
	 * @param string $code The plaintext code.
	 * @return string Hashed code.
	 */
	public static function hash_code( $code ) {
		// Normalize: uppercase, no spaces.
		$code = strtoupper( str_replace( array( '-', ' ' ), '', $code ) );
		return wp_hash( $code, 'nonce' );
	}

	/**
	 * Verify a backup code against stored hashes.
	 *
	 * @param string $code         The user-provided code.
	 * @param array  $hashed_codes Array of hashed code data.
	 * @return int|false Index of the matching code, or false if not found/already used.
	 */
	public static function verify( $code, $hashed_codes ) {
		if ( empty( $code ) || empty( $hashed_codes ) ) {
			return false;
		}

		$provided_hash = self::hash_code( $code );

		foreach ( $hashed_codes as $index => $code_data ) {
			// Skip already used codes.
			if ( ! empty( $code_data['used'] ) ) {
				continue;
			}

			if ( AtomicEdge_2FA_Crypto::hash_equals( $code_data['hash'], $provided_hash ) ) {
				return $index;
			}
		}

		return false;
	}

	/**
	 * Mark a backup code as used.
	 *
	 * @param array $hashed_codes Array of hashed code data.
	 * @param int   $index        Index of the code to mark as used.
	 * @return array Updated hashed codes array.
	 */
	public static function mark_used( $hashed_codes, $index ) {
		if ( isset( $hashed_codes[ $index ] ) ) {
			$hashed_codes[ $index ]['used']    = true;
			$hashed_codes[ $index ]['used_at'] = time();
		}
		return $hashed_codes;
	}

	/**
	 * Count remaining (unused) backup codes.
	 *
	 * @param array $hashed_codes Array of hashed code data.
	 * @return int Number of remaining codes.
	 */
	public static function count_remaining( $hashed_codes ) {
		if ( empty( $hashed_codes ) ) {
			return 0;
		}

		$remaining = 0;
		foreach ( $hashed_codes as $code_data ) {
			if ( empty( $code_data['used'] ) ) {
				$remaining++;
			}
		}

		return $remaining;
	}

	/**
	 * Format codes for display (downloadable text).
	 *
	 * @param array  $codes  Array of plaintext codes.
	 * @param string $site   Site name for the header.
	 * @param string $user   Username.
	 * @return string Formatted text content.
	 */
	public static function format_for_download( $codes, $site = '', $user = '' ) {
		if ( empty( $site ) ) {
			$site = get_bloginfo( 'name' );
		}

		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: Site name */
			__( '%s - Two-Factor Authentication Backup Codes', 'atomic-edge-security' ),
			$site
		);
		$lines[] = str_repeat( '-', 50 );

		if ( ! empty( $user ) ) {
			/* translators: %s: Username */
			$lines[] = sprintf( __( 'Account: %s', 'atomic-edge-security' ), $user );
		}

		/* translators: %s: Date */
		$lines[] = sprintf( __( 'Generated: %s', 'atomic-edge-security' ), wp_date( 'F j, Y g:i A' ) );
		$lines[] = '';
		$lines[] = __( 'Each code can only be used once. Store these codes in a safe place.', 'atomic-edge-security' );
		$lines[] = '';

		foreach ( $codes as $index => $code ) {
			$lines[] = sprintf( '%d. %s', $index + 1, $code );
		}

		$lines[] = '';
		$lines[] = __( 'IMPORTANT: These codes will not be shown again.', 'atomic-edge-security' );

		return implode( "\n", $lines );
	}
}
