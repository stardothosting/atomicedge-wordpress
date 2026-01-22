<?php
/**
 * AtomicEdge 2FA TOTP Provider
 *
 * Implements RFC 6238 Time-Based One-Time Password (TOTP) algorithm.
 * Pure PHP implementation with no external dependencies.
 *
 * @package AtomicEdge
 * @since   1.7.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_2FA_TOTP
 *
 * TOTP implementation compatible with Google Authenticator, Authy, etc.
 */
class AtomicEdge_2FA_TOTP {

	/**
	 * Secret key length in bytes (160 bits = 20 bytes).
	 *
	 * @var int
	 */
	const SECRET_BYTES = 20;

	/**
	 * Number of digits in the OTP.
	 *
	 * @var int
	 */
	const DIGIT_COUNT = 6;

	/**
	 * Time step in seconds.
	 *
	 * @var int
	 */
	const TIME_STEP = 30;

	/**
	 * Number of time steps to allow for clock drift (±1 = ±30 seconds).
	 *
	 * @var int
	 */
	const TIME_WINDOW = 1;

	/**
	 * Base32 alphabet for encoding/decoding.
	 *
	 * @var string
	 */
	const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a new random TOTP secret.
	 *
	 * @return string Base32-encoded secret.
	 */
	public static function generate_secret() {
		$secret = random_bytes( self::SECRET_BYTES );
		return self::base32_encode( $secret );
	}

	/**
	 * Get the provisioning URI for authenticator apps (QR code content).
	 *
	 * Format: otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER
	 *
	 * @param string $secret   Base32-encoded secret.
	 * @param string $account  User account identifier (e.g., username or email).
	 * @param string $issuer   Optional. Issuer name (defaults to site name).
	 * @return string The otpauth:// URI.
	 */
	public static function get_provisioning_uri( $secret, $account, $issuer = '' ) {
		if ( empty( $issuer ) ) {
			$issuer = get_bloginfo( 'name' );
		}

		// Sanitize for URI.
		$issuer  = rawurlencode( $issuer );
		$account = rawurlencode( $account );
		$secret  = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', $secret ) );

		// Format: otpauth://totp/Issuer:account?secret=SECRET&issuer=Issuer.
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d',
			$issuer,
			$account,
			$secret,
			$issuer,
			self::DIGIT_COUNT,
			self::TIME_STEP
		);
	}

	/**
	 * Verify a TOTP code.
	 *
	 * Allows for clock drift within the configured time window.
	 *
	 * @param string   $secret    Base32-encoded secret.
	 * @param string   $code      User-provided code to verify.
	 * @param int|null $timestamp Optional. Unix timestamp (defaults to current time).
	 * @return bool True if the code is valid.
	 */
	public static function verify( $secret, $code, $timestamp = null ) {
		if ( empty( $secret ) || empty( $code ) ) {
			return false;
		}

		// Normalize code: remove spaces and ensure correct length.
		$code = preg_replace( '/\s+/', '', $code );
		if ( strlen( $code ) !== self::DIGIT_COUNT ) {
			return false;
		}

		// Ensure code is numeric.
		if ( ! ctype_digit( $code ) ) {
			return false;
		}

		if ( null === $timestamp ) {
			$timestamp = time();
		}

		$current_timestep = self::get_timestep( $timestamp );

		// Check codes within the time window to account for clock drift.
		for ( $offset = -self::TIME_WINDOW; $offset <= self::TIME_WINDOW; $offset++ ) {
			$check_timestep = $current_timestep + $offset;
			$expected_code  = self::calculate_totp( $secret, $check_timestep );

			if ( AtomicEdge_2FA_Crypto::hash_equals( $expected_code, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get the current TOTP code (for display/testing).
	 *
	 * @param string   $secret    Base32-encoded secret.
	 * @param int|null $timestamp Optional. Unix timestamp.
	 * @return string The current TOTP code.
	 */
	public static function get_current_code( $secret, $timestamp = null ) {
		if ( null === $timestamp ) {
			$timestamp = time();
		}
		$timestep = self::get_timestep( $timestamp );
		return self::calculate_totp( $secret, $timestep );
	}

	/**
	 * Calculate the time step counter.
	 *
	 * @param int $timestamp Unix timestamp.
	 * @return int Time step counter.
	 */
	private static function get_timestep( $timestamp ) {
		return (int) floor( $timestamp / self::TIME_STEP );
	}

	/**
	 * Calculate TOTP for a given time step.
	 *
	 * Implements RFC 6238 TOTP and RFC 4226 HOTP algorithms.
	 *
	 * @param string $secret   Base32-encoded secret.
	 * @param int    $timestep Time step counter.
	 * @return string The TOTP code (zero-padded to DIGIT_COUNT).
	 */
	private static function calculate_totp( $secret, $timestep ) {
		// Decode the Base32 secret to binary.
		$key = self::base32_decode( $secret );
		if ( false === $key ) {
			return str_repeat( '0', self::DIGIT_COUNT );
		}

		// Pack the time step as a 64-bit big-endian unsigned integer.
		$time = pack( 'N*', 0, $timestep );

		// Calculate HMAC-SHA1.
		$hash = hash_hmac( 'sha1', $time, $key, true );

		// Dynamic truncation (RFC 4226).
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;

		$binary = (
			( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xff )
		);

		// Generate the OTP.
		$otp = $binary % pow( 10, self::DIGIT_COUNT );

		return str_pad( (string) $otp, self::DIGIT_COUNT, '0', STR_PAD_LEFT );
	}

	/**
	 * Encode binary data to Base32.
	 *
	 * @param string $data Binary data.
	 * @return string Base32-encoded string.
	 */
	public static function base32_encode( $data ) {
		$binary = '';
		foreach ( str_split( $data ) as $char ) {
			$binary .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}

		$encoded = '';
		$chunks  = str_split( $binary, 5 );

		foreach ( $chunks as $chunk ) {
			// Pad the last chunk if necessary.
			$chunk    = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$index    = bindec( $chunk );
			$encoded .= self::BASE32_CHARS[ $index ];
		}

		return $encoded;
	}

	/**
	 * Decode Base32 string to binary data.
	 *
	 * @param string $data Base32-encoded string.
	 * @return string|false Binary data, or false on invalid input.
	 */
	public static function base32_decode( $data ) {
		// Remove any whitespace and convert to uppercase.
		$data = strtoupper( preg_replace( '/\s+/', '', $data ) );

		// Remove padding characters.
		$data = rtrim( $data, '=' );

		if ( empty( $data ) ) {
			return false;
		}

		$binary = '';
		foreach ( str_split( $data ) as $char ) {
			$index = strpos( self::BASE32_CHARS, $char );
			if ( false === $index ) {
				return false; // Invalid character.
			}
			$binary .= str_pad( decbin( $index ), 5, '0', STR_PAD_LEFT );
		}

		$decoded = '';
		$chunks  = str_split( $binary, 8 );

		foreach ( $chunks as $chunk ) {
			if ( strlen( $chunk ) === 8 ) {
				$decoded .= chr( bindec( $chunk ) );
			}
		}

		return $decoded;
	}

	/**
	 * Get the remaining seconds until the current code expires.
	 *
	 * @param int|null $timestamp Optional. Unix timestamp.
	 * @return int Seconds remaining (0-29).
	 */
	public static function get_seconds_remaining( $timestamp = null ) {
		if ( null === $timestamp ) {
			$timestamp = time();
		}
		return self::TIME_STEP - ( $timestamp % self::TIME_STEP );
	}
}
