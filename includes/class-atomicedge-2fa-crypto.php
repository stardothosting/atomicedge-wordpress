<?php
/**
 * AtomicEdge 2FA Cryptography Utilities
 *
 * Provides encryption/decryption for TOTP secrets using libsodium.
 *
 * @package AtomicEdge
 * @since   1.7.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_2FA_Crypto
 *
 * Handles encryption and decryption of sensitive 2FA data using libsodium.
 * Requires PHP 7.2+ (libsodium bundled) and WordPress 5.2+.
 */
class AtomicEdge_2FA_Crypto {

	/**
	 * Plugin-specific salt for key derivation.
	 *
	 * @var string
	 */
	const KEY_SALT = 'atomicedge_2fa_v1';

	/**
	 * Check if encryption is available.
	 *
	 * @return bool True if libsodium is available.
	 */
	public static function is_available() {
		return function_exists( 'sodium_crypto_secretbox' ) &&
			   function_exists( 'sodium_crypto_secretbox_open' ) &&
			   defined( 'SODIUM_CRYPTO_SECRETBOX_NONCEBYTES' ) &&
			   defined( 'SODIUM_CRYPTO_SECRETBOX_KEYBYTES' );
	}

	/**
	 * Encrypt plaintext data.
	 *
	 * Uses sodium_crypto_secretbox (XSalsa20-Poly1305).
	 *
	 * @param string $plaintext The data to encrypt.
	 * @return string|false Base64-encoded encrypted data, or false on failure.
	 */
	public static function encrypt( $plaintext ) {
		if ( ! self::is_available() ) {
			return false;
		}

		if ( empty( $plaintext ) ) {
			return false;
		}

		try {
			$key   = self::derive_key();
			$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

			$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, $key );

			// Prepend nonce to ciphertext for storage.
			$encrypted = $nonce . $ciphertext;

			// Clear sensitive data from memory.
			sodium_memzero( $key );
			sodium_memzero( $plaintext );

			return base64_encode( $encrypted );
		} catch ( Exception $e ) {
			return false;
		}
	}

	/**
	 * Decrypt encrypted data.
	 *
	 * @param string $encrypted Base64-encoded encrypted data.
	 * @return string|false Decrypted plaintext, or false on failure.
	 */
	public static function decrypt( $encrypted ) {
		if ( ! self::is_available() ) {
			return false;
		}

		if ( empty( $encrypted ) ) {
			return false;
		}

		try {
			$decoded = base64_decode( $encrypted, true );
			if ( false === $decoded ) {
				return false;
			}

			// Validate minimum length (nonce + auth tag).
			$min_length = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
			if ( strlen( $decoded ) < $min_length ) {
				return false;
			}

			$key        = self::derive_key();
			$nonce      = substr( $decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$ciphertext = substr( $decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

			$plaintext = sodium_crypto_secretbox_open( $ciphertext, $nonce, $key );

			// Clear sensitive data from memory.
			sodium_memzero( $key );

			return $plaintext;
		} catch ( Exception $e ) {
			return false;
		}
	}

	/**
	 * Derive encryption key from WordPress salts.
	 *
	 * Never use raw WordPress keys directly. Always derive a purpose-specific key.
	 *
	 * @return string 32-byte binary key for sodium_crypto_secretbox.
	 */
	private static function derive_key() {
		// Use WordPress authentication keys as the master secret.
		$master = '';

		if ( defined( 'AUTH_KEY' ) ) {
			$master .= AUTH_KEY;
		}
		if ( defined( 'SECURE_AUTH_KEY' ) ) {
			$master .= SECURE_AUTH_KEY;
		}

		// Fallback if keys are not defined (should never happen in production).
		if ( empty( $master ) ) {
			$master = 'atomicedge_fallback_key_' . get_site_url();
		}

		// Derive a 32-byte key using SHA-256.
		return hash( 'sha256', $master . self::KEY_SALT, true );
	}

	/**
	 * Generate a cryptographically secure random string.
	 *
	 * @param int $length Length of the string in bytes.
	 * @return string Hex-encoded random string.
	 */
	public static function random_hex( $length = 32 ) {
		return bin2hex( random_bytes( $length ) );
	}

	/**
	 * Constant-time string comparison to prevent timing attacks.
	 *
	 * @param string $known   The known string.
	 * @param string $unknown The user-provided string.
	 * @return bool True if strings are equal.
	 */
	public static function hash_equals( $known, $unknown ) {
		if ( function_exists( 'hash_equals' ) ) {
			return hash_equals( $known, $unknown );
		}

		// Fallback for older PHP (shouldn't be needed for WP 5.8+).
		$known_length = strlen( $known );
		if ( strlen( $unknown ) !== $known_length ) {
			return false;
		}

		$result = 0;
		for ( $i = 0; $i < $known_length; $i++ ) {
			$result |= ord( $known[ $i ] ) ^ ord( $unknown[ $i ] );
		}

		return 0 === $result;
	}
}
