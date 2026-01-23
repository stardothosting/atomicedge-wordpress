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
	 * Debug log helper - only logs when WP_DEBUG is true.
	 *
	 * @param string $message Log message.
	 * @return void
	 */
	private static function debug_log( $message ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'AtomicEdge 2FA Crypto: ' . $message );
		}
	}

	/**
	 * Check if encryption is available.
	 *
	 * @return bool True if libsodium is available.
	 */
	public static function is_available() {
		$has_secretbox      = function_exists( 'sodium_crypto_secretbox' );
		$has_secretbox_open = function_exists( 'sodium_crypto_secretbox_open' );
		$has_nonce_const    = defined( 'SODIUM_CRYPTO_SECRETBOX_NONCEBYTES' );
		$has_key_const      = defined( 'SODIUM_CRYPTO_SECRETBOX_KEYBYTES' );

		$available = $has_secretbox && $has_secretbox_open && $has_nonce_const && $has_key_const;

		if ( ! $available ) {
			self::debug_log( sprintf(
				'is_available check failed: secretbox=%s, secretbox_open=%s, nonce_const=%s, key_const=%s',
				$has_secretbox ? 'yes' : 'NO',
				$has_secretbox_open ? 'yes' : 'NO',
				$has_nonce_const ? 'yes' : 'NO',
				$has_key_const ? 'yes' : 'NO'
			) );
		}

		return $available;
	}

	/**
	 * Encrypt plaintext data.
	 *
	 * Uses sodium_crypto_secretbox (XSalsa20-Poly1305).
	 *
	 * @param string $plaintext The data to encrypt.
	 * @return string|\WP_Error Base64-encoded encrypted data, or WP_Error on failure.
	 */
	public static function encrypt( $plaintext ) {
		self::debug_log( 'encrypt() called, plaintext length: ' . strlen( $plaintext ) );

		if ( ! self::is_available() ) {
			self::debug_log( 'encrypt() failed: sodium not available' );
			return new \WP_Error( 'sodium_unavailable', 'libsodium functions not available' );
		}

		if ( empty( $plaintext ) ) {
			self::debug_log( 'encrypt() failed: empty plaintext' );
			return new \WP_Error( 'empty_plaintext', 'Empty data provided for encryption' );
		}

		try {
			self::debug_log( 'encrypt() deriving key...' );
			$key = self::derive_key();
			self::debug_log( 'encrypt() key derived, length: ' . strlen( $key ) );

			self::debug_log( 'encrypt() generating nonce...' );
			$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			self::debug_log( 'encrypt() nonce generated, length: ' . strlen( $nonce ) );

			self::debug_log( 'encrypt() calling sodium_crypto_secretbox...' );
			$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, $key );
			self::debug_log( 'encrypt() ciphertext generated, length: ' . strlen( $ciphertext ) );

			// Prepend nonce to ciphertext for storage.
			$encrypted = $nonce . $ciphertext;

			// Clear key from memory.
			sodium_memzero( $key );

			$result = base64_encode( $encrypted );
			self::debug_log( 'encrypt() success, result length: ' . strlen( $result ) );

			return $result;
		} catch ( \Exception $e ) {
			self::debug_log( 'encrypt() Exception: ' . $e->getMessage() );
			return new \WP_Error( 'encrypt_exception', 'Encryption error: ' . $e->getMessage() );
		} catch ( \Error $e ) {
			self::debug_log( 'encrypt() Error: ' . $e->getMessage() );
			return new \WP_Error( 'encrypt_error', 'Encryption fatal: ' . $e->getMessage() );
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
