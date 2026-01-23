<?php
/**
 * AtomicEdge 2FA Crypto Class Tests
 *
 * Tests for the AtomicEdge_2FA_Crypto class including encryption,
 * decryption, and utility methods.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * 2FA Crypto Class Test Suite
 */
class TwoFactorCryptoTest extends TestCase {

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();
	}

	// =========================================================================
	// Availability Tests
	// =========================================================================

	/**
	 * Test is_available returns true when libsodium is present.
	 */
	public function test_is_available_returns_true() {
		// libsodium is bundled in PHP 7.2+
		$this->assertTrue( \AtomicEdge_2FA_Crypto::is_available() );
	}

	// =========================================================================
	// Encryption/Decryption Tests
	// =========================================================================

	/**
	 * Test encrypt returns a non-empty string.
	 */
	public function test_encrypt_returns_base64_string() {
		$plaintext = 'test_secret_data';
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $plaintext );

		$this->assertIsString( $encrypted );
		$this->assertNotEmpty( $encrypted );
		$this->assertNotEquals( $plaintext, $encrypted );
	}

	/**
	 * Test encrypted data differs from plaintext.
	 */
	public function test_encrypted_data_differs_from_plaintext() {
		$plaintext = 'JBSWY3DPEHPK3PXP';
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $plaintext );

		$this->assertNotEquals( $plaintext, $encrypted );
		// Should be base64 encoded
		$this->assertMatchesRegularExpression( '/^[A-Za-z0-9+\/=]+$/', $encrypted );
	}

	/**
	 * Test decrypt returns original plaintext.
	 */
	public function test_decrypt_returns_original_plaintext() {
		$plaintext = 'test_secret_totp_key_12345';
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $plaintext );
		$decrypted = \AtomicEdge_2FA_Crypto::decrypt( $encrypted );

		$this->assertEquals( $plaintext, $decrypted );
	}

	/**
	 * Test encryption/decryption roundtrip with various data.
	 *
	 * @dataProvider plaintext_data_provider
	 */
	public function test_encryption_decryption_roundtrip( $plaintext ) {
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $plaintext );
		$decrypted = \AtomicEdge_2FA_Crypto::decrypt( $encrypted );

		$this->assertEquals( $plaintext, $decrypted );
	}

	/**
	 * Data provider for roundtrip tests.
	 *
	 * @return array
	 */
	public function plaintext_data_provider() {
		return array(
			'short_string'    => array( 'ABC' ),
			'totp_secret'     => array( 'JBSWY3DPEHPK3PXP' ),
			'long_secret'     => array( 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' ),
			'with_spaces'     => array( 'secret with spaces' ),
			'special_chars'   => array( 'secret!@#$%^&*()' ),
			'unicode'         => array( 'secret_üñíçödé' ),
			'binary_safe'     => array( "\x00\x01\x02\x03" ),
		);
	}

	/**
	 * Test encrypt returns WP_Error for empty input.
	 */
	public function test_encrypt_returns_error_for_empty_input() {
		$result = \AtomicEdge_2FA_Crypto::encrypt( '' );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertEquals( 'empty_plaintext', $result->get_error_code() );
	}

	/**
	 * Test decrypt returns false for empty input.
	 */
	public function test_decrypt_returns_false_for_empty_input() {
		$this->assertFalse( \AtomicEdge_2FA_Crypto::decrypt( '' ) );
	}

	/**
	 * Test decrypt returns false for invalid base64.
	 */
	public function test_decrypt_returns_false_for_invalid_base64() {
		$this->assertFalse( \AtomicEdge_2FA_Crypto::decrypt( 'not-valid-base64!!!' ) );
	}

	/**
	 * Test decrypt returns false for tampered data.
	 */
	public function test_decrypt_returns_false_for_tampered_data() {
		$plaintext = 'original_secret';
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $plaintext );

		// Tamper with the encrypted data
		$decoded = base64_decode( $encrypted );
		$tampered = base64_encode( $decoded . 'tampered' );

		$this->assertFalse( \AtomicEdge_2FA_Crypto::decrypt( $tampered ) );
	}

	/**
	 * Test decrypt returns false for truncated data.
	 */
	public function test_decrypt_returns_false_for_truncated_data() {
		$plaintext = 'original_secret';
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $plaintext );

		// Truncate the encrypted data
		$truncated = substr( $encrypted, 0, 10 );

		$this->assertFalse( \AtomicEdge_2FA_Crypto::decrypt( $truncated ) );
	}

	/**
	 * Test multiple encryptions produce different ciphertexts (nonce is random).
	 */
	public function test_multiple_encryptions_produce_different_ciphertexts() {
		$plaintext = 'same_secret';

		$encrypted1 = \AtomicEdge_2FA_Crypto::encrypt( $plaintext );
		$encrypted2 = \AtomicEdge_2FA_Crypto::encrypt( $plaintext );

		$this->assertNotEquals( $encrypted1, $encrypted2 );

		// But both should decrypt to the same value
		$this->assertEquals( $plaintext, \AtomicEdge_2FA_Crypto::decrypt( $encrypted1 ) );
		$this->assertEquals( $plaintext, \AtomicEdge_2FA_Crypto::decrypt( $encrypted2 ) );
	}

	// =========================================================================
	// Random Hex Tests
	// =========================================================================

	/**
	 * Test random_hex returns correct length.
	 */
	public function test_random_hex_returns_correct_length() {
		$hex16 = \AtomicEdge_2FA_Crypto::random_hex( 16 );
		$hex32 = \AtomicEdge_2FA_Crypto::random_hex( 32 );

		// Hex encoding doubles the length
		$this->assertEquals( 32, strlen( $hex16 ) );
		$this->assertEquals( 64, strlen( $hex32 ) );
	}

	/**
	 * Test random_hex returns only hex characters.
	 */
	public function test_random_hex_returns_hex_characters() {
		$hex = \AtomicEdge_2FA_Crypto::random_hex( 32 );

		$this->assertMatchesRegularExpression( '/^[0-9a-f]+$/', $hex );
	}

	/**
	 * Test random_hex produces unique values.
	 */
	public function test_random_hex_produces_unique_values() {
		$values = array();
		for ( $i = 0; $i < 100; $i++ ) {
			$values[] = \AtomicEdge_2FA_Crypto::random_hex( 32 );
		}

		// All 100 values should be unique
		$this->assertCount( 100, array_unique( $values ) );
	}

	// =========================================================================
	// Hash Equals Tests
	// =========================================================================

	/**
	 * Test hash_equals returns true for identical strings.
	 */
	public function test_hash_equals_returns_true_for_identical_strings() {
		$this->assertTrue( \AtomicEdge_2FA_Crypto::hash_equals( 'abc123', 'abc123' ) );
	}

	/**
	 * Test hash_equals returns false for different strings.
	 */
	public function test_hash_equals_returns_false_for_different_strings() {
		$this->assertFalse( \AtomicEdge_2FA_Crypto::hash_equals( 'abc123', 'abc124' ) );
	}

	/**
	 * Test hash_equals returns false for different lengths.
	 */
	public function test_hash_equals_returns_false_for_different_lengths() {
		$this->assertFalse( \AtomicEdge_2FA_Crypto::hash_equals( 'abc', 'abcd' ) );
	}

	/**
	 * Test hash_equals with empty strings.
	 */
	public function test_hash_equals_with_empty_strings() {
		$this->assertTrue( \AtomicEdge_2FA_Crypto::hash_equals( '', '' ) );
		$this->assertFalse( \AtomicEdge_2FA_Crypto::hash_equals( '', 'a' ) );
	}
}
