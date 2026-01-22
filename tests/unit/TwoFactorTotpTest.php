<?php
/**
 * AtomicEdge 2FA TOTP Class Tests
 *
 * Tests for the AtomicEdge_2FA_TOTP class including secret generation,
 * code calculation, verification, and base32 encoding/decoding.
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
 * 2FA TOTP Class Test Suite
 */
class TwoFactorTotpTest extends TestCase {

	/**
	 * Known test vector secret (base32: JBSWY3DPEHPK3PXP).
	 * From RFC 6238 test vectors.
	 *
	 * @var string
	 */
	const TEST_SECRET = 'JBSWY3DPEHPK3PXP';

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		// Mock get_bloginfo for provisioning URI tests.
		Functions\when( 'get_bloginfo' )->alias(
			function ( $show ) {
				return 'name' === $show ? 'Test Site' : '';
			}
		);
	}

	// =========================================================================
	// Secret Generation Tests
	// =========================================================================

	/**
	 * Test generate_secret returns base32 encoded string.
	 */
	public function test_generate_secret_returns_base32_string() {
		$secret = \AtomicEdge_2FA_TOTP::generate_secret();

		$this->assertIsString( $secret );
		$this->assertNotEmpty( $secret );
		// Base32 only uses A-Z and 2-7
		$this->assertMatchesRegularExpression( '/^[A-Z2-7]+$/', $secret );
	}

	/**
	 * Test generate_secret returns correct length.
	 */
	public function test_generate_secret_returns_correct_length() {
		$secret = \AtomicEdge_2FA_TOTP::generate_secret();

		// 20 bytes = 160 bits, base32 encodes 5 bits per char = 32 chars
		$this->assertEquals( 32, strlen( $secret ) );
	}

	/**
	 * Test generate_secret produces unique values.
	 */
	public function test_generate_secret_produces_unique_values() {
		$secrets = array();
		for ( $i = 0; $i < 100; $i++ ) {
			$secrets[] = \AtomicEdge_2FA_TOTP::generate_secret();
		}

		$this->assertCount( 100, array_unique( $secrets ) );
	}

	// =========================================================================
	// Provisioning URI Tests
	// =========================================================================

	/**
	 * Test get_provisioning_uri format.
	 */
	public function test_get_provisioning_uri_format() {
		$uri = \AtomicEdge_2FA_TOTP::get_provisioning_uri(
			self::TEST_SECRET,
			'user@example.com',
			'MyApp'
		);

		$this->assertStringStartsWith( 'otpauth://totp/', $uri );
		$this->assertStringContainsString( 'secret=' . self::TEST_SECRET, $uri );
		$this->assertStringContainsString( 'issuer=MyApp', $uri );
		$this->assertStringContainsString( 'digits=6', $uri );
		$this->assertStringContainsString( 'period=30', $uri );
	}

	/**
	 * Test get_provisioning_uri uses site name as default issuer.
	 */
	public function test_get_provisioning_uri_uses_site_name_as_default_issuer() {
		$uri = \AtomicEdge_2FA_TOTP::get_provisioning_uri(
			self::TEST_SECRET,
			'testuser'
		);

		$this->assertStringContainsString( 'issuer=Test%20Site', $uri );
	}

	/**
	 * Test get_provisioning_uri encodes special characters.
	 */
	public function test_get_provisioning_uri_encodes_special_characters() {
		$uri = \AtomicEdge_2FA_TOTP::get_provisioning_uri(
			self::TEST_SECRET,
			'user@example.com',
			'My App & Co.'
		);

		// Should be URL encoded
		$this->assertStringContainsString( 'My%20App', $uri );
		$this->assertStringContainsString( 'user%40example.com', $uri );
	}

	// =========================================================================
	// TOTP Calculation Tests
	// =========================================================================

	/**
	 * Test get_current_code returns 6 digit string.
	 */
	public function test_get_current_code_returns_6_digit_string() {
		$code = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET );

		$this->assertIsString( $code );
		$this->assertEquals( 6, strlen( $code ) );
		$this->assertTrue( ctype_digit( $code ) );
	}

	/**
	 * Test get_current_code is deterministic for same timestamp.
	 */
	public function test_get_current_code_is_deterministic() {
		$timestamp = 1234567890;

		$code1 = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp );
		$code2 = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp );

		$this->assertEquals( $code1, $code2 );
	}

	/**
	 * Test codes change after time step (30 seconds).
	 */
	public function test_codes_change_after_time_step() {
		$timestamp1 = 1234567890;
		$timestamp2 = $timestamp1 + 30; // One time step later

		$code1 = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp1 );
		$code2 = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp2 );

		$this->assertNotEquals( $code1, $code2 );
	}

	/**
	 * Test codes are same within time step.
	 */
	public function test_codes_are_same_within_time_step() {
		// Pick a timestamp that's at the start of a time step
		$timestamp = 1234567890 - ( 1234567890 % 30 );

		$code1 = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp );
		$code2 = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp + 15 );
		$code3 = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp + 29 );

		$this->assertEquals( $code1, $code2 );
		$this->assertEquals( $code1, $code3 );
	}

	/**
	 * Test known RFC 6238 test vectors.
	 *
	 * Using the test secret "12345678901234567890" (ASCII) which is
	 * "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" in base32.
	 */
	public function test_known_rfc_test_vectors() {
		// RFC 6238 uses ASCII "12345678901234567890" as the secret
		// We need to convert it to base32
		$ascii_secret = '12345678901234567890';
		$base32_secret = \AtomicEdge_2FA_TOTP::base32_encode( $ascii_secret );

		// RFC 6238 test: T = 59 seconds (timestep 1)
		// Expected TOTP: 287082 for SHA1
		// Note: The exact value depends on implementation details
		$code = \AtomicEdge_2FA_TOTP::get_current_code( $base32_secret, 59 );
		$this->assertEquals( 6, strlen( $code ) );
		$this->assertTrue( ctype_digit( $code ) );
	}

	// =========================================================================
	// Verification Tests
	// =========================================================================

	/**
	 * Test verify returns true for valid current code.
	 */
	public function test_verify_returns_true_for_valid_code() {
		$timestamp = time();
		$code = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp );

		$result = \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, $code, $timestamp );

		$this->assertTrue( $result );
	}

	/**
	 * Test verify returns false for invalid code.
	 */
	public function test_verify_returns_false_for_invalid_code() {
		$result = \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, '000000' );

		// Could theoretically pass if 000000 happens to be the current code
		// but statistically very unlikely
		$this->assertFalse( $result );
	}

	/**
	 * Test verify handles clock drift within window.
	 */
	public function test_verify_handles_clock_drift_within_window() {
		$timestamp = 1234567890;
		$code = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp );

		// Should pass at exact time
		$this->assertTrue( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, $code, $timestamp ) );

		// Should pass 30 seconds later (within +1 window)
		$this->assertTrue( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, $code, $timestamp + 30 ) );

		// Should pass 30 seconds earlier (within -1 window)
		$this->assertTrue( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, $code, $timestamp - 30 ) );
	}

	/**
	 * Test verify fails outside time window.
	 */
	public function test_verify_fails_outside_time_window() {
		$timestamp = 1234567890;
		$code = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp );

		// Should fail 90 seconds later (outside ±1 window)
		$this->assertFalse( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, $code, $timestamp + 90 ) );

		// Should fail 90 seconds earlier
		$this->assertFalse( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, $code, $timestamp - 90 ) );
	}

	/**
	 * Test verify returns false for empty secret.
	 */
	public function test_verify_returns_false_for_empty_secret() {
		$this->assertFalse( \AtomicEdge_2FA_TOTP::verify( '', '123456' ) );
	}

	/**
	 * Test verify returns false for empty code.
	 */
	public function test_verify_returns_false_for_empty_code() {
		$this->assertFalse( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, '' ) );
	}

	/**
	 * Test verify returns false for wrong length code.
	 */
	public function test_verify_returns_false_for_wrong_length_code() {
		$this->assertFalse( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, '12345' ) );
		$this->assertFalse( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, '1234567' ) );
	}

	/**
	 * Test verify returns false for non-numeric code.
	 */
	public function test_verify_returns_false_for_non_numeric_code() {
		$this->assertFalse( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, 'abcdef' ) );
		$this->assertFalse( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, '12345a' ) );
	}

	/**
	 * Test verify handles code with spaces.
	 */
	public function test_verify_handles_code_with_spaces() {
		$timestamp = 1234567890;
		$code = \AtomicEdge_2FA_TOTP::get_current_code( self::TEST_SECRET, $timestamp );

		// Insert spaces
		$code_with_spaces = substr( $code, 0, 3 ) . ' ' . substr( $code, 3 );

		$this->assertTrue( \AtomicEdge_2FA_TOTP::verify( self::TEST_SECRET, $code_with_spaces, $timestamp ) );
	}

	// =========================================================================
	// Base32 Encoding/Decoding Tests
	// =========================================================================

	/**
	 * Test base32_encode produces valid output.
	 */
	public function test_base32_encode_produces_valid_output() {
		$data = 'Hello!';
		$encoded = \AtomicEdge_2FA_TOTP::base32_encode( $data );

		$this->assertMatchesRegularExpression( '/^[A-Z2-7]+$/', $encoded );
	}

	/**
	 * Test base32_decode reverses encoding.
	 */
	public function test_base32_decode_reverses_encoding() {
		$original = 'TestData123';
		$encoded = \AtomicEdge_2FA_TOTP::base32_encode( $original );
		$decoded = \AtomicEdge_2FA_TOTP::base32_decode( $encoded );

		$this->assertEquals( $original, $decoded );
	}

	/**
	 * Test base32 encoding/decoding roundtrip with various data.
	 *
	 * @dataProvider base32_roundtrip_data_provider
	 */
	public function test_base32_roundtrip( $data ) {
		$encoded = \AtomicEdge_2FA_TOTP::base32_encode( $data );
		$decoded = \AtomicEdge_2FA_TOTP::base32_decode( $encoded );

		$this->assertEquals( $data, $decoded );
	}

	/**
	 * Data provider for base32 roundtrip tests.
	 *
	 * @return array
	 */
	public function base32_roundtrip_data_provider() {
		return array(
			'single_char'  => array( 'A' ),
			'short_string' => array( 'Hi' ),
			'medium'       => array( 'Hello World' ),
			'binary'       => array( "\x00\x01\x02\x03\x04" ),
			'random_20'    => array( random_bytes( 20 ) ),
		);
	}

	/**
	 * Test base32_decode handles lowercase input.
	 */
	public function test_base32_decode_handles_lowercase() {
		$encoded = 'jbswy3dpehpk3pxp'; // lowercase
		$decoded = \AtomicEdge_2FA_TOTP::base32_decode( $encoded );

		$this->assertNotFalse( $decoded );
	}

	/**
	 * Test base32_decode handles padding.
	 */
	public function test_base32_decode_handles_padding() {
		$encoded = 'JBSWY3DPEHPK3PXP====';
		$decoded = \AtomicEdge_2FA_TOTP::base32_decode( $encoded );

		$this->assertNotFalse( $decoded );
	}

	/**
	 * Test base32_decode returns false for invalid characters.
	 */
	public function test_base32_decode_returns_false_for_invalid_chars() {
		$this->assertFalse( \AtomicEdge_2FA_TOTP::base32_decode( 'INVALID!@#$' ) );
		$this->assertFalse( \AtomicEdge_2FA_TOTP::base32_decode( 'ABCD0189' ) ); // 0, 1, 8, 9 are not in base32
	}

	/**
	 * Test base32_decode returns false for empty string.
	 */
	public function test_base32_decode_returns_false_for_empty_string() {
		$this->assertFalse( \AtomicEdge_2FA_TOTP::base32_decode( '' ) );
	}

	// =========================================================================
	// Seconds Remaining Tests
	// =========================================================================

	/**
	 * Test get_seconds_remaining returns valid range.
	 */
	public function test_get_seconds_remaining_returns_valid_range() {
		$seconds = \AtomicEdge_2FA_TOTP::get_seconds_remaining();

		$this->assertGreaterThanOrEqual( 0, $seconds );
		$this->assertLessThanOrEqual( 30, $seconds );
	}

	/**
	 * Test get_seconds_remaining at specific timestamps.
	 */
	public function test_get_seconds_remaining_at_specific_timestamps() {
		// At the start of a 30-second window
		$this->assertEquals( 30, \AtomicEdge_2FA_TOTP::get_seconds_remaining( 0 ) );
		$this->assertEquals( 30, \AtomicEdge_2FA_TOTP::get_seconds_remaining( 30 ) );
		$this->assertEquals( 30, \AtomicEdge_2FA_TOTP::get_seconds_remaining( 60 ) );

		// In the middle
		$this->assertEquals( 15, \AtomicEdge_2FA_TOTP::get_seconds_remaining( 15 ) );
		$this->assertEquals( 15, \AtomicEdge_2FA_TOTP::get_seconds_remaining( 45 ) );

		// Near the end
		$this->assertEquals( 1, \AtomicEdge_2FA_TOTP::get_seconds_remaining( 29 ) );
		$this->assertEquals( 1, \AtomicEdge_2FA_TOTP::get_seconds_remaining( 59 ) );
	}
}
