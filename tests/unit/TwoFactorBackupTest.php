<?php
/**
 * AtomicEdge 2FA Backup Codes Class Tests
 *
 * Tests for the AtomicEdge_2FA_Backup class including code generation,
 * verification, and management.
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
 * 2FA Backup Codes Class Test Suite
 */
class TwoFactorBackupTest extends TestCase {

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		// Mock get_bloginfo for format tests.
		Functions\when( 'get_bloginfo' )->alias(
			function ( $show ) {
				return 'name' === $show ? 'Test Site' : '';
			}
		);

		// Mock wp_hash for backup code hashing.
		Functions\when( 'wp_hash' )->alias(
			function ( $data, $scheme = 'auth' ) {
				return hash_hmac( 'md5', $data, 'test_salt_' . $scheme );
			}
		);

		// Mock wp_date for format_for_download.
		Functions\when( 'wp_date' )->alias(
			function ( $format, $timestamp = null ) {
				return gmdate( $format, $timestamp ?? time() );
			}
		);

		// Mock translation function.
		Functions\when( '__' )->alias(
			function ( $text, $domain = 'default' ) {
				return $text;
			}
		);
	}

	// =========================================================================
	// Code Generation Tests
	// =========================================================================

	/**
	 * Test generate returns correct structure.
	 */
	public function test_generate_returns_correct_structure() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'codes', $result );
		$this->assertArrayHasKey( 'hashed_codes', $result );
	}

	/**
	 * Test generate returns 8 codes.
	 */
	public function test_generate_returns_correct_code_count() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$this->assertCount( 8, $result['codes'] );
		$this->assertCount( 8, $result['hashed_codes'] );
	}

	/**
	 * Test generated codes have correct format (XXXX-XXXX).
	 */
	public function test_generated_codes_have_correct_format() {
		$result = \AtomicEdge_2FA_Backup::generate();

		foreach ( $result['codes'] as $code ) {
			$this->assertMatchesRegularExpression(
				'/^[A-Z2-9]{4}-[A-Z2-9]{4}$/',
				$code,
				"Code '$code' does not match expected format"
			);
		}
	}

	/**
	 * Test generated codes are unique.
	 */
	public function test_generated_codes_are_unique() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$unique_codes = array_unique( $result['codes'] );
		$this->assertCount( 8, $unique_codes );
	}

	/**
	 * Test hashed codes have correct structure.
	 */
	public function test_hashed_codes_have_correct_structure() {
		$result = \AtomicEdge_2FA_Backup::generate();

		foreach ( $result['hashed_codes'] as $code_data ) {
			$this->assertArrayHasKey( 'hash', $code_data );
			$this->assertArrayHasKey( 'used', $code_data );
			$this->assertArrayHasKey( 'created_at', $code_data );
			$this->assertFalse( $code_data['used'] );
			$this->assertIsInt( $code_data['created_at'] );
		}
	}

	/**
	 * Test hashed codes differ from plaintext codes.
	 */
	public function test_hashed_codes_differ_from_plaintext() {
		$result = \AtomicEdge_2FA_Backup::generate();

		foreach ( $result['codes'] as $index => $code ) {
			$this->assertNotEquals(
				$code,
				$result['hashed_codes'][ $index ]['hash']
			);
		}
	}

	/**
	 * Test codes don't contain most confusing characters (O, 0, 1, I).
	 */
	public function test_codes_dont_contain_confusing_chars() {
		// Generate multiple times to ensure we get enough samples
		for ( $i = 0; $i < 10; $i++ ) {
			$result = \AtomicEdge_2FA_Backup::generate();

			foreach ( $result['codes'] as $code ) {
				// Remove dash for check
				$code_chars = str_replace( '-', '', $code );

				// Should not contain O, 0, 1, I (most confusing chars)
				// Note: L and K are kept as they're less commonly confused
				$this->assertStringNotContainsString( 'O', $code_chars );
				$this->assertStringNotContainsString( '0', $code_chars );
				$this->assertStringNotContainsString( '1', $code_chars );
				$this->assertStringNotContainsString( 'I', $code_chars );
			}
		}
	}

	// =========================================================================
	// Verification Tests
	// =========================================================================

	/**
	 * Test verify returns index for valid unused code.
	 */
	public function test_verify_returns_index_for_valid_code() {
		$result = \AtomicEdge_2FA_Backup::generate();

		// Verify the first code
		$index = \AtomicEdge_2FA_Backup::verify(
			$result['codes'][0],
			$result['hashed_codes']
		);

		$this->assertSame( 0, $index );
	}

	/**
	 * Test verify works for any code position.
	 */
	public function test_verify_works_for_any_code_position() {
		$result = \AtomicEdge_2FA_Backup::generate();

		// Verify the 5th code (index 4)
		$index = \AtomicEdge_2FA_Backup::verify(
			$result['codes'][4],
			$result['hashed_codes']
		);

		$this->assertSame( 4, $index );
	}

	/**
	 * Test verify returns false for invalid code.
	 */
	public function test_verify_returns_false_for_invalid_code() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$index = \AtomicEdge_2FA_Backup::verify(
			'INVALID-CODE',
			$result['hashed_codes']
		);

		$this->assertFalse( $index );
	}

	/**
	 * Test verify returns false for used code.
	 */
	public function test_verify_returns_false_for_used_code() {
		$result = \AtomicEdge_2FA_Backup::generate();

		// Mark first code as used
		$result['hashed_codes'][0]['used'] = true;

		$index = \AtomicEdge_2FA_Backup::verify(
			$result['codes'][0],
			$result['hashed_codes']
		);

		$this->assertFalse( $index );
	}

	/**
	 * Test verify handles lowercase input.
	 */
	public function test_verify_handles_lowercase_input() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$lowercase_code = strtolower( $result['codes'][0] );
		$index = \AtomicEdge_2FA_Backup::verify(
			$lowercase_code,
			$result['hashed_codes']
		);

		$this->assertSame( 0, $index );
	}

	/**
	 * Test verify handles code without dash.
	 */
	public function test_verify_handles_code_without_dash() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$code_without_dash = str_replace( '-', '', $result['codes'][0] );
		$index = \AtomicEdge_2FA_Backup::verify(
			$code_without_dash,
			$result['hashed_codes']
		);

		$this->assertSame( 0, $index );
	}

	/**
	 * Test verify handles code with spaces.
	 */
	public function test_verify_handles_code_with_spaces() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$code_with_spaces = str_replace( '-', ' ', $result['codes'][0] );
		$index = \AtomicEdge_2FA_Backup::verify(
			$code_with_spaces,
			$result['hashed_codes']
		);

		$this->assertSame( 0, $index );
	}

	/**
	 * Test verify returns false for empty code.
	 */
	public function test_verify_returns_false_for_empty_code() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$this->assertFalse( \AtomicEdge_2FA_Backup::verify( '', $result['hashed_codes'] ) );
	}

	/**
	 * Test verify returns false for empty hashed codes.
	 */
	public function test_verify_returns_false_for_empty_hashed_codes() {
		$this->assertFalse( \AtomicEdge_2FA_Backup::verify( 'ABCD-EFGH', array() ) );
	}

	// =========================================================================
	// Mark Used Tests
	// =========================================================================

	/**
	 * Test mark_used sets used flag.
	 */
	public function test_mark_used_sets_used_flag() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$updated = \AtomicEdge_2FA_Backup::mark_used( $result['hashed_codes'], 0 );

		$this->assertTrue( $updated[0]['used'] );
		$this->assertArrayHasKey( 'used_at', $updated[0] );
		$this->assertIsInt( $updated[0]['used_at'] );
	}

	/**
	 * Test mark_used only affects specified index.
	 */
	public function test_mark_used_only_affects_specified_index() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$updated = \AtomicEdge_2FA_Backup::mark_used( $result['hashed_codes'], 2 );

		// Only index 2 should be marked
		$this->assertFalse( $updated[0]['used'] );
		$this->assertFalse( $updated[1]['used'] );
		$this->assertTrue( $updated[2]['used'] );
		$this->assertFalse( $updated[3]['used'] );
	}

	/**
	 * Test mark_used handles invalid index gracefully.
	 */
	public function test_mark_used_handles_invalid_index() {
		$result = \AtomicEdge_2FA_Backup::generate();

		// Should not throw, just return unchanged
		$updated = \AtomicEdge_2FA_Backup::mark_used( $result['hashed_codes'], 99 );

		$this->assertCount( 8, $updated );
		foreach ( $updated as $code_data ) {
			$this->assertFalse( $code_data['used'] );
		}
	}

	// =========================================================================
	// Count Remaining Tests
	// =========================================================================

	/**
	 * Test count_remaining returns full count for new codes.
	 */
	public function test_count_remaining_returns_full_count() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$remaining = \AtomicEdge_2FA_Backup::count_remaining( $result['hashed_codes'] );

		$this->assertEquals( 8, $remaining );
	}

	/**
	 * Test count_remaining decreases after mark_used.
	 */
	public function test_count_remaining_decreases_after_mark_used() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$updated = \AtomicEdge_2FA_Backup::mark_used( $result['hashed_codes'], 0 );
		$remaining = \AtomicEdge_2FA_Backup::count_remaining( $updated );

		$this->assertEquals( 7, $remaining );
	}

	/**
	 * Test count_remaining returns zero when all used.
	 */
	public function test_count_remaining_returns_zero_when_all_used() {
		$result = \AtomicEdge_2FA_Backup::generate();

		// Mark all as used
		$updated = $result['hashed_codes'];
		for ( $i = 0; $i < 8; $i++ ) {
			$updated = \AtomicEdge_2FA_Backup::mark_used( $updated, $i );
		}

		$remaining = \AtomicEdge_2FA_Backup::count_remaining( $updated );

		$this->assertEquals( 0, $remaining );
	}

	/**
	 * Test count_remaining returns zero for empty array.
	 */
	public function test_count_remaining_returns_zero_for_empty_array() {
		$this->assertEquals( 0, \AtomicEdge_2FA_Backup::count_remaining( array() ) );
	}

	// =========================================================================
	// Format for Download Tests
	// =========================================================================

	/**
	 * Test format_for_download returns string.
	 */
	public function test_format_for_download_returns_string() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$formatted = \AtomicEdge_2FA_Backup::format_for_download( $result['codes'] );

		$this->assertIsString( $formatted );
		$this->assertNotEmpty( $formatted );
	}

	/**
	 * Test format_for_download includes site name.
	 */
	public function test_format_for_download_includes_site_name() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$formatted = \AtomicEdge_2FA_Backup::format_for_download(
			$result['codes'],
			'My Test Site'
		);

		$this->assertStringContainsString( 'My Test Site', $formatted );
	}

	/**
	 * Test format_for_download includes username.
	 */
	public function test_format_for_download_includes_username() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$formatted = \AtomicEdge_2FA_Backup::format_for_download(
			$result['codes'],
			'Test Site',
			'testuser'
		);

		$this->assertStringContainsString( 'testuser', $formatted );
	}

	/**
	 * Test format_for_download includes all codes.
	 */
	public function test_format_for_download_includes_all_codes() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$formatted = \AtomicEdge_2FA_Backup::format_for_download( $result['codes'] );

		foreach ( $result['codes'] as $code ) {
			$this->assertStringContainsString( $code, $formatted );
		}
	}

	/**
	 * Test format_for_download includes warning message.
	 */
	public function test_format_for_download_includes_warning() {
		$result = \AtomicEdge_2FA_Backup::generate();

		$formatted = \AtomicEdge_2FA_Backup::format_for_download( $result['codes'] );

		// Should include warning about single use
		$this->assertStringContainsString( 'once', strtolower( $formatted ) );
	}

	// =========================================================================
	// Hash Code Tests
	// =========================================================================

	/**
	 * Test hash_code returns consistent hash.
	 */
	public function test_hash_code_returns_consistent_hash() {
		$code = 'ABCD-EFGH';

		$hash1 = \AtomicEdge_2FA_Backup::hash_code( $code );
		$hash2 = \AtomicEdge_2FA_Backup::hash_code( $code );

		$this->assertEquals( $hash1, $hash2 );
	}

	/**
	 * Test hash_code normalizes input.
	 */
	public function test_hash_code_normalizes_input() {
		$hash1 = \AtomicEdge_2FA_Backup::hash_code( 'ABCD-EFGH' );
		$hash2 = \AtomicEdge_2FA_Backup::hash_code( 'abcd-efgh' );
		$hash3 = \AtomicEdge_2FA_Backup::hash_code( 'ABCDEFGH' );
		$hash4 = \AtomicEdge_2FA_Backup::hash_code( 'abcd efgh' );

		$this->assertEquals( $hash1, $hash2 );
		$this->assertEquals( $hash1, $hash3 );
		$this->assertEquals( $hash1, $hash4 );
	}

	/**
	 * Test hash_code produces different hashes for different codes.
	 */
	public function test_hash_code_produces_different_hashes() {
		$hash1 = \AtomicEdge_2FA_Backup::hash_code( 'ABCD-EFGH' );
		$hash2 = \AtomicEdge_2FA_Backup::hash_code( 'WXYZ-1234' );

		$this->assertNotEquals( $hash1, $hash2 );
	}
}
