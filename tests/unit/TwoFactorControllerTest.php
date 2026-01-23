<?php
/**
 * AtomicEdge 2FA Main Controller Tests
 *
 * Tests for the AtomicEdge_2FA class including enrollment, verification,
 * rate limiting, and user management.
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
 * 2FA Main Controller Test Suite
 */
class TwoFactorControllerTest extends TestCase {

	/**
	 * Test user ID.
	 *
	 * @var int
	 */
	private $test_user_id = 123;

	/**
	 * User meta storage for tests.
	 *
	 * @var array
	 */
	private $user_meta = array();

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		$this->user_meta = array();

		// Mock get_userdata.
		Functions\when( 'get_userdata' )->alias(
			function ( $user_id ) {
				if ( $user_id === $this->test_user_id ) {
					return (object) array(
						'ID'         => $user_id,
						'user_login' => 'testuser',
						'user_email' => 'test@example.com',
					);
				}
				return false;
			}
		);

		// Mock get_user_meta.
		Functions\when( 'get_user_meta' )->alias(
			function ( $user_id, $key, $single = false ) {
				$full_key = $user_id . '_' . $key;
				if ( ! isset( $this->user_meta[ $full_key ] ) ) {
					return $single ? '' : array();
				}
				return $single ? $this->user_meta[ $full_key ] : array( $this->user_meta[ $full_key ] );
			}
		);

		// Mock update_user_meta.
		Functions\when( 'update_user_meta' )->alias(
			function ( $user_id, $key, $value ) {
				$this->user_meta[ $user_id . '_' . $key ] = $value;
				return true;
			}
		);

		// Mock delete_user_meta.
		Functions\when( 'delete_user_meta' )->alias(
			function ( $user_id, $key ) {
				unset( $this->user_meta[ $user_id . '_' . $key ] );
				return true;
			}
		);

		// Mock get_bloginfo.
		Functions\when( 'get_bloginfo' )->alias(
			function ( $show ) {
				return 'name' === $show ? 'Test Site' : '';
			}
		);

		// Mock wp_hash.
		Functions\when( 'wp_hash' )->alias(
			function ( $data, $scheme = 'auth' ) {
				return hash_hmac( 'md5', $data, 'test_salt_' . $scheme );
			}
		);

		// Mock wp_date.
		Functions\when( 'wp_date' )->alias(
			function ( $format, $timestamp = null ) {
				return gmdate( $format, $timestamp ?? time() );
			}
		);

		// Mock translation.
		Functions\when( '__' )->alias(
			function ( $text, $domain = 'default' ) {
				return $text;
			}
		);
	}

	// =========================================================================
	// Enabled Status Tests
	// =========================================================================

	/**
	 * Test is_enabled_for_user returns false when not set.
	 */
	public function test_is_enabled_returns_false_when_not_set() {
		$this->assertFalse( \AtomicEdge_2FA::is_enabled_for_user( $this->test_user_id ) );
	}

	/**
	 * Test is_enabled_for_user returns true when enabled.
	 */
	public function test_is_enabled_returns_true_when_enabled() {
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_ENABLED ] = '1';

		$this->assertTrue( \AtomicEdge_2FA::is_enabled_for_user( $this->test_user_id ) );
	}

	// =========================================================================
	// Enrollment Tests
	// =========================================================================

	/**
	 * Test start_enrollment returns secret and URI.
	 */
	public function test_start_enrollment_returns_secret_and_uri() {
		$result = \AtomicEdge_2FA::start_enrollment( $this->test_user_id );

		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'secret', $result );
		$this->assertArrayHasKey( 'provisioning_uri', $result );
		$this->assertNotEmpty( $result['secret'] );
		$this->assertStringStartsWith( 'otpauth://totp/', $result['provisioning_uri'] );
	}

	/**
	 * Test start_enrollment stores pending secret.
	 */
	public function test_start_enrollment_stores_pending_secret() {
		\AtomicEdge_2FA::start_enrollment( $this->test_user_id );

		$pending_key = $this->test_user_id . '_' . \AtomicEdge_2FA::META_PENDING_SECRET;
		$this->assertArrayHasKey( $pending_key, $this->user_meta );
		$this->assertNotEmpty( $this->user_meta[ $pending_key ] );
	}

	/**
	 * Test start_enrollment returns WP_Error for invalid user.
	 */
	public function test_start_enrollment_returns_error_for_invalid_user() {
		$result = \AtomicEdge_2FA::start_enrollment( 99999 );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertEquals( 'invalid_user', $result->get_error_code() );
	}

	/**
	 * Test complete_enrollment enables 2FA with valid code.
	 */
	public function test_complete_enrollment_enables_2fa() {
		// Start enrollment
		$enrollment = \AtomicEdge_2FA::start_enrollment( $this->test_user_id );

		// Get a valid code for the pending secret
		$code = \AtomicEdge_2FA_TOTP::get_current_code( $enrollment['secret'] );

		// Complete enrollment
		$result = \AtomicEdge_2FA::complete_enrollment( $this->test_user_id, $code );

		$this->assertTrue( $result['success'] );
		$this->assertArrayHasKey( 'backup_codes', $result );
		$this->assertCount( 8, $result['backup_codes'] );
		$this->assertTrue( \AtomicEdge_2FA::is_enabled_for_user( $this->test_user_id ) );
	}

	/**
	 * Test complete_enrollment fails with invalid code.
	 */
	public function test_complete_enrollment_fails_with_invalid_code() {
		\AtomicEdge_2FA::start_enrollment( $this->test_user_id );

		$result = \AtomicEdge_2FA::complete_enrollment( $this->test_user_id, '000000' );

		$this->assertFalse( $result['success'] );
		$this->assertArrayHasKey( 'error', $result );
		$this->assertFalse( \AtomicEdge_2FA::is_enabled_for_user( $this->test_user_id ) );
	}

	/**
	 * Test complete_enrollment fails without pending enrollment.
	 */
	public function test_complete_enrollment_fails_without_pending() {
		$result = \AtomicEdge_2FA::complete_enrollment( $this->test_user_id, '123456' );

		$this->assertFalse( $result['success'] );
		$this->assertStringContainsString( 'pending', strtolower( $result['error'] ) );
	}

	/**
	 * Test complete_enrollment clears pending secret.
	 */
	public function test_complete_enrollment_clears_pending_secret() {
		$enrollment = \AtomicEdge_2FA::start_enrollment( $this->test_user_id );
		$code = \AtomicEdge_2FA_TOTP::get_current_code( $enrollment['secret'] );

		\AtomicEdge_2FA::complete_enrollment( $this->test_user_id, $code );

		$pending_key = $this->test_user_id . '_' . \AtomicEdge_2FA::META_PENDING_SECRET;
		$this->assertArrayNotHasKey( $pending_key, $this->user_meta );
	}

	/**
	 * Test cancel_enrollment clears pending secret.
	 */
	public function test_cancel_enrollment_clears_pending() {
		\AtomicEdge_2FA::start_enrollment( $this->test_user_id );

		\AtomicEdge_2FA::cancel_enrollment( $this->test_user_id );

		$pending_key = $this->test_user_id . '_' . \AtomicEdge_2FA::META_PENDING_SECRET;
		$this->assertArrayNotHasKey( $pending_key, $this->user_meta );
	}

	// =========================================================================
	// Disable Tests
	// =========================================================================

	/**
	 * Test disable removes all 2FA data.
	 */
	public function test_disable_removes_all_2fa_data() {
		// Set up enabled 2FA
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_ENABLED ] = '1';
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_TOTP_SECRET ] = 'encrypted_secret';
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_BACKUP_CODES ] = array();

		$result = \AtomicEdge_2FA::disable( $this->test_user_id );

		$this->assertTrue( $result );
		$this->assertFalse( \AtomicEdge_2FA::is_enabled_for_user( $this->test_user_id ) );
		$this->assertArrayNotHasKey(
			$this->test_user_id . '_' . \AtomicEdge_2FA::META_TOTP_SECRET,
			$this->user_meta
		);
	}

	// =========================================================================
	// TOTP Verification Tests
	// =========================================================================

	/**
	 * Test verify_totp returns true for valid code.
	 */
	public function test_verify_totp_returns_true_for_valid_code() {
		// Set up user with 2FA
		$secret = \AtomicEdge_2FA_TOTP::generate_secret();
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $secret );
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_TOTP_SECRET ] = $encrypted;

		$code = \AtomicEdge_2FA_TOTP::get_current_code( $secret );

		$this->assertTrue( \AtomicEdge_2FA::verify_totp( $this->test_user_id, $code ) );
	}

	/**
	 * Test verify_totp returns false for invalid code.
	 */
	public function test_verify_totp_returns_false_for_invalid_code() {
		$secret = \AtomicEdge_2FA_TOTP::generate_secret();
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $secret );
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_TOTP_SECRET ] = $encrypted;

		$this->assertFalse( \AtomicEdge_2FA::verify_totp( $this->test_user_id, '000000' ) );
	}

	/**
	 * Test verify_totp returns false when no secret stored.
	 */
	public function test_verify_totp_returns_false_without_secret() {
		$this->assertFalse( \AtomicEdge_2FA::verify_totp( $this->test_user_id, '123456' ) );
	}

	// =========================================================================
	// Backup Code Verification Tests
	// =========================================================================

	/**
	 * Test verify_backup_code returns true for valid code.
	 */
	public function test_verify_backup_code_returns_true_for_valid() {
		$backup = \AtomicEdge_2FA_Backup::generate();
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_BACKUP_CODES ] = $backup['hashed_codes'];

		$this->assertTrue( \AtomicEdge_2FA::verify_backup_code( $this->test_user_id, $backup['codes'][0] ) );
	}

	/**
	 * Test verify_backup_code marks code as used.
	 */
	public function test_verify_backup_code_marks_as_used() {
		$backup = \AtomicEdge_2FA_Backup::generate();
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_BACKUP_CODES ] = $backup['hashed_codes'];

		\AtomicEdge_2FA::verify_backup_code( $this->test_user_id, $backup['codes'][0] );

		// Try to use same code again
		$this->assertFalse( \AtomicEdge_2FA::verify_backup_code( $this->test_user_id, $backup['codes'][0] ) );
	}

	/**
	 * Test verify_backup_code returns false for invalid code.
	 */
	public function test_verify_backup_code_returns_false_for_invalid() {
		$backup = \AtomicEdge_2FA_Backup::generate();
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_BACKUP_CODES ] = $backup['hashed_codes'];

		$this->assertFalse( \AtomicEdge_2FA::verify_backup_code( $this->test_user_id, 'INVA-LIDD' ) );
	}

	// =========================================================================
	// Rate Limiting Tests
	// =========================================================================

	/**
	 * Test is_rate_limited returns false initially.
	 */
	public function test_is_rate_limited_returns_false_initially() {
		$this->assertFalse( \AtomicEdge_2FA::is_rate_limited( $this->test_user_id ) );
	}

	/**
	 * Test rate limiting after 3 failures.
	 */
	public function test_rate_limiting_after_3_failures() {
		for ( $i = 0; $i < 3; $i++ ) {
			\AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );
		}

		$lockout = \AtomicEdge_2FA::is_rate_limited( $this->test_user_id );

		$this->assertIsInt( $lockout );
		$this->assertLessThanOrEqual( 60, $lockout ); // 1 minute lockout
	}

	/**
	 * Test rate limiting after 5 failures.
	 */
	public function test_rate_limiting_after_5_failures() {
		for ( $i = 0; $i < 5; $i++ ) {
			\AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );
		}

		$lockout = \AtomicEdge_2FA::is_rate_limited( $this->test_user_id );

		$this->assertIsInt( $lockout );
		$this->assertLessThanOrEqual( 900, $lockout ); // 15 minute lockout
	}

	/**
	 * Test rate limiting after 10 failures.
	 */
	public function test_rate_limiting_after_10_failures() {
		for ( $i = 0; $i < 10; $i++ ) {
			\AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );
		}

		$lockout = \AtomicEdge_2FA::is_rate_limited( $this->test_user_id );

		$this->assertIsInt( $lockout );
		$this->assertLessThanOrEqual( 3600, $lockout ); // 1 hour lockout
	}

	/**
	 * Test reset_rate_limit clears lockout.
	 */
	public function test_reset_rate_limit_clears_lockout() {
		for ( $i = 0; $i < 5; $i++ ) {
			\AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );
		}

		\AtomicEdge_2FA::reset_rate_limit( $this->test_user_id );

		$this->assertFalse( \AtomicEdge_2FA::is_rate_limited( $this->test_user_id ) );
	}

	/**
	 * Test record_success resets rate limit.
	 */
	public function test_record_success_resets_rate_limit() {
		for ( $i = 0; $i < 3; $i++ ) {
			\AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );
		}

		\AtomicEdge_2FA::record_success( $this->test_user_id );

		$this->assertFalse( \AtomicEdge_2FA::is_rate_limited( $this->test_user_id ) );
	}

	// =========================================================================
	// Backup Code Regeneration Tests
	// =========================================================================

	/**
	 * Test regenerate_backup_codes returns new codes.
	 */
	public function test_regenerate_backup_codes_returns_new_codes() {
		// Enable 2FA first
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_ENABLED ] = '1';
		$backup = \AtomicEdge_2FA_Backup::generate();
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_BACKUP_CODES ] = $backup['hashed_codes'];

		$new_codes = \AtomicEdge_2FA::regenerate_backup_codes( $this->test_user_id );

		$this->assertIsArray( $new_codes );
		$this->assertCount( 8, $new_codes );
		// New codes should be different
		$this->assertNotEquals( $backup['codes'], $new_codes );
	}

	/**
	 * Test regenerate_backup_codes fails when not enabled.
	 */
	public function test_regenerate_backup_codes_fails_when_not_enabled() {
		$this->assertFalse( \AtomicEdge_2FA::regenerate_backup_codes( $this->test_user_id ) );
	}

	// =========================================================================
	// User Status Tests
	// =========================================================================

	/**
	 * Test get_user_status returns expected structure.
	 */
	public function test_get_user_status_returns_expected_structure() {
		$status = \AtomicEdge_2FA::get_user_status( $this->test_user_id );

		$this->assertIsArray( $status );
		$this->assertArrayHasKey( 'enabled', $status );
		$this->assertArrayHasKey( 'setup_date', $status );
		$this->assertArrayHasKey( 'last_used', $status );
		$this->assertArrayHasKey( 'codes_remaining', $status );
		$this->assertArrayHasKey( 'codes_total', $status );
	}

	/**
	 * Test get_user_status reflects enabled state.
	 */
	public function test_get_user_status_reflects_enabled_state() {
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_ENABLED ] = '1';

		$status = \AtomicEdge_2FA::get_user_status( $this->test_user_id );

		$this->assertTrue( $status['enabled'] );
	}

	/**
	 * Test get_user_status counts remaining codes.
	 */
	public function test_get_user_status_counts_remaining_codes() {
		$backup = \AtomicEdge_2FA_Backup::generate();
		// Mark 3 codes as used
		$backup['hashed_codes'][0]['used'] = true;
		$backup['hashed_codes'][1]['used'] = true;
		$backup['hashed_codes'][2]['used'] = true;
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_BACKUP_CODES ] = $backup['hashed_codes'];

		$status = \AtomicEdge_2FA::get_user_status( $this->test_user_id );

		$this->assertEquals( 5, $status['codes_remaining'] );
		$this->assertEquals( 8, $status['codes_total'] );
	}

	// =========================================================================
	// Login Nonce Tests
	// =========================================================================

	/**
	 * Test create_login_nonce returns key and expiration.
	 */
	public function test_create_login_nonce_returns_key_and_expiration() {
		$nonce = \AtomicEdge_2FA::create_login_nonce( $this->test_user_id );

		$this->assertIsArray( $nonce );
		$this->assertArrayHasKey( 'key', $nonce );
		$this->assertArrayHasKey( 'expiration', $nonce );
		$this->assertNotEmpty( $nonce['key'] );
		$this->assertGreaterThan( time(), $nonce['expiration'] );
	}

	/**
	 * Test verify_login_nonce returns true for valid nonce.
	 */
	public function test_verify_login_nonce_returns_true_for_valid() {
		$nonce = \AtomicEdge_2FA::create_login_nonce( $this->test_user_id );

		$this->assertTrue( \AtomicEdge_2FA::verify_login_nonce( $this->test_user_id, $nonce['key'] ) );
	}

	/**
	 * Test verify_login_nonce returns false for invalid nonce.
	 */
	public function test_verify_login_nonce_returns_false_for_invalid() {
		\AtomicEdge_2FA::create_login_nonce( $this->test_user_id );

		$this->assertFalse( \AtomicEdge_2FA::verify_login_nonce( $this->test_user_id, 'invalid_nonce' ) );
	}

	/**
	 * Test verify_login_nonce returns false when no nonce exists.
	 */
	public function test_verify_login_nonce_returns_false_without_nonce() {
		$this->assertFalse( \AtomicEdge_2FA::verify_login_nonce( $this->test_user_id, 'any_key' ) );
	}

	/**
	 * Test login nonce expiration is approximately 10 minutes.
	 */
	public function test_login_nonce_expiration_is_10_minutes() {
		$nonce = \AtomicEdge_2FA::create_login_nonce( $this->test_user_id );

		$expected = time() + ( 10 * 60 );
		$this->assertEqualsWithDelta( $expected, $nonce['expiration'], 5 );
	}

	// =========================================================================
	// Edge Case Tests - Expired Nonce
	// =========================================================================

	/**
	 * Test verify_login_nonce returns false for expired nonce.
	 */
	public function test_verify_login_nonce_returns_false_when_expired() {
		// Create nonce with immediate expiration (in the past).
		$nonce_data = array(
			'key'        => \AtomicEdge_2FA_Crypto::random_hex( 32 ),
			'expiration' => time() - 1, // Already expired.
		);
		$stored = array(
			'key'        => hash_hmac( 'md5', $nonce_data['key'], 'test_salt_nonce' ),
			'expiration' => $nonce_data['expiration'],
		);
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_LOGIN_NONCE ] = $stored;

		$this->assertFalse( \AtomicEdge_2FA::verify_login_nonce( $this->test_user_id, $nonce_data['key'] ) );
	}

	/**
	 * Test expired nonce is deleted after failed verification.
	 */
	public function test_expired_nonce_is_deleted_after_verification() {
		$nonce_key = $this->test_user_id . '_' . \AtomicEdge_2FA::META_LOGIN_NONCE;
		$stored    = array(
			'key'        => 'some_hash',
			'expiration' => time() - 1,
		);
		$this->user_meta[ $nonce_key ] = $stored;

		\AtomicEdge_2FA::verify_login_nonce( $this->test_user_id, 'any_key' );

		$this->assertArrayNotHasKey( $nonce_key, $this->user_meta );
	}

	// =========================================================================
	// Edge Case Tests - Get User Secret
	// =========================================================================

	/**
	 * Test get_user_secret returns false when no secret stored.
	 */
	public function test_get_user_secret_returns_false_when_empty() {
		$this->assertFalse( \AtomicEdge_2FA::get_user_secret( $this->test_user_id ) );
	}

	/**
	 * Test get_user_secret returns decrypted secret.
	 */
	public function test_get_user_secret_returns_decrypted_secret() {
		$secret    = \AtomicEdge_2FA_TOTP::generate_secret();
		$encrypted = \AtomicEdge_2FA_Crypto::encrypt( $secret );
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_TOTP_SECRET ] = $encrypted;

		$result = \AtomicEdge_2FA::get_user_secret( $this->test_user_id );

		$this->assertEquals( $secret, $result );
	}

	// =========================================================================
	// Edge Case Tests - Backup Codes
	// =========================================================================

	/**
	 * Test verify_backup_code returns false with empty codes.
	 */
	public function test_verify_backup_code_returns_false_with_empty_codes() {
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_BACKUP_CODES ] = '';

		$this->assertFalse( \AtomicEdge_2FA::verify_backup_code( $this->test_user_id, 'ABCD-EFGH' ) );
	}

	/**
	 * Test verify_backup_code returns false when no codes stored.
	 */
	public function test_verify_backup_code_returns_false_without_codes() {
		$this->assertFalse( \AtomicEdge_2FA::verify_backup_code( $this->test_user_id, 'ABCD-EFGH' ) );
	}

	// =========================================================================
	// Edge Case Tests - Complete Enrollment Decryption Failure
	// =========================================================================

	/**
	 * Test complete_enrollment fails with corrupted pending secret.
	 */
	public function test_complete_enrollment_fails_with_corrupted_secret() {
		// Store a corrupted/invalid encrypted value.
		$this->user_meta[ $this->test_user_id . '_' . \AtomicEdge_2FA::META_PENDING_SECRET ] = 'invalid_encrypted_data';

		$result = \AtomicEdge_2FA::complete_enrollment( $this->test_user_id, '123456' );

		$this->assertFalse( $result['success'] );
		$this->assertStringContainsString( 'decrypt', strtolower( $result['error'] ) );
	}

	// =========================================================================
	// Edge Case Tests - Rate Limiting Edge Cases
	// =========================================================================

	/**
	 * Test record_failed_attempt below threshold does not lockout.
	 */
	public function test_record_failed_attempt_below_threshold_no_lockout() {
		$lockout = \AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );

		$this->assertFalse( $lockout );
		$this->assertFalse( \AtomicEdge_2FA::is_rate_limited( $this->test_user_id ) );
	}

	/**
	 * Test record_failed_attempt exactly at threshold triggers lockout.
	 */
	public function test_record_failed_attempt_at_threshold_triggers_lockout() {
		// Get to 2 failures.
		\AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );
		\AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );

		// The 3rd failure should trigger lockout.
		$lockout = \AtomicEdge_2FA::record_failed_attempt( $this->test_user_id );

		$this->assertIsInt( $lockout );
		$this->assertEquals( 60, $lockout ); // 1 minute lockout.
	}

	// =========================================================================
	// Edge Case Tests - Disable When Not Enabled
	// =========================================================================

	/**
	 * Test disable succeeds even when 2FA was not enabled.
	 */
	public function test_disable_succeeds_when_not_enabled() {
		// No 2FA data set.
		$result = \AtomicEdge_2FA::disable( $this->test_user_id );

		$this->assertTrue( $result );
	}

	// =========================================================================
	// Edge Case Tests - User Status Edge Cases
	// =========================================================================

	/**
	 * Test get_user_status returns nulls for dates when not set.
	 */
	public function test_get_user_status_returns_null_dates_when_not_set() {
		$status = \AtomicEdge_2FA::get_user_status( $this->test_user_id );

		$this->assertNull( $status['setup_date'] );
		$this->assertNull( $status['last_used'] );
	}

	/**
	 * Test get_user_status returns zero codes when none stored.
	 */
	public function test_get_user_status_returns_zero_codes_when_none_stored() {
		$status = \AtomicEdge_2FA::get_user_status( $this->test_user_id );

		$this->assertEquals( 0, $status['codes_remaining'] );
		$this->assertEquals( 8, $status['codes_total'] );
	}

	// =========================================================================
	// Edge Case Tests - Delete Login Nonce
	// =========================================================================

	/**
	 * Test delete_login_nonce removes nonce.
	 */
	public function test_delete_login_nonce_removes_nonce() {
		$nonce_key = $this->test_user_id . '_' . \AtomicEdge_2FA::META_LOGIN_NONCE;
		$this->user_meta[ $nonce_key ] = array(
			'key'        => 'test_hash',
			'expiration' => time() + 600,
		);

		\AtomicEdge_2FA::delete_login_nonce( $this->test_user_id );

		$this->assertArrayNotHasKey( $nonce_key, $this->user_meta );
	}

	// =========================================================================
	// Edge Case Tests - Record Success
	// =========================================================================

	/**
	 * Test record_success updates last_used timestamp.
	 */
	public function test_record_success_updates_last_used() {
		$before = time();
		\AtomicEdge_2FA::record_success( $this->test_user_id );
		$after = time();

		$last_used_key = $this->test_user_id . '_' . \AtomicEdge_2FA::META_LAST_USED;
		$this->assertArrayHasKey( $last_used_key, $this->user_meta );
		$this->assertGreaterThanOrEqual( $before, $this->user_meta[ $last_used_key ] );
		$this->assertLessThanOrEqual( $after, $this->user_meta[ $last_used_key ] );
	}

	// =========================================================================
	// Edge Case Tests - Is Available
	// =========================================================================

	/**
	 * Test is_available reflects crypto availability.
	 */
	public function test_is_available_reflects_crypto() {
		$result = \AtomicEdge_2FA::is_available();

		// Should be true when OpenSSL is available.
		$this->assertIsBool( $result );
	}

	// =========================================================================
	// Edge Case Tests - Log Event
	// =========================================================================

	/**
	 * Test log_event triggers action hook.
	 */
	public function test_log_event_triggers_action() {
		$captured_args = array();

		Functions\when( 'do_action' )->alias(
			function ( $hook, ...$args ) use ( &$captured_args ) {
				if ( 'atomicedge_2fa_event' === $hook ) {
					$captured_args = $args;
				}
			}
		);

		\AtomicEdge_2FA::log_event( $this->test_user_id, 'test_event', array( 'foo' => 'bar' ) );

		$this->assertEquals( $this->test_user_id, $captured_args[0] );
		$this->assertEquals( 'test_event', $captured_args[1] );
		$this->assertEquals( array( 'foo' => 'bar' ), $captured_args[2] );
	}
}
