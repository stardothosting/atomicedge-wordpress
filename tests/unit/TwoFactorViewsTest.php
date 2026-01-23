<?php
/**
 * AtomicEdge 2FA Views Static Analysis Tests
 *
 * Validates that view templates reference valid constants and methods.
 * These tests prevent runtime errors like undefined constants in templates.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use AtomicEdge\Tests\TestCase;

/**
 * 2FA Views Static Analysis Test Suite
 */
class TwoFactorViewsTest extends TestCase {

	/**
	 * View files to analyze.
	 *
	 * @var array
	 */
	private $view_files = array(
		'admin/views/2fa-settings.php',
		'admin/views/partials/2fa-policy-tab.php',
		'admin/views/partials/2fa-users-tab.php',
		'admin/views/partials/2fa-audit-tab.php',
	);

	/**
	 * Test that all referenced class constants exist.
	 *
	 * Scans view files for CLASS::CONSTANT patterns and verifies they exist.
	 *
	 * @return void
	 */
	public function test_view_constants_exist() {
		$errors = array();

		foreach ( $this->view_files as $file ) {
			$filepath = ATOMICEDGE_PLUGIN_DIR . $file;

			if ( ! file_exists( $filepath ) ) {
				continue; // Skip if file doesn't exist (handles partial test runs).
			}

			$content = file_get_contents( $filepath );

			// Match patterns like AtomicEdge_2FA::META_KEY or AtomicEdge_2FA_Backup::CODE_COUNT.
			preg_match_all( '/\b(AtomicEdge_[A-Za-z0-9_]+)::([A-Z][A-Z0-9_]+)\b/', $content, $matches, PREG_SET_ORDER );

			foreach ( $matches as $match ) {
				$class    = $match[1];
				$constant = $match[2];

				// Check if the class exists.
				if ( ! class_exists( $class ) ) {
					$errors[] = sprintf(
						'File %s references undefined class: %s',
						$file,
						$class
					);
					continue;
				}

				// Check if the constant exists on the class.
				$reflection = new \ReflectionClass( $class );
				if ( ! $reflection->hasConstant( $constant ) ) {
					$errors[] = sprintf(
						'File %s references undefined constant: %s::%s',
						$file,
						$class,
						$constant
					);
				}
			}
		}

		$this->assertEmpty(
			$errors,
			"View files reference undefined constants:\n" . implode( "\n", $errors )
		);
	}

	/**
	 * Test that all referenced static method calls exist.
	 *
	 * Scans view files for CLASS::method() patterns and verifies they exist.
	 *
	 * @return void
	 */
	public function test_view_static_methods_exist() {
		$errors = array();

		foreach ( $this->view_files as $file ) {
			$filepath = ATOMICEDGE_PLUGIN_DIR . $file;

			if ( ! file_exists( $filepath ) ) {
				continue;
			}

			$content = file_get_contents( $filepath );

			// Match patterns like AtomicEdge_2FA::is_enabled_for_user(.
			preg_match_all( '/\b(AtomicEdge_[A-Za-z0-9_]+)::([a-z][a-z0-9_]*)\s*\(/', $content, $matches, PREG_SET_ORDER );

			foreach ( $matches as $match ) {
				$class  = $match[1];
				$method = $match[2];

				// Check if the class exists.
				if ( ! class_exists( $class ) ) {
					$errors[] = sprintf(
						'File %s references undefined class: %s',
						$file,
						$class
					);
					continue;
				}

				// Check if the method exists on the class.
				if ( ! method_exists( $class, $method ) ) {
					$errors[] = sprintf(
						'File %s references undefined method: %s::%s()',
						$file,
						$class,
						$method
					);
				}
			}
		}

		$this->assertEmpty(
			$errors,
			"View files reference undefined methods:\n" . implode( "\n", $errors )
		);
	}

	/**
	 * Test that 2FA view files use correct meta key references.
	 *
	 * Specifically validates backup codes meta key usage.
	 *
	 * @return void
	 */
	public function test_backup_codes_meta_key_correct() {
		$users_tab = ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/2fa-users-tab.php';

		if ( ! file_exists( $users_tab ) ) {
			$this->markTestSkipped( 'Users tab file not found.' );
		}

		$content = file_get_contents( $users_tab );

		// Should use AtomicEdge_2FA::META_BACKUP_CODES, not AtomicEdge_2FA_Backup::META_KEY.
		$this->assertStringNotContainsString(
			'AtomicEdge_2FA_Backup::META_KEY',
			$content,
			'Users tab should not reference undefined AtomicEdge_2FA_Backup::META_KEY constant'
		);

		// Should reference the correct constant.
		$this->assertStringContainsString(
			'AtomicEdge_2FA::META_BACKUP_CODES',
			$content,
			'Users tab should use AtomicEdge_2FA::META_BACKUP_CODES for backup codes meta key'
		);
	}

	/**
	 * Test that policy status array keys are correctly referenced.
	 *
	 * Validates that get_user_enforcement_status() return keys are used correctly.
	 *
	 * @return void
	 */
	public function test_policy_status_keys_correct() {
		$users_tab = ATOMICEDGE_PLUGIN_DIR . 'admin/views/partials/2fa-users-tab.php';

		if ( ! file_exists( $users_tab ) ) {
			$this->markTestSkipped( 'Users tab file not found.' );
		}

		$content = file_get_contents( $users_tab );

		// Get the actual return keys from the policy class.
		$reflection = new \ReflectionMethod( 'AtomicEdge_2FA_Policy', 'get_user_enforcement_status' );

		// Should not use old/wrong key names.
		$this->assertStringNotContainsString(
			"\$policy_status['status']",
			$content,
			'Users tab should not reference undefined policy_status[status] key'
		);

		$this->assertStringNotContainsString(
			"\$policy_status['days_remaining']",
			$content,
			'Users tab should not reference undefined policy_status[days_remaining] key'
		);

		// Should use correct key names.
		$this->assertStringContainsString(
			"\$policy_status['required']",
			$content,
			'Users tab should use policy_status[required] key'
		);

		$this->assertStringContainsString(
			"\$policy_status['in_grace_period']",
			$content,
			'Users tab should use policy_status[in_grace_period] key'
		);
	}

	/**
	 * Test that all 2FA classes are properly loaded.
	 *
	 * @return void
	 */
	public function test_twofa_classes_exist() {
		$required_classes = array(
			'AtomicEdge_2FA',
			'AtomicEdge_2FA_Audit',
			'AtomicEdge_2FA_Backup',
			'AtomicEdge_2FA_Crypto',
			'AtomicEdge_2FA_Policy',
			'AtomicEdge_2FA_TOTP',
		);

		foreach ( $required_classes as $class ) {
			$this->assertTrue(
				class_exists( $class ),
				sprintf( 'Required 2FA class %s should exist', $class )
			);
		}
	}

	/**
	 * Test that META_BACKUP_CODES constant exists and has expected format.
	 *
	 * @return void
	 */
	public function test_meta_backup_codes_constant() {
		$this->assertTrue(
			defined( 'AtomicEdge_2FA::META_BACKUP_CODES' ),
			'AtomicEdge_2FA::META_BACKUP_CODES constant should be defined'
		);

		$value = \AtomicEdge_2FA::META_BACKUP_CODES;
		$this->assertIsString( $value, 'META_BACKUP_CODES should be a string' );
		$this->assertStringStartsWith( '_atomicedge_', $value, 'META_BACKUP_CODES should start with _atomicedge_' );
	}
}
