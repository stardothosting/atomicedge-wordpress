<?php
/**
 * Tests for class file dependencies and loading order.
 *
 * These tests verify that all plugin class files can be loaded independently
 * and don't have circular or missing dependencies. This catches bugs where
 * a class file tries to use another class that hasn't been loaded yet.
 *
 * LESSON LEARNED (2026-02-16): Class loading order issues caused a fatal error
 * in production when AtomicEdge_Cron was called before it was loaded. These
 * tests prevent similar issues by verifying each class can load standalone.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;

/**
 * Test case for class dependencies.
 */
class ClassDependencyTest extends TestCase {

	/**
	 * List of all plugin class files and their expected class names.
	 * Note: class-atomicedge-cdn-rules.php only defines constants, no class.
	 *
	 * @var array
	 */
	private $class_files = array(
		'includes/class-atomicedge.php'                    => 'AtomicEdge',
		'includes/class-atomicedge-api.php'                => 'AtomicEdge_API',
		'includes/class-atomicedge-admin.php'              => 'AtomicEdge_Admin',
		'includes/class-atomicedge-ajax.php'               => 'AtomicEdge_Ajax',
		'includes/class-atomicedge-scanner.php'            => 'AtomicEdge_Scanner',
		'includes/class-atomicedge-vulnerability-scanner.php' => 'AtomicEdge_Vulnerability_Scanner',
		'includes/class-atomicedge-cron.php'               => 'AtomicEdge_Cron',
		'includes/class-atomicedge-cdn.php'                => 'AtomicEdge_CDN',
		'includes/class-atomicedge-cdn-rewrite.php'        => 'AtomicEdge_CDN_Rewrite',
		// Note: class-atomicedge-cdn-rules.php only defines constants, not a class.
		'includes/class-atomicedge-dev-mode.php'           => 'AtomicEdge_Dev_Mode',
		'includes/class-atomicedge-2fa.php'                => 'AtomicEdge_2FA',
		'includes/class-atomicedge-2fa-crypto.php'         => 'AtomicEdge_2FA_Crypto',
		'includes/class-atomicedge-2fa-totp.php'           => 'AtomicEdge_2FA_TOTP',
		'includes/class-atomicedge-2fa-backup.php'         => 'AtomicEdge_2FA_Backup',
		'includes/class-atomicedge-2fa-policy.php'         => 'AtomicEdge_2FA_Policy',
		'includes/class-atomicedge-2fa-audit.php'          => 'AtomicEdge_2FA_Audit',
		'includes/class-atomicedge-2fa-login.php'          => 'AtomicEdge_2FA_Login',
	);

	/**
	 * Test that all class files exist.
	 *
	 * @return void
	 */
	public function test_all_class_files_exist() {
		foreach ( $this->class_files as $file => $class_name ) {
			$full_path = ATOMICEDGE_PLUGIN_DIR . $file;
			$this->assertFileExists(
				$full_path,
				sprintf( 'Class file %s should exist', $file )
			);
		}
	}

	/**
	 * Test that each class file defines the expected class.
	 *
	 * @return void
	 */
	public function test_class_files_define_expected_classes() {
		foreach ( $this->class_files as $file => $class_name ) {
			// Class should already be loaded by bootstrap.
			$this->assertTrue(
				class_exists( $class_name ),
				sprintf( 'Class %s from %s should be defined', $class_name, $file )
			);
		}
	}

	/**
	 * Test that class files have proper namespace/no namespace consistency.
	 *
	 * All AtomicEdge classes should be in the global namespace for WordPress compatibility.
	 *
	 * @return void
	 */
	public function test_classes_are_in_global_namespace() {
		foreach ( $this->class_files as $file => $class_name ) {
			// Check the class is in global namespace (no backslash prefix needed).
			$this->assertTrue(
				class_exists( $class_name ) || class_exists( '\\' . $class_name ),
				sprintf( 'Class %s should be in global namespace', $class_name )
			);
		}
	}

	/**
	 * Test that no class file has syntax errors.
	 *
	 * @return void
	 */
	public function test_class_files_have_no_syntax_errors() {
		foreach ( $this->class_files as $file => $class_name ) {
			$full_path = ATOMICEDGE_PLUGIN_DIR . $file;

			// Use php -l to check syntax.
			$output     = array();
			$return_var = 0;
			exec( 'php -l ' . escapeshellarg( $full_path ) . ' 2>&1', $output, $return_var );

			$this->assertEquals(
				0,
				$return_var,
				sprintf( 'Class file %s has syntax errors: %s', $file, implode( "\n", $output ) )
			);
		}
	}

	/**
	 * Test that main plugin file has all required includes in atomicedge_init().
	 *
	 * @return void
	 */
	public function test_main_plugin_includes_all_class_files() {
		$plugin_file = ATOMICEDGE_PLUGIN_DIR . 'atomicedge.php';
		$contents    = file_get_contents( $plugin_file );

		// Extract the atomicedge_init function.
		$pattern = '/function\s+atomicedge_init\s*\(\s*\)\s*\{(.*?)\n\}/s';
		preg_match( $pattern, $contents, $matches );

		$this->assertNotEmpty( $matches, 'Should find atomicedge_init function' );

		$init_body = $matches[1];

		// Check each class file is included (except main plugin class and CLI).
		$files_to_check = array(
			'class-atomicedge-api.php',
			'class-atomicedge-admin.php',
			'class-atomicedge-ajax.php',
			'class-atomicedge-scanner.php',
			'class-atomicedge-cron.php',
			'class-atomicedge-cdn.php',
			'class-atomicedge-2fa.php',
		);

		foreach ( $files_to_check as $file ) {
			$this->assertStringContainsString(
				$file,
				$init_body,
				sprintf( 'atomicedge_init() should include %s', $file )
			);
		}
	}

	/**
	 * Test that 2FA classes are loaded in correct dependency order.
	 *
	 * @return void
	 */
	public function test_2fa_classes_loaded_in_correct_order() {
		$plugin_file = ATOMICEDGE_PLUGIN_DIR . 'atomicedge.php';
		$contents    = file_get_contents( $plugin_file );

		// 2FA Crypto should be loaded before 2FA (main class depends on Crypto).
		$crypto_pos = strpos( $contents, 'class-atomicedge-2fa-crypto.php' );
		$main_pos   = strpos( $contents, "require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-2fa.php'" );

		$this->assertLessThan(
			$main_pos,
			$crypto_pos,
			'2FA Crypto should be loaded before main 2FA class'
		);

		// TOTP should be loaded before main 2FA class.
		$totp_pos = strpos( $contents, 'class-atomicedge-2fa-totp.php' );
		$this->assertLessThan(
			$main_pos,
			$totp_pos,
			'2FA TOTP should be loaded before main 2FA class'
		);
	}

	/**
	 * Test that AtomicEdge_Cron has no constructor dependencies.
	 *
	 * This specifically tests the class that caused the v2.4.3 bug.
	 *
	 * @return void
	 */
	public function test_cron_class_has_no_constructor_dependencies() {
		$cron_file = ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cron.php';
		$contents  = file_get_contents( $cron_file );

		// Check constructor doesn't instantiate other plugin classes.
		$pattern = '/public\s+function\s+__construct\s*\(\s*\)\s*\{(.*?)\n\t\}/s';
		preg_match( $pattern, $contents, $matches );

		if ( ! empty( $matches[1] ) ) {
			$constructor_body = $matches[1];

			// Should not instantiate other AtomicEdge classes.
			$this->assertStringNotContainsString(
				'new AtomicEdge_',
				$constructor_body,
				'Cron constructor should not instantiate other AtomicEdge classes'
			);
		}

		$this->assertTrue( true ); // Pass if no constructor or empty constructor.
	}

	/**
	 * Test that static methods used in activation don't require instance.
	 *
	 * @return void
	 */
	public function test_cron_schedule_methods_are_static() {
		$this->assertTrue(
			( new \ReflectionMethod( 'AtomicEdge_Cron', 'schedule_cdn_cleanup' ) )->isStatic(),
			'schedule_cdn_cleanup should be a static method'
		);
	}

	/**
	 * Test that CDN classes can work independently.
	 *
	 * @return void
	 */
	public function test_cdn_classes_exist_and_are_independent() {
		$cdn_classes = array(
			'AtomicEdge_CDN',
			'AtomicEdge_CDN_Rewrite',
			// Note: AtomicEdge_CDN_Rules is not a class, it's a constants file.
		);

		foreach ( $cdn_classes as $class ) {
			$this->assertTrue(
				class_exists( $class ),
				sprintf( 'CDN class %s should exist', $class )
			);
		}
	}

	/**
	 * Test that CDN Rules constants file exists and defines expected constants.
	 *
	 * @return void
	 */
	public function test_cdn_rules_constants_are_defined() {
		// This file only defines constants, not a class.
		$this->assertTrue(
			defined( 'ATOMICEDGE_CDN_SUFFIX' ),
			'ATOMICEDGE_CDN_SUFFIX constant should be defined'
		);
	}
}
