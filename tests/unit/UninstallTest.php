<?php
/**
 * Tests for plugin uninstall process.
 *
 * These tests verify that:
 * 1. uninstall.php can run without loading any plugin classes
 * 2. All cleanup functions are WordPress core functions (not plugin methods)
 * 3. No class dependencies exist that could cause fatal errors
 *
 * LESSON LEARNED (2026-02-16): Similar to activation hooks, uninstall.php runs
 * in a completely isolated context where no plugin classes are loaded.
 * Any call to plugin classes in uninstall.php would cause a fatal error.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * Test case for uninstall process.
 */
class UninstallTest extends TestCase {

	/**
	 * Path to the uninstall file.
	 *
	 * @var string
	 */
	private $uninstall_file;

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();
		$this->uninstall_file = dirname( dirname( __DIR__ ) ) . '/uninstall.php';
	}

	/**
	 * Test that uninstall.php exists.
	 *
	 * @return void
	 */
	public function test_uninstall_file_exists() {
		$this->assertFileExists( $this->uninstall_file, 'uninstall.php should exist' );
	}

	/**
	 * Test that uninstall.php has no class dependencies.
	 *
	 * This is the KEY test that prevents activation-style bugs in uninstall.
	 * WordPress runs uninstall.php in complete isolation - no plugin code is loaded.
	 *
	 * @return void
	 */
	public function test_uninstall_has_no_class_dependencies() {
		$contents = file_get_contents( $this->uninstall_file );

		// Remove comments to avoid false positives.
		$contents = preg_replace( '/\/\*.*?\*\//s', '', $contents );
		$contents = preg_replace( '/\/\/.*$/m', '', $contents );

		// Check for any class instantiation (new ClassName).
		preg_match_all( '/new\s+([A-Z][A-Za-z0-9_]+)\s*\(/', $contents, $new_matches );

		// Check for static method calls (ClassName::method).
		preg_match_all( '/([A-Z][A-Za-z0-9_]+)::[a-z_]+\s*\(/', $contents, $static_matches );

		// Exclude wpdb since it's a WordPress global, not a plugin class.
		$class_usages = array_merge(
			array_filter( $new_matches[1], fn( $c ) => $c !== 'wpdb' ),
			array_filter( $static_matches[1], fn( $c ) => $c !== 'wpdb' )
		);

		// Also exclude WordPress core classes.
		$wp_core_classes = array( 'WP_Error', 'WP_Query', 'WP_User', 'WP_Post', 'WP_Term' );
		$class_usages    = array_filter( $class_usages, fn( $c ) => ! in_array( $c, $wp_core_classes, true ) );

		$this->assertEmpty(
			$class_usages,
			sprintf(
				'uninstall.php should not use any plugin classes. Found: %s. ' .
				'WordPress runs uninstall.php in isolation - no plugin code is loaded.',
				implode( ', ', $class_usages )
			)
		);
	}

	/**
	 * Test that uninstall.php has the required security check.
	 *
	 * @return void
	 */
	public function test_uninstall_has_security_check() {
		$contents = file_get_contents( $this->uninstall_file );

		$this->assertStringContainsString(
			'WP_UNINSTALL_PLUGIN',
			$contents,
			'uninstall.php must check for WP_UNINSTALL_PLUGIN constant'
		);
	}

	/**
	 * Test that uninstall.php deletes all known options.
	 *
	 * @return void
	 */
	public function test_uninstall_cleans_up_options() {
		$contents = file_get_contents( $this->uninstall_file );

		// Check for key options that should be cleaned up.
		$expected_options = array(
			'atomicedge_api_key',
			'atomicedge_api_url',
			'atomicedge_connected',
			'atomicedge_site_data',
		);

		foreach ( $expected_options as $option ) {
			$this->assertStringContainsString(
				$option,
				$contents,
				sprintf( 'uninstall.php should clean up option: %s', $option )
			);
		}
	}

	/**
	 * Test that uninstall.php clears scheduled cron events.
	 *
	 * @return void
	 */
	public function test_uninstall_clears_cron_events() {
		$contents = file_get_contents( $this->uninstall_file );

		$this->assertStringContainsString(
			'wp_clear_scheduled_hook',
			$contents,
			'uninstall.php should clear scheduled cron events'
		);

		// Check for specific cron hooks.
		$expected_hooks = array(
			'atomicedge_daily_scan',
			'atomicedge_sync_settings',
		);

		foreach ( $expected_hooks as $hook ) {
			$this->assertStringContainsString(
				$hook,
				$contents,
				sprintf( 'uninstall.php should clear cron hook: %s', $hook )
			);
		}
	}

	/**
	 * Test that uninstall.php drops the scanner queue table.
	 *
	 * @return void
	 */
	public function test_uninstall_drops_database_tables() {
		$contents = file_get_contents( $this->uninstall_file );

		$this->assertStringContainsString(
			'atomicedge_scan_queue',
			$contents,
			'uninstall.php should drop the scanner queue table'
		);

		$this->assertStringContainsString(
			'DROP TABLE',
			$contents,
			'uninstall.php should use DROP TABLE'
		);
	}

	/**
	 * Test that uninstall.php cleans up transients.
	 *
	 * @return void
	 */
	public function test_uninstall_cleans_up_transients() {
		$contents = file_get_contents( $this->uninstall_file );

		$this->assertStringContainsString(
			'_transient_atomicedge_',
			$contents,
			'uninstall.php should clean up plugin transients'
		);
	}

	/**
	 * Test that uninstall.php does not require any plugin files.
	 *
	 * @return void
	 */
	public function test_uninstall_does_not_require_plugin_files() {
		$contents = file_get_contents( $this->uninstall_file );

		// Remove comments.
		$contents = preg_replace( '/\/\*.*?\*\//s', '', $contents );
		$contents = preg_replace( '/\/\/.*$/m', '', $contents );

		// Check for require/include statements (excluding WordPress core).
		preg_match_all( '/(?:require|include)(?:_once)?\s*[\(\s][\'"]([^\'"]+)[\'"]/i', $contents, $matches );

		$plugin_includes = array_filter(
			$matches[1],
			function ( $path ) {
				// Filter out WordPress core files.
				return strpos( $path, 'wp-admin' ) === false &&
					strpos( $path, 'wp-includes' ) === false &&
					strpos( $path, 'ABSPATH' ) === false;
			}
		);

		$this->assertEmpty(
			$plugin_includes,
			sprintf(
				'uninstall.php should not require/include plugin files. Found: %s',
				implode( ', ', $plugin_includes )
			)
		);
	}

	/**
	 * Test that uninstall.php has SQL injection protection.
	 *
	 * @return void
	 */
	public function test_uninstall_has_sql_injection_protection() {
		$contents = file_get_contents( $this->uninstall_file );

		// Should use prepared statements or sanitization.
		$has_prepare = strpos( $contents, '$wpdb->prepare' ) !== false;
		$has_regex   = strpos( $contents, 'preg_match' ) !== false;

		$this->assertTrue(
			$has_prepare || $has_regex,
			'uninstall.php should use $wpdb->prepare() or regex validation for SQL queries'
		);
	}
}
