<?php
/**
 * JavaScript Syntax Validation Tests
 *
 * Ensures all plugin JavaScript files are syntactically valid.
 * Catches issues like the 2026-02-28 adaptive-defense.js syntax
 * error that broke the entire Adaptive Defense page.
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
 * JS Syntax Test Suite
 */
class JsSyntaxTest extends TestCase {

	/**
	 * JavaScript files to validate.
	 *
	 * @var array<string>
	 */
	private static $js_files = array(
		'admin/js/admin.js',
		'admin/js/adaptive-defense.js',
	);

	/**
	 * Test that Node.js is available for syntax checking.
	 *
	 * @return void
	 */
	public function test_node_is_available_for_syntax_checks() {
		$output = array();
		$code   = 0;
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
		exec( 'node --version 2>&1', $output, $code );

		$this->assertSame(
			0,
			$code,
			'Node.js must be installed to validate JavaScript syntax. Install it via: apt install nodejs'
		);
	}

	/**
	 * Test admin.js has valid JavaScript syntax.
	 *
	 * @depends test_node_is_available_for_syntax_checks
	 * @return void
	 */
	public function test_admin_js_has_valid_syntax() {
		$this->assert_js_syntax_valid( 'admin/js/admin.js' );
	}

	/**
	 * Test adaptive-defense.js has valid JavaScript syntax.
	 *
	 * Regression test: a stray closing brace at line 373 broke ALL
	 * Adaptive Defense tabs (Status, Actor Profiles, Threat Detections).
	 * The entire file failed to parse, so no JS executed at all.
	 *
	 * @depends test_node_is_available_for_syntax_checks
	 * @return void
	 */
	public function test_adaptive_defense_js_has_valid_syntax() {
		$this->assert_js_syntax_valid( 'admin/js/adaptive-defense.js' );
	}

	/**
	 * Test no duplicate closing braces in adaptive-defense.js.
	 *
	 * Regression guard: detects the "},\n        }," pattern that caused
	 * the 2026-02-28 syntax error when blockIpToBlacklist was added.
	 *
	 * @return void
	 */
	public function test_adaptive_defense_js_no_duplicate_closing_braces() {
		$path    = $this->get_plugin_path( 'admin/js/adaptive-defense.js' );
		$content = file_get_contents( $path );

		$this->assertNotFalse( $content, 'Could not read adaptive-defense.js' );

		// Match the exact pattern that caused the bug: method closing "},\n        },"
		// (closing brace+comma immediately followed by another closing brace+comma
		// at the same or lower indentation, with no new method declaration between them).
		$pattern = '/\},\s*\n\s*\},\s*\n\s*\n\s*\/\*\*/';

		$this->assertDoesNotMatchRegularExpression(
			$pattern,
			$content,
			'Found duplicate closing brace pattern in adaptive-defense.js. '
			. 'This caused the 2026-02-28 incident where ALL Adaptive Defense tabs '
			. 'were broken. Check for stray "}," between methods.'
		);
	}

	/**
	 * Test all JS files exist.
	 *
	 * @return void
	 */
	public function test_all_expected_js_files_exist() {
		foreach ( self::$js_files as $file ) {
			$path = $this->get_plugin_path( $file );
			$this->assertFileExists( $path, "Expected JavaScript file not found: {$file}" );
		}
	}

	/**
	 * Assert that a JavaScript file has valid syntax via Node.js.
	 *
	 * @param string $relative_path Path relative to plugin root.
	 * @return void
	 */
	private function assert_js_syntax_valid( $relative_path ) {
		$path = $this->get_plugin_path( $relative_path );

		$this->assertFileExists( $path, "JavaScript file not found: {$relative_path}" );

		$output = array();
		$code   = 0;
		$cmd    = 'node -c ' . escapeshellarg( $path ) . ' 2>&1';

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
		exec( $cmd, $output, $code );

		$this->assertSame(
			0,
			$code,
			"JavaScript syntax error in {$relative_path}:\n" . implode( "\n", $output )
		);
	}

	/**
	 * Get absolute path to a plugin file.
	 *
	 * @param string $relative_path Path relative to plugin root.
	 * @return string
	 */
	private function get_plugin_path( $relative_path ) {
		return dirname( __DIR__, 2 ) . '/' . $relative_path;
	}
}
