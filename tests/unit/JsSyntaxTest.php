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
	 * Guard: WAF logs Blacklist button must use IP blacklist, not Adaptive Defense.
	 *
	 * The WAF logs "Blacklist" button must call blacklistIpFromWafLogs() which
	 * routes to the IP blacklist (SiteSettings.ip_blacklist), NOT blockIpFromWafLogs()
	 * which writes to Adaptive Defense (ActorProfile.is_blocked).
	 *
	 * Changed 2026-03-13: WAF logs blocking now routes to IP blacklist instead
	 * of Adaptive Defense.
	 *
	 * @return void
	 */
	public function test_waf_logs_blacklist_button_uses_ip_blacklist() {
		$path    = $this->get_plugin_path( 'admin/js/admin.js' );
		$content = file_get_contents( $path );

		$this->assertNotFalse( $content, 'Could not read admin.js' );

		// The WAF logs handler must call blacklistIpFromWafLogs.
		$this->assertStringContainsString(
			'blacklistIpFromWafLogs',
			$content,
			'admin.js must contain blacklistIpFromWafLogs() method for WAF logs blacklisting'
		);

		// Extract the .atomicedge-blacklist-ip click handler block (narrow window: 15 lines after the binding).
		$lines       = explode( "\n", $content );
		$handlerBody = '';
		$inHandler   = false;
		$remaining   = 0;

		foreach ( $lines as $line ) {
			if ( ! $inHandler && strpos( $line, '.atomicedge-blacklist-ip' ) !== false && strpos( $line, "'click'" ) !== false ) {
				$inHandler = true;
				$remaining = 15;
			}
			if ( $inHandler ) {
				$handlerBody .= $line . "\n";
				$remaining--;
				if ( $remaining <= 0 ) {
					break;
				}
			}
		}

		$this->assertNotEmpty( $handlerBody, '.atomicedge-blacklist-ip click handler not found in admin.js' );

		// The handler must call blacklistIpFromWafLogs.
		$this->assertStringContainsString(
			'blacklistIpFromWafLogs',
			$handlerBody,
			'WAF logs .atomicedge-blacklist-ip click handler must call blacklistIpFromWafLogs()'
		);
	}

	/**
	 * Guard: blacklistIpFromWafLogs must use atomicedge_add_ip_blacklist AJAX action.
	 *
	 * Ensures the method routes to the IP blacklist endpoint, not Adaptive Defense.
	 *
	 * @return void
	 */
	public function test_blacklist_ip_from_waf_logs_uses_blacklist_ajax_action() {
		$path    = $this->get_plugin_path( 'admin/js/admin.js' );
		$content = file_get_contents( $path );

		$this->assertNotFalse( $content, 'Could not read admin.js' );

		// Find the blacklistIpFromWafLogs function and verify it uses atomicedge_add_ip_blacklist.
		$pattern = '/blacklistIpFromWafLogs\s*:.*?atomicedge_add_ip_blacklist/s';
		$this->assertMatchesRegularExpression(
			$pattern,
			$content,
			'blacklistIpFromWafLogs() must call the atomicedge_add_ip_blacklist AJAX action (IP blacklist), '
			. 'NOT atomicedge_block_ip (Adaptive Defense).'
		);
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

	/**
	 * Verify the make-permanent button checks can_permanent_block before rendering.
	 *
	 * Guard test: prevents regression where the "Make Permanent" button renders
	 * as fully active for free tier users who cannot use the feature.
	 */
	public function test_make_permanent_button_checks_plan_gate_in_js() {
		$js = file_get_contents( $this->get_plugin_path( 'admin/js/adaptive-defense.js' ) );

		$this->assertStringContainsString(
			'can_permanent_block',
			$js,
			'adaptive-defense.js must check atomicedge_admin.can_permanent_block before rendering the Make Permanent button'
		);
	}

	/**
	 * Verify makePermanent() has plan_limit error handling.
	 *
	 * Defense-in-depth: the JS should detect plan_limit errors from the API
	 * and show an upgrade message instead of a generic error.
	 */
	public function test_make_permanent_js_handles_plan_limit_error() {
		$js = file_get_contents( $this->get_plugin_path( 'admin/js/adaptive-defense.js' ) );

		$this->assertStringContainsString(
			'plan_limit',
			$js,
			'adaptive-defense.js makePermanent() must handle plan_limit error code from the API'
		);
	}

	/**
	 * Verify disabled button has cursor-not-allowed for free tier.
	 */
	public function test_make_permanent_disabled_button_has_visual_indicator() {
		$js = file_get_contents( $this->get_plugin_path( 'admin/js/adaptive-defense.js' ) );

		$this->assertStringContainsString(
			'cursor:not-allowed',
			$js,
			'Free-tier Make Permanent button must have cursor:not-allowed styling'
		);
	}

	// =========================================================================
	// Nonce Refresh Mechanism Guard Tests
	// =========================================================================

	/**
	 * Guard: admin.js ajax() helper must detect nonce_error flag.
	 *
	 * The ajax() helper must check response.data.nonce_error so it can
	 * transparently retry after fetching a fresh nonce.
	 *
	 * Incident 2026-03-09: "Security check failed" with no auto-recovery.
	 */
	public function test_admin_js_ajax_helper_detects_nonce_error() {
		$js = file_get_contents( $this->get_plugin_path( 'admin/js/admin.js' ) );

		$this->assertStringContainsString(
			'nonce_error',
			$js,
			'admin.js ajax() helper must detect nonce_error flag from the server response '
			. 'to trigger transparent nonce refresh and retry'
		);
	}

	/**
	 * Guard: admin.js must have refreshNonceAndRetry method.
	 *
	 * This method fetches a fresh nonce from the server and replays
	 * the original AJAX request.
	 */
	public function test_admin_js_has_refresh_nonce_and_retry_method() {
		$js = file_get_contents( $this->get_plugin_path( 'admin/js/admin.js' ) );

		$this->assertStringContainsString(
			'refreshNonceAndRetry',
			$js,
			'admin.js must contain refreshNonceAndRetry() method for transparent nonce recovery'
		);
	}

	/**
	 * Guard: refreshNonceAndRetry must call atomicedge_refresh_nonce action.
	 *
	 * Ensures the method uses the correct server-side endpoint.
	 */
	public function test_refresh_nonce_uses_correct_ajax_action() {
		$js = file_get_contents( $this->get_plugin_path( 'admin/js/admin.js' ) );

		$this->assertStringContainsString(
			'atomicedge_refresh_nonce',
			$js,
			'refreshNonceAndRetry() must use the atomicedge_refresh_nonce AJAX action'
		);
	}

	/**
	 * Guard: ajax() helper must accept _isRetry parameter to prevent infinite loops.
	 *
	 * Without retry prevention, a permanent nonce failure would cause an
	 * infinite refresh→retry→refresh loop.
	 */
	public function test_ajax_helper_has_retry_prevention() {
		$js = file_get_contents( $this->get_plugin_path( 'admin/js/admin.js' ) );

		$this->assertStringContainsString(
			'_isRetry',
			$js,
			'admin.js ajax() must accept _isRetry parameter to prevent infinite nonce refresh loops'
		);
	}

	/**
	 * Guard: malware scanner should adapt after gateway-style failures.
	 */
	public function test_malware_scan_retries_with_smaller_budget_after_gateway_timeout() {
		$js = file_get_contents( $this->get_plugin_path( 'admin/js/admin.js' ) );

		$this->assertStringContainsString( 'http_status', $js );
		$this->assertStringContainsString( 'status === 504', $js );
		$this->assertStringContainsString( 'timeBudget = 4', $js );
		$this->assertStringContainsString( 'time_budget:', $js );
	}
}
