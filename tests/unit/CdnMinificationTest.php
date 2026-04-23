<?php
/**
 * CDN Minification Tests
 *
 * Tests for minification cache clearing, auto-clear on disable,
 * and wp_delete_file return value handling.
 *
 * Bug 2026-04: Minification persisted after being disabled because:
 * 1. clear_minified_cache() used wp_delete_file() return value check,
 *    but wp_delete_file() returns void — so deletion failures were silent.
 * 2. Disabling minification did NOT auto-clear cached minified files.
 *    Browsers/CDN continued serving stale minified URLs.
 * 3. A dead AJAX handler in AtomicEdge_CDN with a mismatched nonce
 *    was never reachable (harmless but confusing).
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * CDN Minification Test Suite
 *
 * @covers \AtomicEdge_CDN::clear_minified_cache
 * @covers \AtomicEdge_CDN::get_cache_stats
 * @covers \AtomicEdge_Ajax::ajax_save_cdn_settings
 * @covers \AtomicEdge_Ajax::ajax_clear_minify_cache
 */
class CdnMinificationTest extends TestCase {

	/**
	 * AJAX handler instance.
	 *
	 * @var \AtomicEdge_Ajax
	 */
	private $ajax;

	/**
	 * Captured JSON response.
	 *
	 * @var array|null
	 */
	private $json_response = null;

	/**
	 * JSON response type (success/error).
	 *
	 * @var string|null
	 */
	private $json_response_type = null;

	/**
	 * Temp directory for cache tests.
	 *
	 * @var string
	 */
	private $temp_dir;

	protected function set_up() {
		parent::set_up();

		$_POST    = array();
		$_GET     = array();
		$_REQUEST = array();

		// Provide a valid nonce by default.
		$_POST['nonce'] = 'valid-nonce';

		$this->json_response      = null;
		$this->json_response_type = null;

		// Create temp directory for cache tests.
		$this->temp_dir = sys_get_temp_dir() . '/atomicedge-minify-test-' . uniqid();

		// Mock wp_send_json_success to capture output.
		Functions\when( 'wp_send_json_success' )->alias(
			function ( $data = null ) {
				$this->json_response      = $data;
				$this->json_response_type = 'success';
				throw new \AtomicEdge\Tests\AjaxExitException( 'success' );
			}
		);

		// Mock wp_send_json_error to capture output.
		Functions\when( 'wp_send_json_error' )->alias(
			function ( $data = null ) {
				$this->json_response      = $data;
				$this->json_response_type = 'error';
				throw new \AtomicEdge\Tests\AjaxExitException( 'error' );
			}
		);

		// Mock nonce verification and capability checks.
		Functions\when( 'wp_verify_nonce' )->justReturn( true );
		Functions\when( 'current_user_can' )->justReturn( true );

		// Mock sanitize_textarea_field.
		Functions\when( 'sanitize_textarea_field' )->alias(
			function ( $str ) {
				return strip_tags( $str );
			}
		);

		$mock_api   = $this->createMock( \AtomicEdge_API::class );
		$this->ajax = new \AtomicEdge_Ajax( $mock_api );
	}

	protected function tear_down() {
		// Cleanup temp directories.
		$this->recursive_rmdir( $this->temp_dir );
		parent::tear_down();
	}

	/**
	 * Recursively remove a directory.
	 *
	 * @param string $dir Directory path.
	 */
	private function recursive_rmdir( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$items = glob( $dir . '/*' );
		if ( $items ) {
			foreach ( $items as $item ) {
				is_dir( $item ) ? $this->recursive_rmdir( $item ) : @unlink( $item );
			}
		}
		@rmdir( $dir );
	}

	/**
	 * Create a cache directory structure with test files.
	 *
	 * @param int $css_count Number of CSS files to create.
	 * @param int $js_count  Number of JS files to create.
	 * @return string Cache directory path.
	 */
	private function create_cache_files( int $css_count = 2, int $js_count = 1 ): string {
		$cache_dir = $this->temp_dir . '/' . ATOMICEDGE_CDN_CACHE_DIR;
		$css_dir   = $cache_dir . '/css';
		$js_dir    = $cache_dir . '/js';

		mkdir( $css_dir, 0755, true );
		mkdir( $js_dir, 0755, true );

		for ( $i = 0; $i < $css_count; $i++ ) {
			file_put_contents( $css_dir . '/test' . $i . '.css', 'body{margin:0}' );
		}
		for ( $i = 0; $i < $js_count; $i++ ) {
			file_put_contents( $js_dir . '/test' . $i . '.js', 'var x=1;' );
		}

		return $cache_dir;
	}

	/**
	 * Mock wp_upload_dir to use our temp directory.
	 */
	private function mock_upload_dir(): void {
		Functions\when( 'wp_upload_dir' )->justReturn( array(
			'basedir' => $this->temp_dir,
			'baseurl' => 'http://example.com/wp-content/uploads',
		) );
	}

	/**
	 * Mock wp_delete_file to actually delete files (like real WordPress).
	 */
	private function mock_wp_delete_file_real(): void {
		Functions\when( 'wp_delete_file' )->alias( function ( $file ) {
			@unlink( $file );
			// Returns void, just like real WordPress.
		} );
	}

	/**
	 * Mock wp_delete_file to silently fail (simulate permission error).
	 */
	private function mock_wp_delete_file_noop(): void {
		Functions\when( 'wp_delete_file' )->alias( function ( $file ) {
			// Does nothing — simulates file permission failure.
			// Returns void, just like real WordPress.
		} );
	}

	/**
	 * Build serialized form data for the CDN settings form.
	 *
	 * @param array $fields Key-value pairs to include in the form data.
	 * @return string URL-encoded form data string.
	 */
	private function build_form_data( array $fields ): string {
		$fields['atomicedge_cdn_nonce'] = 'valid-cdn-nonce';
		return http_build_query( $fields );
	}

	/**
	 * Call the save handler with form data and catch the exit exception.
	 *
	 * @param string $form_data Serialized form data.
	 */
	private function call_save( string $form_data ): void {
		$_POST['formData'] = $form_data;

		try {
			$this->ajax->ajax_save_cdn_settings();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected — simulates wp_send_json exit.
		}
	}

	// =========================================================================
	// clear_minified_cache() — deletion verification fix
	// =========================================================================

	/**
	 * Test clear_minified_cache correctly counts successfully deleted files.
	 *
	 * Regression: wp_delete_file() returns void. The old code used
	 * `if (wp_delete_file($file) !== false)` which always evaluated to true
	 * because null !== false. Now we verify with file_exists() after deletion.
	 */
	public function test_clear_cache_counts_only_actually_deleted_files() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$this->create_cache_files( 2, 1 );

		$result = \AtomicEdge_CDN::clear_minified_cache();

		$this->assertTrue( $result['success'] );
		$this->assertSame( 3, $result['deleted'] );
	}

	/**
	 * Test clear_minified_cache reports zero deleted when deletion fails.
	 *
	 * Regression: Previously reported all files as deleted even when
	 * wp_delete_file() silently failed (e.g., permission errors).
	 */
	public function test_clear_cache_reports_zero_when_deletion_fails() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_noop();
		$this->create_cache_files( 2, 1 );

		$result = \AtomicEdge_CDN::clear_minified_cache();

		$this->assertTrue( $result['success'] );
		// Files still exist because wp_delete_file was a no-op.
		$this->assertSame( 0, $result['deleted'] );
	}

	/**
	 * Test clear_minified_cache clears the transient regardless of file deletion status.
	 */
	public function test_clear_cache_always_clears_transient() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_noop();
		// Must create cache files so the method doesn't early-return before delete_transient.
		$this->create_cache_files( 1, 0 );

		// Set the transient.
		$this->set_transient( 'atomicedge_cdn_minify_map', array( 'some' => 'data' ) );

		$result = \AtomicEdge_CDN::clear_minified_cache();

		$this->assertTrue( $result['success'] );
		// Transient should be cleared even though file deletion failed (noop mock).
		$this->assertFalse( $this->get_transient( 'atomicedge_cdn_minify_map' ) );
	}

	/**
	 * Test clear_minified_cache returns zero for empty cache directory.
	 */
	public function test_clear_cache_returns_zero_for_empty_cache() {
		$this->mock_upload_dir();

		// Create empty directories.
		$cache_dir = $this->temp_dir . '/' . ATOMICEDGE_CDN_CACHE_DIR;
		mkdir( $cache_dir . '/css', 0755, true );
		mkdir( $cache_dir . '/js', 0755, true );

		$result = \AtomicEdge_CDN::clear_minified_cache();

		$this->assertTrue( $result['success'] );
		$this->assertSame( 0, $result['deleted'] );
	}

	/**
	 * Test clear_minified_cache returns zero for non-existent cache directory.
	 */
	public function test_clear_cache_returns_zero_for_missing_dir() {
		Functions\when( 'wp_upload_dir' )->justReturn( array(
			'basedir' => sys_get_temp_dir() . '/non-existent-' . uniqid(),
		) );

		$result = \AtomicEdge_CDN::clear_minified_cache();

		$this->assertTrue( $result['success'] );
		$this->assertSame( 0, $result['deleted'] );
	}

	/**
	 * Test that files are actually removed from disk after clear.
	 */
	public function test_clear_cache_actually_removes_files_from_disk() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$cache_dir = $this->create_cache_files( 2, 1 );

		// Verify files exist before clear.
		$css_files = glob( $cache_dir . '/css/*' );
		$js_files  = glob( $cache_dir . '/js/*' );
		$this->assertCount( 2, $css_files );
		$this->assertCount( 1, $js_files );

		\AtomicEdge_CDN::clear_minified_cache();

		// Verify files are gone after clear.
		$css_files_after = glob( $cache_dir . '/css/*' );
		$js_files_after  = glob( $cache_dir . '/js/*' );
		$this->assertEmpty( $css_files_after );
		$this->assertEmpty( $js_files_after );
	}

	// =========================================================================
	// AJAX clear cache handler
	// =========================================================================

	/**
	 * Test AJAX clear cache handler returns success with correct count.
	 */
	public function test_ajax_clear_cache_returns_success_with_count() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$this->create_cache_files( 1, 1 );

		try {
			$this->ajax->ajax_clear_minify_cache();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertStringContainsString( '2', $this->json_response['message'] );
	}

	/**
	 * Test AJAX clear cache handler works when no cache exists.
	 */
	public function test_ajax_clear_cache_succeeds_with_empty_cache() {
		Functions\when( 'wp_upload_dir' )->justReturn( array(
			'basedir' => sys_get_temp_dir() . '/non-existent-' . uniqid(),
		) );

		try {
			$this->ajax->ajax_clear_minify_cache();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertStringContainsString( '0', $this->json_response['message'] );
	}

	// =========================================================================
	// Auto-clear cache on minification disable (critical regression fix)
	// =========================================================================

	/**
	 * Test disabling CSS minification auto-clears the cache.
	 *
	 * This is THE critical regression test — users reported minification
	 * persisting after they disabled it. Root cause: stale cached files.
	 */
	public function test_disabling_css_minification_auto_clears_cache() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$cache_dir = $this->create_cache_files( 2, 1 );

		// Pre-set CSS minification as enabled.
		$this->set_option( 'atomicedge_cdn_minify_css', 'on' );
		$this->set_option( 'atomicedge_cdn_minify_js', 'off' );

		// Save minification tab with CSS disabled (checkbox absent).
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab' => 'minification',
			// CSS checkbox absent = disabled.
		) ) );

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertSame( 'off', $this->get_option( 'atomicedge_cdn_minify_css' ) );

		// Cache should be cleared.
		$css_files = glob( $cache_dir . '/css/*' );
		$js_files  = glob( $cache_dir . '/js/*' );
		$this->assertEmpty( $css_files, 'CSS cache files should be cleared when CSS minification is disabled' );
		$this->assertEmpty( $js_files, 'JS cache files should also be cleared' );
	}

	/**
	 * Test disabling JS minification auto-clears the cache.
	 */
	public function test_disabling_js_minification_auto_clears_cache() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$cache_dir = $this->create_cache_files( 1, 2 );

		// Pre-set JS minification as enabled.
		$this->set_option( 'atomicedge_cdn_minify_css', 'off' );
		$this->set_option( 'atomicedge_cdn_minify_js', 'on' );

		// Save minification tab with JS disabled.
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab' => 'minification',
			// JS checkbox absent = disabled.
		) ) );

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertSame( 'off', $this->get_option( 'atomicedge_cdn_minify_js' ) );

		// Cache should be cleared.
		$js_files = glob( $cache_dir . '/js/*' );
		$this->assertEmpty( $js_files, 'JS cache files should be cleared when JS minification is disabled' );
	}

	/**
	 * Test disabling both CSS and JS minification auto-clears the cache.
	 */
	public function test_disabling_both_minification_auto_clears_cache() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$cache_dir = $this->create_cache_files( 2, 2 );

		// Pre-set both as enabled.
		$this->set_option( 'atomicedge_cdn_minify_css', 'on' );
		$this->set_option( 'atomicedge_cdn_minify_js', 'on' );

		// Save with both disabled.
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab' => 'minification',
		) ) );

		$this->assertSame( 'success', $this->json_response_type );

		// All cache should be cleared.
		$css_files = glob( $cache_dir . '/css/*' );
		$js_files  = glob( $cache_dir . '/js/*' );
		$this->assertEmpty( $css_files );
		$this->assertEmpty( $js_files );
	}

	/**
	 * Test enabling minification does NOT clear the cache.
	 *
	 * Only disable transitions should trigger auto-clear.
	 */
	public function test_enabling_minification_does_not_clear_cache() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$cache_dir = $this->create_cache_files( 2, 1 );

		// Pre-set minification as disabled.
		$this->set_option( 'atomicedge_cdn_minify_css', 'off' );
		$this->set_option( 'atomicedge_cdn_minify_js', 'off' );

		// Save with CSS enabled.
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab'        => 'minification',
			'atomicedge_cdn_minify_css' => 'on',
		) ) );

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertSame( 'on', $this->get_option( 'atomicedge_cdn_minify_css' ) );

		// Cache should still exist — enable does NOT clear.
		$css_files = glob( $cache_dir . '/css/*' );
		$this->assertCount( 2, $css_files, 'Cache should not be cleared when enabling minification' );
	}

	/**
	 * Test saving minification with no state change does NOT clear cache.
	 */
	public function test_saving_with_no_change_does_not_clear_cache() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$cache_dir = $this->create_cache_files( 2, 1 );

		// Pre-set both as disabled.
		$this->set_option( 'atomicedge_cdn_minify_css', 'off' );
		$this->set_option( 'atomicedge_cdn_minify_js', 'off' );

		// Save again with same settings (still disabled).
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab' => 'minification',
		) ) );

		$this->assertSame( 'success', $this->json_response_type );

		// Cache should still exist — no transition occurred.
		$css_files = glob( $cache_dir . '/css/*' );
		$this->assertCount( 2, $css_files, 'Cache should not be cleared when no state change occurs' );
	}

	/**
	 * Test saving from general tab does NOT clear minification cache.
	 */
	public function test_saving_general_tab_does_not_clear_minify_cache() {
		$this->mock_upload_dir();
		$this->mock_wp_delete_file_real();
		$cache_dir = $this->create_cache_files( 2, 1 );

		// Pre-set minification as enabled.
		$this->set_option( 'atomicedge_cdn_minify_css', 'on' );

		// Save from general tab.
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab'           => 'general',
			'atomicedge_cdn_local_enabled' => 'on',
		) ) );

		// Cache should still exist — general tab doesn't touch minification.
		$css_files = glob( $cache_dir . '/css/*' );
		$this->assertCount( 2, $css_files, 'General tab save should not clear minification cache' );
	}

	// =========================================================================
	// Dead AJAX handler removal guard tests
	// =========================================================================

	/**
	 * Test that AtomicEdge_CDN does not register the dead AJAX handler.
	 *
	 * Guard test: ensures the dead handler with mismatched nonce
	 * (atomicedge_cdn_clear_minified_cache / atomicedge_cdn_clear_cache)
	 * is not re-introduced.
	 */
	public function test_cdn_class_does_not_register_dead_ajax_handler() {
		$source = file_get_contents( ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cdn.php' );

		$this->assertStringNotContainsString(
			'atomicedge_cdn_clear_minified_cache',
			$source,
			'Dead AJAX action atomicedge_cdn_clear_minified_cache should not exist in CDN class'
		);

		$this->assertStringNotContainsString(
			'ajax_clear_minified_cache',
			$source,
			'Dead handler method ajax_clear_minified_cache should not exist in CDN class'
		);
	}

	/**
	 * Test that the working AJAX handler exists in the Ajax class.
	 */
	public function test_working_ajax_handler_exists_in_ajax_class() {
		$source = file_get_contents( ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-ajax.php' );

		$this->assertStringContainsString(
			'atomicedge_clear_minify_cache',
			$source,
			'Working AJAX action should exist in Ajax class'
		);

		$this->assertStringContainsString(
			'ajax_clear_minify_cache',
			$source,
			'Working handler method should exist in Ajax class'
		);
	}

	// =========================================================================
	// wp_delete_file return value guard test
	// =========================================================================

	/**
	 * Guard test: clear_minified_cache must NOT check wp_delete_file return value.
	 *
	 * wp_delete_file() returns void. Any code checking its return value
	 * (e.g., `if (wp_delete_file($file) !== false)`) is a bug because
	 * void !== false is always true.
	 */
	public function test_clear_cache_does_not_check_wp_delete_file_return() {
		$source = file_get_contents( ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cdn.php' );

		$this->assertDoesNotMatchRegularExpression(
			'/wp_delete_file\s*\([^)]+\)\s*!==\s*false/',
			$source,
			'clear_minified_cache must not check wp_delete_file() return value (it returns void)'
		);

		$this->assertDoesNotMatchRegularExpression(
			'/if\s*\(\s*wp_delete_file/',
			$source,
			'wp_delete_file() must not be used as a conditional (it returns void)'
		);
	}

	/**
	 * Guard test: clear_minified_cache must verify deletion with file_exists().
	 */
	public function test_clear_cache_verifies_deletion_with_file_exists() {
		$source = file_get_contents( ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cdn.php' );

		// After wp_delete_file, there should be a file_exists check.
		$this->assertMatchesRegularExpression(
			'/wp_delete_file\s*\([^)]+\);\s*\n\s*if\s*\(\s*!\s*file_exists/',
			$source,
			'clear_minified_cache must verify deletion with file_exists() after wp_delete_file()'
		);
	}

	// =========================================================================
	// Auto-clear on disable guard test
	// =========================================================================

	/**
	 * Guard test: ajax_save_cdn_settings must call clear_minified_cache on disable.
	 *
	 * Source-level scan to prevent the auto-clear logic from being removed.
	 */
	public function test_save_handler_has_auto_clear_on_disable() {
		$source = file_get_contents( ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-ajax.php' );

		// Must capture previous state.
		$this->assertStringContainsString(
			'was_css_on',
			$source,
			'Save handler must capture previous CSS minification state'
		);

		$this->assertStringContainsString(
			'was_js_on',
			$source,
			'Save handler must capture previous JS minification state'
		);

		// Must call clear_minified_cache.
		$this->assertStringContainsString(
			'clear_minified_cache',
			$source,
			'Save handler must call clear_minified_cache when disabling minification'
		);
	}

	// =========================================================================
	// get_cache_stats tests
	// =========================================================================

	/**
	 * Test get_cache_stats returns correct counts.
	 */
	public function test_get_cache_stats_returns_correct_counts() {
		$this->mock_upload_dir();
		$this->create_cache_files( 3, 2 );

		$stats = \AtomicEdge_CDN::get_cache_stats();

		$this->assertSame( 5, $stats['count'] );
		$this->assertSame( 3, $stats['css_count'] );
		$this->assertSame( 2, $stats['js_count'] );
		$this->assertGreaterThan( 0, $stats['total_size'] );
		$this->assertNotEmpty( $stats['size_human'] );
	}

	/**
	 * Test get_cache_stats returns zeros for empty cache.
	 */
	public function test_get_cache_stats_returns_zeros_for_empty_cache() {
		Functions\when( 'wp_upload_dir' )->justReturn( array(
			'basedir' => sys_get_temp_dir() . '/non-existent-' . uniqid(),
		) );

		$stats = \AtomicEdge_CDN::get_cache_stats();

		$this->assertSame( 0, $stats['count'] );
		$this->assertSame( 0, $stats['css_count'] );
		$this->assertSame( 0, $stats['js_count'] );
		$this->assertSame( 0, $stats['total_size'] );
	}

	// =========================================================================
	// Minification option gating
	// =========================================================================

	/**
	 * Test get_cdn_options returns correct minification state.
	 */
	public function test_get_cdn_options_returns_minification_state() {
		$this->set_option( 'atomicedge_cdn_minify_css', 'on' );
		$this->set_option( 'atomicedge_cdn_minify_js', 'off' );
		$this->set_option( 'atomicedge_cdn_minify_html', 'on' );

		$options = \AtomicEdge_CDN::get_cdn_options();

		$this->assertSame( 'on', $options['cdn_minify_css'] );
		$this->assertSame( 'off', $options['cdn_minify_js'] );
		$this->assertSame( 'on', $options['cdn_minify_html'] );
	}

	/**
	 * Test minification options default to empty string (not 'on').
	 */
	public function test_minification_options_default_to_empty() {
		// Fresh install — no options set.
		$options = \AtomicEdge_CDN::get_cdn_options();

		$this->assertSame( '', $options['cdn_minify_css'] );
		$this->assertSame( '', $options['cdn_minify_js'] );
		$this->assertSame( '', $options['cdn_minify_html'] );
	}

	/**
	 * Test HTML minification requires CDN to be enabled.
	 */
	public function test_html_minification_requires_cdn_enabled() {
		// CDN disabled, HTML minification on.
		$this->set_option( 'atomicedge_cdn_local_enabled', 'off' );
		$this->set_option( 'atomicedge_cdn_minify_html', 'on' );

		$this->assertFalse(
			\AtomicEdge_CDN::is_html_minification_enabled(),
			'HTML minification should be disabled when CDN is off'
		);
	}
}
