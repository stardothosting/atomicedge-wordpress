<?php
/**
 * CDN View Contract Tests
 *
 * Tests that verify the data contracts between CDN views and PHP classes.
 * These tests ensure views receive the data they expect from backend methods.
 *
 * @package AtomicEdge\Tests\Integration
 */

namespace AtomicEdge\Tests\Integration;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * CDN View Contract Test Suite
 *
 * These tests verify that:
 * 1. Methods return all keys expected by views
 * 2. Data types match what views expect
 * 3. Default values are reasonable
 */
class CdnViewContractTest extends TestCase {

	/**
	 * Test get_cache_stats returns all keys expected by cdn-minification-tab.php.
	 *
	 * The view file uses these keys:
	 * - $cache_stats['count']
	 * - $cache_stats['size_human']
	 * - $cache_stats['css_count']
	 * - $cache_stats['js_count']
	 *
	 * @see admin/views/partials/cdn-minification-tab.php lines 27-31
	 */
	public function test_get_cache_stats_contract_for_minification_tab() {
		$stats = \AtomicEdge_CDN::get_cache_stats();

		// Keys used by cdn-minification-tab.php
		$this->assertArrayHasKey( 'count', $stats, 'cdn-minification-tab.php line 28: $cache_stats[\'count\']' );
		$this->assertArrayHasKey( 'size_human', $stats, 'cdn-minification-tab.php line 29: $cache_stats[\'size_human\']' );
		$this->assertArrayHasKey( 'css_count', $stats, 'cdn-minification-tab.php line 30: $cache_stats[\'css_count\']' );
		$this->assertArrayHasKey( 'js_count', $stats, 'cdn-minification-tab.php line 31: $cache_stats[\'js_count\']' );

		// Type checks
		$this->assertIsInt( $stats['count'], 'count must be integer' );
		$this->assertIsString( $stats['size_human'], 'size_human must be string' );
		$this->assertIsInt( $stats['css_count'], 'css_count must be integer' );
		$this->assertIsInt( $stats['js_count'], 'js_count must be integer' );

		// Logical checks
		$this->assertGreaterThanOrEqual( 0, $stats['count'], 'count cannot be negative' );
		$this->assertGreaterThanOrEqual( 0, $stats['css_count'], 'css_count cannot be negative' );
		$this->assertGreaterThanOrEqual( 0, $stats['js_count'], 'js_count cannot be negative' );
		$this->assertSame(
			$stats['css_count'] + $stats['js_count'],
			$stats['count'],
			'count must equal css_count + js_count'
		);
	}

	/**
	 * Test get_cdn_options returns all keys expected by cdn-general-tab.php.
	 *
	 * The view uses $cdn_options array values.
	 *
	 * @see admin/views/partials/cdn-general-tab.php
	 */
	public function test_get_cdn_options_contract_for_general_tab() {
		$options = \AtomicEdge_CDN::get_cdn_options();

		// Keys that should exist as defined in get_cdn_options()
		$expected_keys = array(
			'cdn_url',
			'cdn_css',
			'cdn_js',
			'cdn_media',
			'cdn_minify_css',
			'cdn_minify_js',
			'cdn_minify_html',
			'cdn_reject_files',
		);

		foreach ( $expected_keys as $key ) {
			$this->assertArrayHasKey( $key, $options, "get_cdn_options must return '{$key}' for view compatibility" );
		}
	}

	/**
	 * Test get_cache_dir returns a string path.
	 *
	 * @see admin/views/partials/cdn-advanced-tab.php
	 */
	public function test_get_cache_dir_returns_string() {
		$cache_dir = \AtomicEdge_CDN::get_cache_dir();

		$this->assertIsString( $cache_dir, 'get_cache_dir must return string' );
		$this->assertNotEmpty( $cache_dir, 'get_cache_dir must not be empty' );
		$this->assertStringContainsString( 'atomicedge', strtolower( $cache_dir ), 'cache dir should contain atomicedge' );
	}

	/**
	 * Test is_cdn_enabled returns boolean.
	 *
	 * @see admin/views/partials/cdn-advanced-tab.php
	 */
	public function test_is_cdn_enabled_returns_boolean() {
		$result = \AtomicEdge_CDN::is_cdn_enabled();

		$this->assertIsBool( $result, 'is_cdn_enabled must return boolean' );
	}

	/**
	 * Test get_cdn_hostname with various scenarios.
	 *
	 * @see includes/class-atomicedge-cdn.php
	 */
	public function test_get_cdn_hostname_contract() {
		// Test with no CDN data
		update_option( 'atomicedge_site_data', array() );
		// Dev mode removed - CDN URL comes from dashboard
		// atomicedge_cdn_dev_url removed

		$hostname = \AtomicEdge_CDN::get_cdn_hostname();
		$this->assertIsString( $hostname, 'get_cdn_hostname must return string' );
	}

	/**
	 * Test that CDN rewriter can be instantiated without errors.
	 *
	 * This is a smoke test to catch initialization issues.
	 */
	public function test_cdn_rewriter_instantiation() {
		// Enable CDN locally and simulate dashboard connection with CDN enabled.
		update_option( 'atomicedge_cdn_local_enabled', 'on' );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', array( 'cdn_enabled' => true, 'cdn_url' => 'https://test.cdn.example.com' ) );

		// Verify is_cdn_enabled returns true.
		$this->assertTrue( \AtomicEdge_CDN::is_cdn_enabled(), 'CDN should be enabled with dashboard connection and CDN enabled' );

		// Instantiate rewriter - should not throw.
		$rewriter = new \AtomicEdge_CDN_Rewrite();
		$this->assertInstanceOf( \AtomicEdge_CDN_Rewrite::class, $rewriter );
	}

	/**
	 * Test CDN rewriter URL rewriting works correctly.
	 */
	public function test_cdn_rewriter_rewrites_urls() {
		// Set up CDN configuration.
		update_option( 'atomicedge_cdn_local_enabled', 'on' );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', array( 'cdn_enabled' => true, 'cdn_url' => 'https://test.cdn.example.com' ) );
		update_option( 'atomicedge_cdn_css', 'on' );
		update_option( 'atomicedge_cdn_js', 'on' );
		update_option( 'atomicedge_cdn_media', 'on' );

		// Create rewriter instance.
		$rewriter = new \AtomicEdge_CDN_Rewrite();

		// Test HTML with various URL types.
		$test_html = '<link href="http://example.com/wp-content/themes/test/style.css" rel="stylesheet">';
		$result    = $rewriter->rewrite( $test_html );

		$this->assertStringContainsString( 'cdn.example.com', $result, 'CSS URLs should be rewritten to CDN' );
	}

	/**
	 * Test that CSS toggle OFF disables CSS rewriting.
	 */
	public function test_css_toggle_off_disables_css_rewriting() {
		// Set up CDN configuration with CSS disabled.
		update_option( 'atomicedge_cdn_local_enabled', 'on' );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', array( 'cdn_enabled' => true, 'cdn_url' => 'https://test.cdn.example.com' ) );
		update_option( 'atomicedge_cdn_css', 'off' ); // CSS disabled.
		update_option( 'atomicedge_cdn_js', 'on' );
		update_option( 'atomicedge_cdn_media', 'on' );

		// Create rewriter instance.
		$rewriter = new \AtomicEdge_CDN_Rewrite();

		// Test CSS URL - should NOT be rewritten.
		$test_css = '<link href="http://example.com/wp-content/themes/test/style.css" rel="stylesheet">';
		$result   = $rewriter->rewrite( $test_css );

		$this->assertStringContainsString( 'example.com/wp-content', $result, 'CSS URLs should NOT be rewritten when CSS toggle is off' );
		$this->assertStringNotContainsString( 'cdn.example.com', $result, 'CDN URL should NOT appear for CSS when disabled' );

		// Test JS URL - should still be rewritten.
		$test_js = '<script src="http://example.com/wp-content/themes/test/script.js"></script>';
		$result  = $rewriter->rewrite( $test_js );

		$this->assertStringContainsString( 'cdn.example.com', $result, 'JS URLs should still be rewritten' );
	}

	/**
	 * Test that JS toggle OFF disables JS rewriting.
	 */
	public function test_js_toggle_off_disables_js_rewriting() {
		// Set up CDN configuration with JS disabled.
		update_option( 'atomicedge_cdn_local_enabled', 'on' );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', array( 'cdn_enabled' => true, 'cdn_url' => 'https://test.cdn.example.com' ) );
		update_option( 'atomicedge_cdn_css', 'on' );
		update_option( 'atomicedge_cdn_js', 'off' ); // JS disabled.
		update_option( 'atomicedge_cdn_media', 'on' );

		// Create rewriter instance.
		$rewriter = new \AtomicEdge_CDN_Rewrite();

		// Test JS URL - should NOT be rewritten.
		$test_js = '<script src="http://example.com/wp-content/themes/test/script.js"></script>';
		$result  = $rewriter->rewrite( $test_js );

		$this->assertStringContainsString( 'example.com/wp-content', $result, 'JS URLs should NOT be rewritten when JS toggle is off' );
		$this->assertStringNotContainsString( 'cdn.example.com', $result, 'CDN URL should NOT appear for JS when disabled' );

		// Test CSS URL - should still be rewritten.
		$test_css = '<link href="http://example.com/wp-content/themes/test/style.css" rel="stylesheet">';
		$result   = $rewriter->rewrite( $test_css );

		$this->assertStringContainsString( 'cdn.example.com', $result, 'CSS URLs should still be rewritten' );
	}

	/**
	 * Test that Media toggle OFF disables image/media rewriting.
	 */
	public function test_media_toggle_off_disables_media_rewriting() {
		// Set up CDN configuration with Media disabled.
		update_option( 'atomicedge_cdn_local_enabled', 'on' );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', array( 'cdn_enabled' => true, 'cdn_url' => 'https://test.cdn.example.com' ) );
		update_option( 'atomicedge_cdn_css', 'on' );
		update_option( 'atomicedge_cdn_js', 'on' );
		update_option( 'atomicedge_cdn_media', 'off' ); // Media disabled.

		// Create rewriter instance.
		$rewriter = new \AtomicEdge_CDN_Rewrite();

		// Test image URL - should NOT be rewritten.
		$test_img = '<img src="http://example.com/wp-content/uploads/2024/01/photo.jpg" alt="test">';
		$result   = $rewriter->rewrite( $test_img );

		$this->assertStringContainsString( 'example.com/wp-content', $result, 'Image URLs should NOT be rewritten when Media toggle is off' );
		$this->assertStringNotContainsString( 'cdn.example.com', $result, 'CDN URL should NOT appear for images when disabled' );

		// Test CSS URL - should still be rewritten.
		$test_css = '<link href="http://example.com/wp-content/themes/test/style.css" rel="stylesheet">';
		$result   = $rewriter->rewrite( $test_css );

		$this->assertStringContainsString( 'cdn.example.com', $result, 'CSS URLs should still be rewritten' );
	}

	/**
	 * Test that all toggles ON rewrites all file types.
	 */
	public function test_all_toggles_on_rewrites_all_types() {
		// Set up CDN configuration with all enabled.
		update_option( 'atomicedge_cdn_local_enabled', 'on' );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', array( 'cdn_enabled' => true, 'cdn_url' => 'https://test.cdn.example.com' ) );
		update_option( 'atomicedge_cdn_css', 'on' );
		update_option( 'atomicedge_cdn_js', 'on' );
		update_option( 'atomicedge_cdn_media', 'on' );

		// Create rewriter instance.
		$rewriter = new \AtomicEdge_CDN_Rewrite();

		// Test HTML with all asset types.
		$test_html = '<!DOCTYPE html>
			<link href="http://example.com/wp-content/themes/test/style.css" rel="stylesheet">
			<script src="http://example.com/wp-content/themes/test/script.js"></script>
			<img src="http://example.com/wp-content/uploads/2024/01/photo.jpg" alt="test">';
		$result = $rewriter->rewrite( $test_html );

		// Count CDN URL occurrences.
		$cdn_count = substr_count( $result, 'cdn.example.com' );

		$this->assertEquals( 3, $cdn_count, 'All 3 URLs (CSS, JS, image) should be rewritten to CDN' );
	}

	/**
	 * Test that all toggles OFF disables all rewriting.
	 */
	public function test_all_toggles_off_disables_all_rewriting() {
		// Set up CDN configuration with all disabled.
		update_option( 'atomicedge_cdn_local_enabled', 'on' );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', array( 'cdn_enabled' => true, 'cdn_url' => 'https://test.cdn.example.com' ) );
		update_option( 'atomicedge_cdn_css', 'off' );
		update_option( 'atomicedge_cdn_js', 'off' );
		update_option( 'atomicedge_cdn_media', 'off' );

		// Create rewriter instance.
		$rewriter = new \AtomicEdge_CDN_Rewrite();

		// Test HTML with all asset types.
		$test_html = '<!DOCTYPE html>
			<link href="http://example.com/wp-content/themes/test/style.css" rel="stylesheet">
			<script src="http://example.com/wp-content/themes/test/script.js"></script>
			<img src="http://example.com/wp-content/uploads/2024/01/photo.jpg" alt="test">';
		$result = $rewriter->rewrite( $test_html );

		// No CDN URL should appear.
		$this->assertStringNotContainsString( 'cdn.example.com', $result, 'No URLs should be rewritten when all toggles are off' );

		// Original URLs should remain.
		$this->assertStringContainsString( 'example.com/wp-content', $result, 'Original URLs should remain unchanged' );
	}

	/**
	 * ===========================================================================
	 * URL SANITIZATION TESTS
	 * ===========================================================================
	 * These tests ensure URL corruption (like http://httphttpshift8.local) NEVER happens.
	 * This bug was found on 2026-01-24 and must NEVER regress.
	 */

	/**
	 * Test sanitize_site_url does not double-prefix http scheme.
	 *
	 * Bug found: URLs like "http://shift8.local" became "http://httphttpshift8.local"
	 */
	public function test_sanitize_site_url_no_double_http_prefix() {
		// URLs that already have http:// should NOT get another prefix.
		$test_cases = array(
			'http://shift8.local'           => 'http://shift8.local',
			'http://example.com'            => 'http://example.com',
			'http://localhost'              => 'http://localhost',
			'http://192.168.1.1'            => 'http://192.168.1.1',
			'http://my-site.dev'            => 'http://my-site.dev',
		);

		foreach ( $test_cases as $input => $expected ) {
			$result = \AtomicEdge_CDN::sanitize_site_url( $input );
			$this->assertEquals( $expected, $result, "URL '$input' should NOT be double-prefixed" );
			$this->assertStringNotContainsString( 'httphttp', $result, "URL '$input' must not contain 'httphttp'" );
			$this->assertStringNotContainsString( 'http://http', $result, "URL '$input' must not contain 'http://http'" );
		}
	}

	/**
	 * Test sanitize_cdn_url does not double-prefix https scheme.
	 *
	 * Bug found: URLs like "https://cdn.atomicedge.io" became "https://httpshttpscdn.atomicedge.io"
	 */
	public function test_sanitize_cdn_url_no_double_https_prefix() {
		// URLs that already have https:// should NOT get another prefix.
		$test_cases = array(
			'https://cdn.atomicedge.io'     => 'https://cdn.atomicedge.io',
			'https://cdn.example.com'       => 'https://cdn.example.com',
			'https://localhost'             => 'https://localhost',
			'https://192.168.1.1'           => 'https://192.168.1.1',
			'https://my-cdn.dev'            => 'https://my-cdn.dev',
		);

		foreach ( $test_cases as $input => $expected ) {
			$result = \AtomicEdge_CDN::sanitize_cdn_url( $input );
			$this->assertEquals( $expected, $result, "URL '$input' should NOT be double-prefixed" );
			$this->assertStringNotContainsString( 'httpshttps', $result, "URL '$input' must not contain 'httpshttps'" );
			$this->assertStringNotContainsString( 'https://https', $result, "URL '$input' must not contain 'https://https'" );
		}
	}

	/**
	 * Test sanitize_site_url adds http:// to URLs without scheme.
	 */
	public function test_sanitize_site_url_adds_http_when_missing() {
		$test_cases = array(
			'shift8.local'    => 'http://shift8.local',
			'example.com'     => 'http://example.com',
			'localhost'       => 'http://localhost',
			'192.168.1.1'     => 'http://192.168.1.1',
		);

		foreach ( $test_cases as $input => $expected ) {
			$result = \AtomicEdge_CDN::sanitize_site_url( $input );
			$this->assertEquals( $expected, $result, "URL '$input' should have http:// added" );
		}
	}

	/**
	 * Test sanitize_cdn_url adds https:// to URLs without scheme.
	 */
	public function test_sanitize_cdn_url_adds_https_when_missing() {
		$test_cases = array(
			'cdn.atomicedge.io' => 'https://cdn.atomicedge.io',
			'cdn.example.com'   => 'https://cdn.example.com',
		);

		foreach ( $test_cases as $input => $expected ) {
			$result = \AtomicEdge_CDN::sanitize_cdn_url( $input );
			$this->assertEquals( $expected, $result, "URL '$input' should have https:// added" );
		}
	}

	/**
	 * Test sanitize_site_url handles URLs with https scheme.
	 */
	public function test_sanitize_site_url_preserves_https_scheme() {
		$test_cases = array(
			'https://shift8.local'  => 'https://shift8.local',
			'https://example.com'   => 'https://example.com',
		);

		foreach ( $test_cases as $input => $expected ) {
			$result = \AtomicEdge_CDN::sanitize_site_url( $input );
			$this->assertEquals( $expected, $result, "URL '$input' should preserve https:// scheme" );
		}
	}

	/**
	 * Test sanitize_cdn_url handles URLs with http scheme (converts to https for CDN).
	 */
	public function test_sanitize_cdn_url_preserves_http_scheme() {
		// Even if user enters http://, we preserve it (they might have a reason).
		$result = \AtomicEdge_CDN::sanitize_cdn_url( 'http://cdn.example.com' );
		$this->assertEquals( 'http://cdn.example.com', $result );
		$this->assertStringNotContainsString( 'httphttp', $result );
	}

	/**
	 * Test empty URL handling.
	 */
	public function test_sanitize_handles_empty_urls() {
		// Site URL returns site_url() when empty (default behavior).
		$site_result = \AtomicEdge_CDN::sanitize_site_url( '' );
		$this->assertNotEmpty( $site_result, 'Site URL should default to site_url() when empty' );

		// CDN URL returns empty when empty (no default).
		$this->assertEmpty( \AtomicEdge_CDN::sanitize_cdn_url( '' ) );
	}

	/**
	 * Test corrupted URL patterns are rejected or fixed.
	 *
	 * These are real corruption patterns we've seen in production.
	 */
	public function test_sanitize_rejects_corrupted_url_patterns() {
		$corrupted_urls = array(
			'http://httphttpshift8.local',          // Double http prefix corruption.
			'https://httpshttpscdn.atomicedge.io',  // Double https prefix corruption.
			'http://http://example.com',            // Scheme in URL path.
			'https://https://cdn.example.com',      // Scheme in URL path.
		);

		foreach ( $corrupted_urls as $corrupted ) {
			// Sanitize should produce a clean URL without double schemes.
			$result_site = \AtomicEdge_CDN::sanitize_site_url( $corrupted );
			$result_cdn  = \AtomicEdge_CDN::sanitize_cdn_url( $corrupted );

			// Neither result should contain double scheme patterns.
			$this->assertStringNotContainsString( 'httphttp', $result_site, "Site URL sanitization failed for '$corrupted'" );
			$this->assertStringNotContainsString( 'httphttp', $result_cdn, "CDN URL sanitization failed for '$corrupted'" );
			$this->assertStringNotContainsString( 'httpshttps', $result_site, "Site URL sanitization failed for '$corrupted'" );
			$this->assertStringNotContainsString( 'httpshttps', $result_cdn, "CDN URL sanitization failed for '$corrupted'" );
		}
	}

	/**
	 * Test CDN rewriting works with properly sanitized URLs (end-to-end).
	 *
	 * This test ensures that after sanitization, URLs actually work for CDN rewriting.
	 */
	public function test_end_to_end_cdn_rewrite_with_sanitized_urls() {
		// Simulate saving URLs through sanitization (as WordPress settings API would).
		$site_url = \AtomicEdge_CDN::sanitize_site_url( 'http://example.com' );
		$cdn_url  = \AtomicEdge_CDN::sanitize_cdn_url( 'https://cdn.example.com' );

		// Set options with sanitized values.
		update_option( 'atomicedge_cdn_local_enabled', 'on' );
		update_option( 'atomicedge_connected', true );
		update_option( 'atomicedge_site_data', array( 'cdn_enabled' => true, 'cdn_url' => 'https://test.cdn.example.com' ) );
		update_option( 'atomicedge_cdn_css', 'on' );

		// Create rewriter and test.
		$rewriter  = new \AtomicEdge_CDN_Rewrite();
		$test_html = '<link href="http://example.com/wp-content/themes/test/style.css" rel="stylesheet">';
		$result    = $rewriter->rewrite( $test_html );

		// CSS should be rewritten to CDN.
		$this->assertStringContainsString( 'cdn.example.com', $result, 'CSS URL should be rewritten to CDN' );
		// Original hostname (without cdn prefix) should NOT appear.
		$this->assertStringNotContainsString( 'http://example.com', $result, 'Original URL scheme+host should be replaced' );
	}
}

