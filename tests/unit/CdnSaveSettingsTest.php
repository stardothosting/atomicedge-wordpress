<?php
/**
 * CDN Save Settings Tests
 *
 * Regression tests for ajax_save_cdn_settings tab-awareness.
 *
 * Bug 2026-07: Saving from the Minification or Advanced tab on the CDN page
 * would set atomicedge_cdn_local_enabled to 'off' because the handler wasn't
 * tab-aware — it processed ALL settings regardless of which tab was active.
 * Fixed by reading the hidden `atomicedge_cdn_tab` field and only saving the
 * active tab's settings.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * CDN Save Settings AJAX Test Suite
 *
 * @covers \AtomicEdge_Ajax::ajax_save_cdn_settings
 */
class CdnSaveSettingsTest extends TestCase {

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

	protected function set_up() {
		parent::set_up();

		$_POST    = array();
		$_GET     = array();
		$_REQUEST = array();

		// Provide a valid nonce by default.
		$_POST['nonce'] = 'valid-nonce';

		$this->json_response      = null;
		$this->json_response_type = null;

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

		// Mock sanitize_textarea_field (used in advanced tab).
		Functions\when( 'sanitize_textarea_field' )->alias(
			function ( $str ) {
				return strip_tags( $str );
			}
		);

		$mock_api   = $this->createMock( \AtomicEdge_API::class );
		$this->ajax = new \AtomicEdge_Ajax( $mock_api );
	}

	/**
	 * Build serialized form data for the CDN settings form.
	 *
	 * @param array $fields Key-value pairs to include in the form data.
	 * @return string URL-encoded form data string.
	 */
	private function build_form_data( array $fields ): string {
		// Always include the CDN nonce.
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
	// General Tab Tests
	// =========================================================================

	/**
	 * Test saving from the General tab with CDN enabled sets the option to 'on'.
	 */
	public function test_general_tab_saves_cdn_enabled_on() {
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab'           => 'general',
			'atomicedge_cdn_local_enabled' => 'on',
			'atomicedge_cdn_css'           => 'on',
			'atomicedge_cdn_js'            => 'on',
			'atomicedge_cdn_media'         => 'on',
		) ) );

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_local_enabled' ) );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_css' ) );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_js' ) );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_media' ) );
	}

	/**
	 * Test saving from the General tab with CDN disabled sets the option to 'off'.
	 */
	public function test_general_tab_saves_cdn_enabled_off() {
		// Pre-set CDN as enabled.
		$this->set_option( 'atomicedge_cdn_local_enabled', 'on' );

		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab' => 'general',
			// Checkbox absent = unchecked = disabled.
		) ) );

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertSame( 'off', get_option( 'atomicedge_cdn_local_enabled' ) );
	}

	// =========================================================================
	// Tab Isolation Tests (CRITICAL REGRESSION)
	// =========================================================================

	/**
	 * Regression: Saving from the Minification tab must NOT change CDN enable state.
	 *
	 * This is the exact customer-reported bug — CDN was turned on, user saved
	 * minification settings, and CDN was disabled on next refresh.
	 */
	public function test_minification_tab_does_not_change_cdn_enabled() {
		// CDN is enabled by the user.
		$this->set_option( 'atomicedge_cdn_local_enabled', 'on' );
		$this->set_option( 'atomicedge_cdn_css', 'on' );
		$this->set_option( 'atomicedge_cdn_js', 'on' );
		$this->set_option( 'atomicedge_cdn_media', 'on' );

		// Save from minification tab — no cdn_local_enabled field present.
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab'        => 'minification',
			'atomicedge_cdn_minify_css' => 'on',
			'atomicedge_cdn_minify_js'  => 'on',
		) ) );

		$this->assertSame( 'success', $this->json_response_type );

		// CDN enable state MUST be unchanged.
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_local_enabled' ), 'Minification tab save disabled CDN!' );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_css' ), 'Minification tab save changed CDN CSS!' );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_js' ), 'Minification tab save changed CDN JS!' );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_media' ), 'Minification tab save changed CDN media!' );

		// Minification settings should be saved.
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_minify_css' ) );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_minify_js' ) );
	}

	/**
	 * Regression: Saving from the Advanced tab must NOT change CDN enable state.
	 */
	public function test_advanced_tab_does_not_change_cdn_enabled() {
		// CDN is enabled by the user.
		$this->set_option( 'atomicedge_cdn_local_enabled', 'on' );

		// Save from advanced tab.
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab'          => 'advanced',
			'atomicedge_cdn_dns_prefetch' => 'on',
			'atomicedge_cdn_reject_files' => 'wp-admin',
		) ) );

		$this->assertSame( 'success', $this->json_response_type );

		// CDN enable state MUST be unchanged.
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_local_enabled' ), 'Advanced tab save disabled CDN!' );

		// Advanced settings should be saved.
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_dns_prefetch' ) );
		$this->assertSame( 'wp-admin', get_option( 'atomicedge_cdn_reject_files' ) );
	}

	/**
	 * Regression: Saving minification tab must NOT change general or advanced settings.
	 */
	public function test_minification_tab_only_saves_minification_options() {
		// Pre-set all tabs' options.
		$this->set_option( 'atomicedge_cdn_local_enabled', 'on' );
		$this->set_option( 'atomicedge_cdn_css', 'on' );
		$this->set_option( 'atomicedge_cdn_dns_prefetch', 'on' );
		$this->set_option( 'atomicedge_cdn_reject_files', 'wp-admin' );

		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab'         => 'minification',
			'atomicedge_cdn_minify_css'  => 'on',
			'atomicedge_cdn_minify_js'   => 'off',
			'atomicedge_cdn_minify_html' => 'on',
		) ) );

		$this->assertSame( 'success', $this->json_response_type );

		// General tab settings preserved.
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_local_enabled' ) );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_css' ) );

		// Advanced tab settings preserved.
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_dns_prefetch' ) );
		$this->assertSame( 'wp-admin', get_option( 'atomicedge_cdn_reject_files' ) );
	}

	/**
	 * Regression: Saving general tab must NOT change minification or advanced settings.
	 */
	public function test_general_tab_only_saves_general_options() {
		// Pre-set minification and advanced options.
		$this->set_option( 'atomicedge_cdn_minify_css', 'on' );
		$this->set_option( 'atomicedge_cdn_minify_js', 'on' );
		$this->set_option( 'atomicedge_cdn_dns_prefetch', 'on' );

		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab'           => 'general',
			'atomicedge_cdn_local_enabled' => 'on',
		) ) );

		$this->assertSame( 'success', $this->json_response_type );

		// Minification settings preserved.
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_minify_css' ) );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_minify_js' ) );

		// Advanced settings preserved.
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_dns_prefetch' ) );
	}

	// =========================================================================
	// Default Tab Behavior
	// =========================================================================

	/**
	 * Test that missing atomicedge_cdn_tab defaults to 'general' tab behavior.
	 */
	public function test_missing_tab_field_defaults_to_general() {
		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_local_enabled' => 'on',
			'atomicedge_cdn_css'           => 'on',
			// Note: no atomicedge_cdn_tab field.
		) ) );

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_local_enabled' ) );
		$this->assertSame( 'on', get_option( 'atomicedge_cdn_css' ) );
	}

	// =========================================================================
	// Edge Cases
	// =========================================================================

	/**
	 * Test saving minification tab with all options off.
	 */
	public function test_minification_tab_all_off() {
		$this->set_option( 'atomicedge_cdn_minify_css', 'on' );
		$this->set_option( 'atomicedge_cdn_minify_js', 'on' );
		$this->set_option( 'atomicedge_cdn_minify_html', 'on' );

		$this->call_save( $this->build_form_data( array(
			'atomicedge_cdn_tab' => 'minification',
			// No minify checkboxes = all unchecked.
		) ) );

		$this->assertSame( 'success', $this->json_response_type );
		$this->assertSame( 'off', get_option( 'atomicedge_cdn_minify_css' ) );
		$this->assertSame( 'off', get_option( 'atomicedge_cdn_minify_js' ) );
		$this->assertSame( 'off', get_option( 'atomicedge_cdn_minify_html' ) );
	}

	/**
	 * Test saving returns error when no form data provided.
	 */
	public function test_save_with_no_form_data_returns_error() {
		// Empty formData.
		$_POST['formData'] = '';

		try {
			$this->ajax->ajax_save_cdn_settings();
		} catch ( \AtomicEdge\Tests\AjaxExitException $e ) {
			// Expected.
		}

		$this->assertSame( 'error', $this->json_response_type );
	}
}
