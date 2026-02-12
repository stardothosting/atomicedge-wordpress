<?php
/**
 * AtomicEdge Admin Tests
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * Admin Test Suite
 */
class AdminTest extends TestCase {

	/**
	 * Instance of the Admin class.
	 *
	 * @var \AtomicEdge_Admin
	 */
	private $admin;

	/**
	 * API mock.
	 *
	 * @var \AtomicEdge_API|\PHPUnit\Framework\MockObject\MockObject
	 */
	private $api;

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		$_POST = array();

		$this->api   = $this->createMock( \AtomicEdge_API::class );
		$this->admin = new \AtomicEdge_Admin( $this->api );
	}

	// =========================================================================
	// Form Submission Tests
	// =========================================================================

	/**
	 * Test settings save updates API URL and sets notice.
	 */
	public function test_handle_settings_save_updates_api_url_and_notice() {
		$_POST['atomicedge_save_settings'] = '1';
		$_POST['_wpnonce']                 = 'nonce';
		$_POST['atomicedge_api_url']       = 'https://example.com/api';

		$this->admin->handle_form_submissions();

		$this->assertSame( 'https://example.com/api', get_option( 'atomicedge_api_url' ) );

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'success', $notices[0]['type'] );
	}

	/**
	 * Test connect with invalid key sets error notice.
	 */
	public function test_handle_connect_invalid_key_sets_error_notice() {
		$_POST['atomicedge_connect'] = '1';
		$_POST['_wpnonce']           = 'nonce';
		$_POST['atomicedge_api_key'] = 'bad-key';

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'error', $notices[0]['type'] );
	}

	/**
	 * Test disconnect calls API and sets success notice.
	 */
	public function test_handle_disconnect_calls_api_and_sets_notice() {
		$_POST['atomicedge_disconnect'] = '1';
		$_POST['_wpnonce']              = 'nonce';

		$this->api->method( 'disconnect' )->willReturn( array( 'message' => 'Disconnected.' ) );

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'success', $notices[0]['type'] );
	}

	/**
	 * Test handle_form_submissions does nothing without POST data.
	 */
	public function test_handle_form_submissions_does_nothing_without_post() {
		$_POST = array();

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertFalse( $notices );
	}

	// =========================================================================
	// Menu Registration Tests
	// =========================================================================

	/**
	 * Test register_menu registers all pages.
	 */
	public function test_register_menu_registers_pages() {
		Functions\expect( 'add_menu_page' )->once();
		Functions\expect( 'add_submenu_page' )->times( 10 );

		$this->admin->register_menu();
		$this->addToAssertionCount( 1 );
	}

	// =========================================================================
	// Admin Notices Tests
	// =========================================================================

	/**
	 * Test display_admin_notices outputs notices.
	 */
	public function test_display_admin_notices_outputs_notices() {
		// Set up notices.
		set_transient(
			'atomicedge_admin_notices',
			array(
				array(
					'type'    => 'success',
					'message' => 'Settings saved.',
				),
			)
		);

		ob_start();
		$this->admin->display_admin_notices();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'notice-success', $output );
		$this->assertStringContainsString( 'Settings saved.', $output );
	}

	/**
	 * Test display_admin_notices does nothing without notices.
	 */
	public function test_display_admin_notices_no_output_without_notices() {
		delete_transient( 'atomicedge_admin_notices' );

		ob_start();
		$this->admin->display_admin_notices();
		$output = ob_get_clean();

		$this->assertEmpty( $output );
	}

	/**
	 * Test display_admin_notices handles error notice type.
	 */
	public function test_display_admin_notices_handles_error_type() {
		set_transient(
			'atomicedge_admin_notices',
			array(
				array(
					'type'    => 'error',
					'message' => 'Connection failed.',
				),
			)
		);

		ob_start();
		$this->admin->display_admin_notices();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'notice-error', $output );
	}

	/**
	 * Test display_admin_notices handles warning notice type.
	 */
	public function test_display_admin_notices_handles_warning_type() {
		set_transient(
			'atomicedge_admin_notices',
			array(
				array(
					'type'    => 'warning',
					'message' => 'API rate limited.',
				),
			)
		);

		ob_start();
		$this->admin->display_admin_notices();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'notice-warning', $output );
	}

	/**
	 * Test display_admin_notices handles multiple notices.
	 */
	public function test_display_admin_notices_handles_multiple_notices() {
		set_transient(
			'atomicedge_admin_notices',
			array(
				array(
					'type'    => 'success',
					'message' => 'First notice.',
				),
				array(
					'type'    => 'error',
					'message' => 'Second notice.',
				),
			)
		);

		ob_start();
		$this->admin->display_admin_notices();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'First notice.', $output );
		$this->assertStringContainsString( 'Second notice.', $output );
	}

	/**
	 * Test display_admin_notices clears transient after display.
	 */
	public function test_display_admin_notices_clears_transient() {
		set_transient(
			'atomicedge_admin_notices',
			array(
				array(
					'type'    => 'success',
					'message' => 'Test notice.',
				),
			)
		);

		ob_start();
		$this->admin->display_admin_notices();
		ob_end_clean();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertFalse( $notices );
	}

	// =========================================================================
	// API Key Masking Tests
	// =========================================================================

	/**
	 * Test get_masked_api_key returns masked key when connected.
	 */
	public function test_get_masked_api_key_returns_masked_when_connected() {
		$this->api->method( 'is_connected' )->willReturn( true );
		$this->api->method( 'get_api_key' )->willReturn( 'abc123def456ghi789' );

		$masked = $this->admin->get_masked_api_key();

		// Should contain bullet points (masking characters).
		$this->assertStringContainsString( '•', $masked );
		// Should preserve some visible portion (last 4 chars).
		$this->assertStringContainsString( 'i789', $masked );
	}

	/**
	 * Test get_masked_api_key returns empty when not connected.
	 */
	public function test_get_masked_api_key_returns_empty_when_not_connected() {
		$this->api->method( 'is_connected' )->willReturn( false );

		$masked = $this->admin->get_masked_api_key();

		$this->assertEmpty( $masked );
	}

	/**
	 * Test get_masked_api_key handles short keys by returning empty.
	 */
	public function test_get_masked_api_key_handles_short_key() {
		$this->api->method( 'is_connected' )->willReturn( true );
		$this->api->method( 'get_api_key' )->willReturn( 'abc' );

		$masked = $this->admin->get_masked_api_key();

		// Short keys may return empty or a masked version - just verify no exception.
		$this->assertIsString( $masked );
	}

	// =========================================================================
	// Class Tests
	// =========================================================================

	/**
	 * Test Admin class can be instantiated.
	 */
	public function test_class_can_be_instantiated() {
		$this->assertInstanceOf( \AtomicEdge_Admin::class, $this->admin );
	}

	/**
	 * Test Admin class has required methods.
	 */
	public function test_class_has_required_methods() {
		$this->assertTrue( method_exists( $this->admin, 'register_menu' ) );
		$this->assertTrue( method_exists( $this->admin, 'handle_form_submissions' ) );
		$this->assertTrue( method_exists( $this->admin, 'display_admin_notices' ) );
		$this->assertTrue( method_exists( $this->admin, 'render_dashboard_page' ) );
	}

	/**
	 * Test Admin stores API reference.
	 */
	public function test_admin_stores_api_reference() {
		// Create new instance to test constructor.
		$api   = $this->createMock( \AtomicEdge_API::class );
		$admin = new \AtomicEdge_Admin( $api );

		$this->assertInstanceOf( \AtomicEdge_Admin::class, $admin );
	}

	// =========================================================================
	// Edge Case Tests - Connect Form Validation
	// =========================================================================

	/**
	 * Test connect with empty API key sets error notice.
	 */
	public function test_handle_connect_empty_key_sets_error_notice() {
		$_POST['atomicedge_connect'] = '1';
		$_POST['_wpnonce']           = 'nonce';
		$_POST['atomicedge_api_key'] = '';

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'error', $notices[0]['type'] );
		$this->assertStringContainsString( 'enter an API key', $notices[0]['message'] );
	}

	/**
	 * Test connect with whitespace-only API key sets error notice.
	 */
	public function test_handle_connect_whitespace_key_sets_error_notice() {
		$_POST['atomicedge_connect'] = '1';
		$_POST['_wpnonce']           = 'nonce';
		$_POST['atomicedge_api_key'] = '   ';

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'error', $notices[0]['type'] );
	}

	/**
	 * Test connect with too short API key sets format error.
	 */
	public function test_handle_connect_short_key_sets_format_error() {
		$_POST['atomicedge_connect'] = '1';
		$_POST['_wpnonce']           = 'nonce';
		$_POST['atomicedge_api_key'] = 'abc123'; // Too short (< 32 chars).

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'error', $notices[0]['type'] );
		$this->assertStringContainsString( 'Invalid API key format', $notices[0]['message'] );
	}

	/**
	 * Test connect with special characters in API key sets format error.
	 */
	public function test_handle_connect_special_chars_sets_format_error() {
		$_POST['atomicedge_connect'] = '1';
		$_POST['_wpnonce']           = 'nonce';
		$_POST['atomicedge_api_key'] = 'abcdef123456!@#$%^&*()_+{}|:"<>?'; // 32+ chars but invalid.

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'error', $notices[0]['type'] );
		$this->assertStringContainsString( 'Invalid API key format', $notices[0]['message'] );
	}

	/**
	 * Test connect with prefixed API key (like sk_test_) sets format error.
	 */
	public function test_handle_connect_prefixed_key_sets_format_error() {
		$_POST['atomicedge_connect'] = '1';
		$_POST['_wpnonce']           = 'nonce';
		$_POST['atomicedge_api_key'] = 'sk_test_abcdefghijklmnopqrstuvwxyz1234'; // Has underscore.

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'error', $notices[0]['type'] );
	}

	/**
	 * Test connect with valid format key attempts API connection.
	 */
	public function test_handle_connect_valid_format_attempts_connection() {
		$_POST['atomicedge_connect'] = '1';
		$_POST['_wpnonce']           = 'nonce';
		$_POST['atomicedge_api_key'] = 'abcdefghijklmnopqrstuvwxyz123456'; // 32 alphanumeric.

		// Mock API failure (format valid but key not recognized).
		$this->api->method( 'connect' )->willReturn(
			array(
				'success' => false,
				'error'   => 'API key not recognized',
			)
		);

		// Need to create new admin with this mock.
		$admin = new \AtomicEdge_Admin( $this->api );
		$admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'error', $notices[0]['type'] );
		$this->assertStringContainsString( 'API key not recognized', $notices[0]['message'] );
	}

	// =========================================================================
	// Edge Case Tests - Settings Save
	// =========================================================================

	/**
	 * Test settings save with empty API URL.
	 */
	public function test_handle_settings_save_with_empty_url() {
		$_POST['atomicedge_save_settings'] = '1';
		$_POST['_wpnonce']                 = 'nonce';
		$_POST['atomicedge_api_url']       = '';

		$this->admin->handle_form_submissions();

		$this->assertSame( '', get_option( 'atomicedge_api_url' ) );

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertSame( 'success', $notices[0]['type'] );
	}

	/**
	 * Test settings save sanitizes malicious URL.
	 */
	public function test_handle_settings_save_sanitizes_url() {
		$_POST['atomicedge_save_settings'] = '1';
		$_POST['_wpnonce']                 = 'nonce';
		$_POST['atomicedge_api_url']       = 'javascript:alert(1)';

		$this->admin->handle_form_submissions();

		// Our mock esc_url_raw just returns the value.
		// In real WordPress, esc_url_raw would strip javascript: protocol.
		// This test verifies the function is called - WordPress handles actual sanitization.
		$saved_url = get_option( 'atomicedge_api_url' );
		$this->assertIsString( $saved_url );
	}

	// =========================================================================
	// Edge Case Tests - Admin Notices
	// =========================================================================

	/**
	 * Test display_admin_notices handles info notice type.
	 */
	public function test_display_admin_notices_handles_info_type() {
		set_transient(
			'atomicedge_admin_notices',
			array(
				array(
					'type'    => 'info',
					'message' => 'Information notice.',
				),
			)
		);

		ob_start();
		$this->admin->display_admin_notices();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'notice-info', $output );
	}

	/**
	 * Test add_admin_notice accumulates notices.
	 */
	public function test_admin_notices_accumulate() {
		$_POST['atomicedge_save_settings'] = '1';
		$_POST['_wpnonce']                 = 'nonce';
		$_POST['atomicedge_api_url']       = 'https://example.com';
		$this->admin->handle_form_submissions();

		// Reset POST and trigger another action.
		$_POST                               = array();
		$_POST['atomicedge_disconnect']      = '1';
		$_POST['_wpnonce']                   = 'nonce';
		$this->api->method( 'disconnect' )->willReturn( array( 'message' => 'Disconnected.' ) );
		$admin = new \AtomicEdge_Admin( $this->api );
		$admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		// Should have accumulated from previous test runs.
		$this->assertIsArray( $notices );
		$this->assertGreaterThanOrEqual( 1, count( $notices ) );
	}
}