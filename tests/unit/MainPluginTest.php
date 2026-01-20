<?php
/**
 * AtomicEdge Main Plugin Class Tests
 *
 * Tests for the main AtomicEdge class including singleton pattern,
 * component initialization, and hooks.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * Main Plugin Class Test Suite
 */
class MainPluginTest extends TestCase {

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		// Reset singleton for testing.
		$reflection = new \ReflectionClass( \AtomicEdge::class );
		$instance   = $reflection->getProperty( 'instance' );
		$instance->setAccessible( true );
		$instance->setValue( null, null );

		// Mock additional WordPress functions.
		Functions\when( 'wp_enqueue_script' )->justReturn( true );
		Functions\when( 'wp_enqueue_style' )->justReturn( true );
		Functions\when( 'wp_localize_script' )->justReturn( true );
	}

	// =========================================================================
	// Singleton Pattern Tests
	// =========================================================================

	/**
	 * Test get_instance returns singleton.
	 */
	public function test_get_instance_returns_singleton() {
		$instance1 = \AtomicEdge::get_instance();
		$instance2 = \AtomicEdge::get_instance();

		$this->assertSame( $instance1, $instance2 );
	}

	/**
	 * Test instance is correct type.
	 */
	public function test_instance_is_correct_type() {
		$instance = \AtomicEdge::get_instance();

		$this->assertInstanceOf( \AtomicEdge::class, $instance );
	}

	/**
	 * Test wakeup throws exception.
	 */
	public function test_wakeup_throws_exception() {
		$this->expectException( \Exception::class );

		$instance   = \AtomicEdge::get_instance();
		$serialized = serialize( $instance );
		unserialize( $serialized );
	}

	// =========================================================================
	// Component Initialization Tests
	// =========================================================================

	/**
	 * Test API component is initialized.
	 */
	public function test_api_component_initialized() {
		$instance = \AtomicEdge::get_instance();

		$this->assertInstanceOf( \AtomicEdge_API::class, $instance->api );
	}

	/**
	 * Test Admin component is initialized.
	 */
	public function test_admin_component_initialized() {
		$instance = \AtomicEdge::get_instance();

		$this->assertInstanceOf( \AtomicEdge_Admin::class, $instance->admin );
	}

	/**
	 * Test AJAX component is initialized.
	 */
	public function test_ajax_component_initialized() {
		$instance = \AtomicEdge::get_instance();

		$this->assertInstanceOf( \AtomicEdge_Ajax::class, $instance->ajax );
	}

	/**
	 * Test Scanner component is initialized.
	 */
	public function test_scanner_component_initialized() {
		$instance = \AtomicEdge::get_instance();

		$this->assertInstanceOf( \AtomicEdge_Scanner::class, $instance->scanner );
	}

	/**
	 * Test Cron component is initialized.
	 */
	public function test_cron_component_initialized() {
		$instance = \AtomicEdge::get_instance();

		$this->assertInstanceOf( \AtomicEdge_Cron::class, $instance->cron );
	}

	// =========================================================================
	// Logging Tests
	// =========================================================================

	/**
	 * Test log method does not throw with debug disabled.
	 */
	public function test_log_does_not_throw_with_debug_disabled() {
		// WP_DEBUG is defined as true in bootstrap, but log should handle it.
		\AtomicEdge::log( 'Test message', array( 'data' => 'value' ) );

		// If we get here without exception, test passes.
		$this->assertTrue( true );
	}

	/**
	 * Test log method accepts string message.
	 */
	public function test_log_accepts_string_message() {
		\AtomicEdge::log( 'Simple string message' );

		$this->assertTrue( true );
	}

	/**
	 * Test log method accepts array context.
	 */
	public function test_log_accepts_array_context() {
		\AtomicEdge::log(
			'Message with context',
			array(
				'key1' => 'value1',
				'key2' => 123,
			)
		);

		$this->assertTrue( true );
	}

	// =========================================================================
	// Asset Enqueue Tests
	// =========================================================================

	/**
	 * Test enqueue_admin_assets loads on main plugin page.
	 *
	 * WordPress generates hooks using sanitize_title($menu_title).
	 * For menu title "Atomic Edge", this yields "atomic-edge".
	 */
	public function test_enqueue_admin_assets_loads_on_main_page() {
		// Reset singleton to get clean instance.
		$reflection = new \ReflectionClass( \AtomicEdge::class );
		$prop       = $reflection->getProperty( 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );

		$instance = \AtomicEdge::get_instance();

		// Mock additional functions needed for localize_script.
		Functions\when( 'admin_url' )->justReturn( 'http://example.com/wp-admin/admin-ajax.php' );
		Functions\when( 'wp_create_nonce' )->justReturn( 'test_nonce' );

		// Track if enqueue was called.
		$enqueue_called = false;
		Functions\when( 'wp_enqueue_script' )->alias(
			function () use ( &$enqueue_called ) {
				$enqueue_called = true;
				return true;
			}
		);
		Functions\when( 'wp_enqueue_style' )->justReturn( true );
		Functions\when( 'wp_localize_script' )->justReturn( true );

		// Main page hook: toplevel_page_atomic-edge-security
		$instance->enqueue_admin_assets( 'toplevel_page_atomic-edge-security' );

		$this->assertTrue( $enqueue_called, 'Assets should be enqueued on main plugin page' );
	}

	/**
	 * Test enqueue_admin_assets loads on submenu pages.
	 *
	 * Submenu hooks use the pattern: {sanitized_parent_title}_page_{submenu_slug}
	 * For parent "Atomic Edge" -> "atomic-edge", submenu "atomicedge-scanner"
	 * Hook would be: atomic-edge_page_atomicedge-scanner
	 */
	public function test_enqueue_admin_assets_loads_on_scanner_page() {
		// Reset singleton to get clean instance.
		$reflection = new \ReflectionClass( \AtomicEdge::class );
		$prop       = $reflection->getProperty( 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );

		$instance = \AtomicEdge::get_instance();

		// Mock additional functions needed for localize_script.
		Functions\when( 'admin_url' )->justReturn( 'http://example.com/wp-admin/admin-ajax.php' );
		Functions\when( 'wp_create_nonce' )->justReturn( 'test_nonce' );

		// Track if enqueue was called.
		$enqueue_called = false;
		Functions\when( 'wp_enqueue_script' )->alias(
			function () use ( &$enqueue_called ) {
				$enqueue_called = true;
				return true;
			}
		);
		Functions\when( 'wp_enqueue_style' )->justReturn( true );
		Functions\when( 'wp_localize_script' )->justReturn( true );

		// Scanner page hook
		$instance->enqueue_admin_assets( 'atomic-edge_page_atomicedge-scanner' );

		$this->assertTrue( $enqueue_called, 'Assets should be enqueued on scanner page' );
	}

	/**
	 * Test enqueue_admin_assets loads on vulnerability scanner page.
	 */
	public function test_enqueue_admin_assets_loads_on_vulnerability_page() {
		// Reset singleton to get clean instance.
		$reflection = new \ReflectionClass( \AtomicEdge::class );
		$prop       = $reflection->getProperty( 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );

		$instance = \AtomicEdge::get_instance();

		// Mock additional functions needed for localize_script.
		Functions\when( 'admin_url' )->justReturn( 'http://example.com/wp-admin/admin-ajax.php' );
		Functions\when( 'wp_create_nonce' )->justReturn( 'test_nonce' );

		// Track if enqueue was called.
		$enqueue_called = false;
		Functions\when( 'wp_enqueue_script' )->alias(
			function () use ( &$enqueue_called ) {
				$enqueue_called = true;
				return true;
			}
		);
		Functions\when( 'wp_enqueue_style' )->justReturn( true );
		Functions\when( 'wp_localize_script' )->justReturn( true );

		// Vulnerability scanner page hook
		$instance->enqueue_admin_assets( 'atomic-edge_page_atomicedge-vulnerabilities' );

		$this->assertTrue( $enqueue_called, 'Assets should be enqueued on vulnerability page' );
	}

	/**
	 * Test enqueue_admin_assets does NOT load on non-plugin pages.
	 */
	public function test_enqueue_admin_assets_skips_non_plugin_pages() {
		// Reset singleton to get clean instance.
		$reflection = new \ReflectionClass( \AtomicEdge::class );
		$prop       = $reflection->getProperty( 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );

		$instance = \AtomicEdge::get_instance();

		// Track if enqueue was called.
		$enqueue_called = false;
		Functions\when( 'wp_enqueue_script' )->alias(
			function () use ( &$enqueue_called ) {
				$enqueue_called = true;
				return true;
			}
		);
		Functions\when( 'wp_enqueue_style' )->alias(
			function () use ( &$enqueue_called ) {
				$enqueue_called = true;
				return true;
			}
		);
		Functions\when( 'wp_localize_script' )->justReturn( true );

		$instance->enqueue_admin_assets( 'plugins.php' );
		$instance->enqueue_admin_assets( 'options-general.php' );
		$instance->enqueue_admin_assets( 'post.php' );

		$this->assertFalse( $enqueue_called, 'Assets should NOT be enqueued on non-plugin pages' );
	}
}
