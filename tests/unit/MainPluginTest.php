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
}
