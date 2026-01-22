<?php
/**
 * AtomicEdge Admin Tests
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

class AdminTest extends TestCase {

	/**
	 * @var \AtomicEdge_Admin
	 */
	private $admin;

	/**
	 * @var \AtomicEdge_API|\PHPUnit\Framework\MockObject\MockObject
	 */
	private $api;

	protected function set_up() {
		parent::set_up();

		$_POST = array();

		$this->api = $this->createMock( \AtomicEdge_API::class );
		$this->admin = new \AtomicEdge_Admin( $this->api );
	}

	public function test_handle_settings_save_updates_api_url_and_notice() {
		$_POST['atomicedge_save_settings'] = '1';
		$_POST['_wpnonce'] = 'nonce';
		$_POST['atomicedge_api_url'] = 'https://example.com/api';

		$this->admin->handle_form_submissions();

		$this->assertSame( 'https://example.com/api', get_option( 'atomicedge_api_url' ) );

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'success', $notices[0]['type'] );
	}

	public function test_handle_connect_invalid_key_sets_error_notice() {
		$_POST['atomicedge_connect'] = '1';
		$_POST['_wpnonce'] = 'nonce';
		$_POST['atomicedge_api_key'] = 'bad-key';

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'error', $notices[0]['type'] );
	}

	public function test_handle_disconnect_calls_api_and_sets_notice() {
		$_POST['atomicedge_disconnect'] = '1';
		$_POST['_wpnonce'] = 'nonce';

		$this->api->method( 'disconnect' )->willReturn( array( 'message' => 'Disconnected.' ) );

		$this->admin->handle_form_submissions();

		$notices = get_transient( 'atomicedge_admin_notices' );
		$this->assertIsArray( $notices );
		$this->assertSame( 'success', $notices[0]['type'] );
	}

	public function test_register_menu_registers_pages() {
		Functions\expect( 'add_menu_page' )->once();
		Functions\expect( 'add_submenu_page' )->times( 9 ); // Dashboard, Analytics, WAF, Access, Scanner, Vuln Scanner, CDN, Settings, 2FA Policy

		$this->admin->register_menu();
		$this->addToAssertionCount( 1 );
	}
}
