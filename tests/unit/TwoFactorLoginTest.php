<?php
/**
 * AtomicEdge 2FA Login Flow Tests
 *
 * Tests for the AtomicEdge_2FA_Login class which handles login flow interception.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;
use Brain\Monkey\Filters;

/**
 * 2FA Login Flow Test Suite
 */
class TwoFactorLoginTest extends TestCase {

	/**
	 * Set up before each test.
	 *
	 * @return void
	 */
	protected function set_up() {
		parent::set_up();

		// Reset globals.
		$_REQUEST = array();
		$_POST    = array();
		$_GET     = array();

		// Mock common WordPress functions.
		Functions\when( 'did_action' )->justReturn( 1 );
		Functions\when( 'add_filter' )->justReturn( true );
		Functions\when( 'remove_filter' )->justReturn( true );
		Functions\when( 'wp_parse_auth_cookie' )->justReturn( array( 'token' => 'test_token' ) );
		Functions\when( 'wp_clear_auth_cookie' )->justReturn( true );
		Functions\when( 'admin_url' )->justReturn( 'http://example.com/wp-admin/' );
		Functions\when( 'sanitize_url' )->alias( function( $url ) { return filter_var( $url, FILTER_SANITIZE_URL ); } );

		// Mock get_user_meta with our test storage.
		Functions\when( 'get_user_meta' )->alias(
			function( $user_id, $key, $single = false ) {
				global $_test_user_meta;
				if ( isset( $_test_user_meta[ $user_id ][ $key ] ) ) {
					$value = $_test_user_meta[ $user_id ][ $key ];
					return $single ? $value : array( $value );
				}
				return $single ? '' : array();
			}
		);
	}

	// =========================================================================
	// Filter Authentication Tests
	// =========================================================================

	/**
	 * Test filter_authenticate_block_cookies returns non-WP_User unchanged.
	 */
	public function test_filter_authenticate_returns_error_unchanged() {
		$login = new \AtomicEdge_2FA_Login();

		$error  = new \WP_Error( 'invalid_password', 'Invalid password' );
		$result = $login->filter_authenticate_block_cookies( $error );

		$this->assertSame( $error, $result );
	}

	/**
	 * Test filter_authenticate_block_cookies returns null unchanged.
	 */
	public function test_filter_authenticate_returns_null_unchanged() {
		$login = new \AtomicEdge_2FA_Login();

		$result = $login->filter_authenticate_block_cookies( null );

		$this->assertNull( $result );
	}

	/**
	 * Test filter_authenticate_block_cookies returns user when not on login page.
	 */
	public function test_filter_authenticate_returns_user_when_not_login_page() {
		Functions\when( 'did_action' )->justReturn( 0 ); // login_init not fired.

		$login = new \AtomicEdge_2FA_Login();

		$user   = $this->create_mock_user( 1, 'testuser' );
		$result = $login->filter_authenticate_block_cookies( $user );

		$this->assertSame( $user, $result );
	}

	// =========================================================================
	// Attach Session Info Tests
	// =========================================================================

	/**
	 * Test attach_session_info adds 2FA marker for enabled users.
	 */
	public function test_attach_session_info_adds_marker_for_2fa_user() {
		$user_id = 1;

		// Mock 2FA as enabled (uses META_ENABLED constant).
		$this->set_user_meta( $user_id, '_atomicedge_2fa_enabled', true );

		$login = new \AtomicEdge_2FA_Login();

		$session_info = array( 'ip' => '127.0.0.1' );
		$result       = $login->attach_session_info( $session_info, $user_id );

		$this->assertArrayHasKey( 'atomicedge_2fa_verified', $result );
		$this->assertTrue( $result['atomicedge_2fa_verified'] );
		$this->assertEquals( '127.0.0.1', $result['ip'] );
	}

	/**
	 * Test attach_session_info does not add marker for non-2FA users.
	 */
	public function test_attach_session_info_no_marker_for_non_2fa_user() {
		$user_id = 1;

		// User has no 2FA setup.
		$this->clear_user_meta( $user_id, '_atomicedge_2fa_enabled' );

		$login = new \AtomicEdge_2FA_Login();

		$session_info = array( 'ip' => '127.0.0.1' );
		$result       = $login->attach_session_info( $session_info, $user_id );

		$this->assertArrayNotHasKey( 'atomicedge_2fa_verified', $result );
		$this->assertEquals( '127.0.0.1', $result['ip'] );
	}

	/**
	 * Test attach_session_info preserves existing session data.
	 */
	public function test_attach_session_info_preserves_existing_data() {
		$user_id = 1;

		// User has no 2FA.
		$this->clear_user_meta( $user_id, '_atomicedge_2fa_enabled' );

		$login = new \AtomicEdge_2FA_Login();

		$session_info = array(
			'ip'         => '127.0.0.1',
			'user_agent' => 'Mozilla/5.0',
			'login'      => time(),
		);
		$result = $login->attach_session_info( $session_info, $user_id );

		// All original data should be preserved.
		$this->assertEquals( '127.0.0.1', $result['ip'] );
		$this->assertEquals( 'Mozilla/5.0', $result['user_agent'] );
		$this->assertArrayHasKey( 'login', $result );
	}

	// =========================================================================
	// Handle 2FA Validation Tests
	// =========================================================================

	/**
	 * Test handle_2fa_validation redirects when missing user_id.
	 *
	 * Note: The production code calls `exit` after `wp_safe_redirect()`.
	 * To test this safely, we mock `wp_safe_redirect` to throw an exception,
	 * simulating the program flow interruption that `exit` would cause.
	 */
	public function test_handle_2fa_validation_redirects_on_missing_user_id() {
		$login = new \AtomicEdge_2FA_Login();

		// Missing wp-auth-id.
		$_POST = array(
			'wp-auth-nonce' => 'test_nonce',
		);

		$redirect_url = null;
		Functions\when( 'wp_safe_redirect' )->alias(
			function( $url ) use ( &$redirect_url ) {
				$redirect_url = $url;
				// Throw exception to simulate exit() and prevent real exit.
				throw new \RuntimeException( 'Redirect called: ' . $url );
			}
		);
		Functions\when( 'wp_login_url' )->justReturn( 'http://example.com/wp-login.php' );

		// Catch the exception thrown by our mock to simulate exit.
		try {
			$login->handle_2fa_validation();
			$this->fail( 'Expected redirect exception was not thrown' );
		} catch ( \RuntimeException $e ) {
			// Expected - the redirect was called and we caught the simulated exit.
		}

		$this->assertEquals( 'http://example.com/wp-login.php', $redirect_url );
	}

	/**
	 * Test handle_2fa_validation redirects when missing nonce.
	 */
	public function test_handle_2fa_validation_redirects_on_missing_nonce() {
		$login = new \AtomicEdge_2FA_Login();

		// Missing wp-auth-nonce.
		$_POST = array(
			'wp-auth-id' => '1',
		);

		$redirect_url = null;
		Functions\when( 'wp_safe_redirect' )->alias(
			function( $url ) use ( &$redirect_url ) {
				$redirect_url = $url;
				// Throw exception to simulate exit().
				throw new \RuntimeException( 'Redirect called: ' . $url );
			}
		);
		Functions\when( 'wp_login_url' )->justReturn( 'http://example.com/wp-login.php' );

		try {
			$login->handle_2fa_validation();
			$this->fail( 'Expected redirect exception was not thrown' );
		} catch ( \RuntimeException $e ) {
			// Expected - the redirect was called.
		}

		$this->assertEquals( 'http://example.com/wp-login.php', $redirect_url );
	}

	/**
	 * Test handle_2fa_validation redirects on invalid nonce.
	 */
	public function test_handle_2fa_validation_redirects_on_invalid_nonce() {
		$login = new \AtomicEdge_2FA_Login();

		$_POST = array(
			'wp-auth-id'    => '1',
			'wp-auth-nonce' => 'invalid_nonce',
		);

		$redirect_url = null;
		Functions\when( 'wp_safe_redirect' )->alias(
			function( $url ) use ( &$redirect_url ) {
				$redirect_url = $url;
				// Throw exception to simulate exit().
				throw new \RuntimeException( 'Redirect called: ' . $url );
			}
		);
		Functions\when( 'wp_login_url' )->justReturn( 'http://example.com/wp-login.php' );
		Functions\when( 'add_query_arg' )->alias(
			function( $key, $value, $url = null ) {
				if ( is_array( $key ) ) {
					$args = $key;
					$url  = $value;
					return $url . '?' . http_build_query( $args );
				}
				return ( $url ?? '' ) . '?' . $key . '=' . rawurlencode( $value );
			}
		);

		try {
			$login->handle_2fa_validation();
			$this->fail( 'Expected redirect exception was not thrown' );
		} catch ( \RuntimeException $e ) {
			// Expected - the redirect was called.
		}

		$this->assertNotNull( $redirect_url );
		$this->assertStringContainsString( 'wp-login.php', $redirect_url );
	}

	// =========================================================================
	// Class Existence Tests
	// =========================================================================

	/**
	 * Test AtomicEdge_2FA_Login class can be instantiated.
	 */
	public function test_class_can_be_instantiated() {
		$login = new \AtomicEdge_2FA_Login();
		$this->assertInstanceOf( \AtomicEdge_2FA_Login::class, $login );
	}

	/**
	 * Test AtomicEdge_2FA_Login has required public methods.
	 */
	public function test_class_has_required_methods() {
		$this->assertTrue( method_exists( \AtomicEdge_2FA_Login::class, 'filter_authenticate_block_cookies' ) );
		$this->assertTrue( method_exists( \AtomicEdge_2FA_Login::class, 'wp_login' ) );
		$this->assertTrue( method_exists( \AtomicEdge_2FA_Login::class, 'handle_2fa_validation' ) );
		$this->assertTrue( method_exists( \AtomicEdge_2FA_Login::class, 'attach_session_info' ) );
	}

	// =========================================================================
	// Helper Methods
	// =========================================================================

	/**
	 * Create a mock WP_User-like object.
	 *
	 * @param int    $id         User ID.
	 * @param string $user_login Username.
	 * @return object Mock user object.
	 */
	private function create_mock_user( $id, $user_login ) {
		// Create a simple object that looks like WP_User.
		return (object) array(
			'ID'         => $id,
			'user_login' => $user_login,
			'user_email' => $user_login . '@example.com',
			'roles'      => array( 'administrator' ),
		);
	}

	/**
	 * Set user meta for testing.
	 *
	 * @param int    $user_id User ID.
	 * @param string $key     Meta key.
	 * @param mixed  $value   Meta value.
	 * @return void
	 */
	private function set_user_meta( $user_id, $key, $value ) {
		global $_test_user_meta;
		if ( ! isset( $_test_user_meta ) ) {
			$_test_user_meta = array();
		}
		$_test_user_meta[ $user_id ][ $key ] = $value;
	}

	/**
	 * Clear user meta for testing.
	 *
	 * @param int    $user_id User ID.
	 * @param string $key     Meta key.
	 * @return void
	 */
	private function clear_user_meta( $user_id, $key ) {
		global $_test_user_meta;
		if ( isset( $_test_user_meta[ $user_id ][ $key ] ) ) {
			unset( $_test_user_meta[ $user_id ][ $key ] );
		}
	}
}
