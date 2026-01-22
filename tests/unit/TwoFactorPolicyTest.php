<?php
/**
 * Tests for AtomicEdge_2FA_Policy class.
 *
 * @package AtomicEdge
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use AtomicEdge_2FA_Policy;
use AtomicEdge_2FA;
use Brain\Monkey\Functions;
use Mockery;

/**
 * Class TwoFactorPolicyTest
 */
class TwoFactorPolicyTest extends TestCase {

	/**
	 * User meta storage simulation.
	 *
	 * @var array
	 */
	private $user_meta = array();

	/**
	 * Options storage simulation.
	 *
	 * @var array
	 */
	private $options = array();

	/**
	 * Set up test environment.
	 */
	protected function setUp(): void {
		parent::setUp();

		// Reset storage.
		$this->user_meta = array();
		$this->options   = array();

		// Mock get_user_meta.
		Functions\when( 'get_user_meta' )->alias(
			function ( $user_id, $key, $single ) {
				if ( $single ) {
					return isset( $this->user_meta[ $user_id ][ $key ] )
						? $this->user_meta[ $user_id ][ $key ]
						: '';
				}
				return isset( $this->user_meta[ $user_id ][ $key ] )
					? (array) $this->user_meta[ $user_id ][ $key ]
					: array();
			}
		);

		// Mock update_user_meta.
		Functions\when( 'update_user_meta' )->alias(
			function ( $user_id, $key, $value ) {
				if ( ! isset( $this->user_meta[ $user_id ] ) ) {
					$this->user_meta[ $user_id ] = array();
				}
				$this->user_meta[ $user_id ][ $key ] = $value;
				return true;
			}
		);

		// Mock delete_user_meta.
		Functions\when( 'delete_user_meta' )->alias(
			function ( $user_id, $key ) {
				if ( isset( $this->user_meta[ $user_id ][ $key ] ) ) {
					unset( $this->user_meta[ $user_id ][ $key ] );
				}
				return true;
			}
		);

		// Mock get_option.
		Functions\when( 'get_option' )->alias(
			function ( $key, $default = false ) {
				return isset( $this->options[ $key ] ) ? $this->options[ $key ] : $default;
			}
		);

		// Mock update_option.
		Functions\when( 'update_option' )->alias(
			function ( $key, $value ) {
				$this->options[ $key ] = $value;
				return true;
			}
		);

		// Mock wp_parse_args.
		Functions\when( 'wp_parse_args' )->alias(
			function ( $args, $defaults ) {
				return array_merge( $defaults, (array) $args );
			}
		);

		// Mock sanitize_key.
		Functions\when( 'sanitize_key' )->alias(
			function ( $key ) {
				return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $key ) );
			}
		);

		// Mock absint.
		Functions\when( 'absint' )->alias(
			function ( $maybeint ) {
				return abs( (int) $maybeint );
			}
		);

		// Mock wp_roles.
		$roles_mock = Mockery::mock();
		$roles_mock->roles = array(
			'administrator' => array( 'name' => 'Administrator' ),
			'editor'        => array( 'name' => 'Editor' ),
			'author'        => array( 'name' => 'Author' ),
			'subscriber'    => array( 'name' => 'Subscriber' ),
		);
		Functions\when( 'wp_roles' )->justReturn( $roles_mock );

		// Mock translate_user_role.
		Functions\when( 'translate_user_role' )->returnArg( 1 );

		// Mock DAY_IN_SECONDS constant.
		if ( ! defined( 'DAY_IN_SECONDS' ) ) {
			define( 'DAY_IN_SECONDS', 86400 );
		}
	}

	/**
	 * Helper to create a mock user object.
	 *
	 * @param int   $id    User ID.
	 * @param array $roles User roles.
	 * @return object Mock user object.
	 */
	private function create_mock_user( $id, $roles = array( 'subscriber' ) ) {
		$user = (object) array(
			'ID'         => $id,
			'roles'      => $roles,
			'user_login' => 'testuser' . $id,
		);
		return $user;
	}

	// ==================== Settings Tests ====================

	public function test_get_settings_returns_defaults_when_not_set() {
		$settings = AtomicEdge_2FA_Policy::get_settings();

		$this->assertFalse( $settings['enabled'] );
		$this->assertIsArray( $settings['enforced_roles'] );
		$this->assertEmpty( $settings['enforced_roles'] );
		$this->assertSame( 7, $settings['grace_period_days'] );
		$this->assertTrue( $settings['allow_grace_bypass'] );
		$this->assertTrue( $settings['show_reminders'] );
	}

	public function test_get_settings_returns_saved_values() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'           => true,
			'enforced_roles'    => array( 'administrator', 'editor' ),
			'grace_period_days' => 14,
		);

		$settings = AtomicEdge_2FA_Policy::get_settings();

		$this->assertTrue( $settings['enabled'] );
		$this->assertSame( array( 'administrator', 'editor' ), $settings['enforced_roles'] );
		$this->assertSame( 14, $settings['grace_period_days'] );
		// Defaults for unset values.
		$this->assertTrue( $settings['allow_grace_bypass'] );
	}

	public function test_update_settings_sanitizes_values() {
		// Include an invalid role.
		$settings = array(
			'enabled'           => 'yes', // truthy string.
			'enforced_roles'    => array( 'administrator', 'invalid_role', 'editor' ),
			'grace_period_days' => '100', // Should cap at 90.
		);

		AtomicEdge_2FA_Policy::update_settings( $settings );
		$saved = $this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ];

		$this->assertTrue( $saved['enabled'] );
		$this->assertSame( array( 'administrator', 'editor' ), $saved['enforced_roles'] );
		$this->assertSame( 90, $saved['grace_period_days'] ); // Capped at 90.
	}

	public function test_update_settings_allows_zero_grace_period() {
		AtomicEdge_2FA_Policy::update_settings( array( 'grace_period_days' => 0 ) );
		$saved = $this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ];

		$this->assertSame( 0, $saved['grace_period_days'] );
	}

	public function test_get_available_roles_returns_all_roles() {
		$roles = AtomicEdge_2FA_Policy::get_available_roles();

		$this->assertArrayHasKey( 'administrator', $roles );
		$this->assertArrayHasKey( 'editor', $roles );
		$this->assertArrayHasKey( 'author', $roles );
		$this->assertArrayHasKey( 'subscriber', $roles );
	}

	// ==================== Requirement Tests ====================

	public function test_is_required_for_user_returns_false_when_policy_disabled() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'        => false,
			'enforced_roles' => array( 'administrator' ),
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);

		$this->assertFalse( AtomicEdge_2FA_Policy::is_required_for_user( 1 ) );
	}

	public function test_is_required_for_user_returns_false_when_no_roles_enforced() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'        => true,
			'enforced_roles' => array(),
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);

		$this->assertFalse( AtomicEdge_2FA_Policy::is_required_for_user( 1 ) );
	}

	public function test_is_required_for_user_returns_true_for_enforced_role() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'        => true,
			'enforced_roles' => array( 'administrator', 'editor' ),
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);

		$this->assertTrue( AtomicEdge_2FA_Policy::is_required_for_user( 1 ) );
	}

	public function test_is_required_for_user_returns_false_for_non_enforced_role() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'        => true,
			'enforced_roles' => array( 'administrator', 'editor' ),
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 2, array( 'subscriber' ) )
		);

		$this->assertFalse( AtomicEdge_2FA_Policy::is_required_for_user( 2 ) );
	}

	public function test_is_required_returns_true_for_multi_role_user_with_one_enforced() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'        => true,
			'enforced_roles' => array( 'administrator' ),
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'subscriber', 'administrator' ) )
		);

		$this->assertTrue( AtomicEdge_2FA_Policy::is_required_for_user( 1 ) );
	}

	public function test_is_required_returns_false_for_invalid_user() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'        => true,
			'enforced_roles' => array( 'administrator' ),
		);

		Functions\when( 'get_userdata' )->justReturn( false );

		$this->assertFalse( AtomicEdge_2FA_Policy::is_required_for_user( 999 ) );
	}

	// ==================== Grace Period Tests ====================

	public function test_start_grace_period_sets_timestamp() {
		// Ensure user doesn't have 2FA enabled (no META_ENABLED set).
		// AtomicEdge_2FA::is_enabled_for_user checks user_meta which we mock.
		// Also need get_userdata for log_event.
		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'subscriber' ) )
		);

		$result = AtomicEdge_2FA_Policy::start_grace_period( 1 );

		$this->assertTrue( $result );
		$this->assertArrayHasKey( AtomicEdge_2FA_Policy::META_GRACE_START, $this->user_meta[1] );
		$this->assertGreaterThan( 0, $this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] );
	}

	public function test_start_grace_period_returns_false_if_already_started() {
		// Set existing grace period.
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - 86400;

		$result = AtomicEdge_2FA_Policy::start_grace_period( 1 );

		$this->assertFalse( $result );
	}

	public function test_start_grace_period_returns_false_if_2fa_enabled() {
		// Set 2FA enabled via user meta (this is what is_enabled_for_user checks).
		$this->user_meta[1][ AtomicEdge_2FA::META_ENABLED ] = '1';

		$result = AtomicEdge_2FA_Policy::start_grace_period( 1 );

		$this->assertFalse( $result );
	}

	public function test_end_grace_period_clears_meta() {
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ]      = time();
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_NOTICE_DISMISSED ] = time();

		AtomicEdge_2FA_Policy::end_grace_period( 1 );

		$this->assertArrayNotHasKey( AtomicEdge_2FA_Policy::META_GRACE_START, $this->user_meta[1] ?? array() );
		$this->assertArrayNotHasKey( AtomicEdge_2FA_Policy::META_NOTICE_DISMISSED, $this->user_meta[1] ?? array() );
	}

	public function test_is_in_grace_period_returns_true_during_grace() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'grace_period_days' => 7,
		);

		// Started 2 days ago.
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - ( 2 * DAY_IN_SECONDS );

		$this->assertTrue( AtomicEdge_2FA_Policy::is_in_grace_period( 1 ) );
	}

	public function test_is_in_grace_period_returns_false_after_grace_expired() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'grace_period_days' => 7,
		);

		// Started 10 days ago.
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - ( 10 * DAY_IN_SECONDS );

		$this->assertFalse( AtomicEdge_2FA_Policy::is_in_grace_period( 1 ) );
	}

	public function test_is_in_grace_period_returns_false_when_grace_disabled() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'grace_period_days' => 0,
		);

		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - DAY_IN_SECONDS;

		$this->assertFalse( AtomicEdge_2FA_Policy::is_in_grace_period( 1 ) );
	}

	public function test_get_grace_days_remaining_calculates_correctly() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'grace_period_days' => 7,
		);

		// Started 2 days ago - should have 5 days left.
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - ( 2 * DAY_IN_SECONDS );

		$remaining = AtomicEdge_2FA_Policy::get_grace_days_remaining( 1 );

		$this->assertSame( 5, $remaining );
	}

	public function test_get_grace_days_remaining_returns_zero_when_expired() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'grace_period_days' => 7,
		);

		// Started 10 days ago.
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - ( 10 * DAY_IN_SECONDS );

		$remaining = AtomicEdge_2FA_Policy::get_grace_days_remaining( 1 );

		$this->assertSame( 0, $remaining );
	}

	public function test_get_grace_days_remaining_returns_zero_when_not_started() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'grace_period_days' => 7,
		);

		$remaining = AtomicEdge_2FA_Policy::get_grace_days_remaining( 1 );

		$this->assertSame( 0, $remaining );
	}

	// ==================== Login Blocking Tests ====================

	public function test_should_block_login_returns_false_when_not_required() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'        => false,
			'enforced_roles' => array( 'administrator' ),
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);

		$this->assertFalse( AtomicEdge_2FA_Policy::should_block_login( 1 ) );
	}

	public function test_should_block_login_returns_false_when_2fa_enabled() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'           => true,
			'enforced_roles'    => array( 'administrator' ),
			'allow_grace_bypass' => true,
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);

		// User has 2FA enabled (via user meta).
		$this->user_meta[1][ AtomicEdge_2FA::META_ENABLED ] = '1';

		$this->assertFalse( AtomicEdge_2FA_Policy::should_block_login( 1 ) );
	}

	public function test_should_block_login_returns_false_during_grace_period_with_bypass() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'            => true,
			'enforced_roles'     => array( 'administrator' ),
			'grace_period_days'  => 7,
			'allow_grace_bypass' => true,
		);

		// Grace started 2 days ago.
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - ( 2 * DAY_IN_SECONDS );

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);
		// User does NOT have 2FA enabled (no META_ENABLED set).

		$this->assertFalse( AtomicEdge_2FA_Policy::should_block_login( 1 ) );
	}

	public function test_should_block_login_returns_true_when_grace_expired() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'            => true,
			'enforced_roles'     => array( 'administrator' ),
			'grace_period_days'  => 7,
			'allow_grace_bypass' => true,
		);

		// Grace started 10 days ago (expired).
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - ( 10 * DAY_IN_SECONDS );

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);
		// User does NOT have 2FA enabled.

		$this->assertTrue( AtomicEdge_2FA_Policy::should_block_login( 1 ) );
	}

	public function test_should_block_login_starts_grace_on_first_login() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'            => true,
			'enforced_roles'     => array( 'administrator' ),
			'grace_period_days'  => 7,
			'allow_grace_bypass' => true,
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);
		// User does NOT have 2FA enabled.

		// First login - no grace period started yet.
		$result = AtomicEdge_2FA_Policy::should_block_login( 1 );

		// Should allow login but grace period should be started.
		$this->assertFalse( $result );
		$this->assertArrayHasKey( AtomicEdge_2FA_Policy::META_GRACE_START, $this->user_meta[1] );
	}

	// ==================== User Status Tests ====================

	public function test_get_user_enforcement_status_returns_complete_info() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'           => true,
			'enforced_roles'    => array( 'administrator' ),
			'grace_period_days' => 7,
		);

		// Grace started 2 days ago.
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_GRACE_START ] = time() - ( 2 * DAY_IN_SECONDS );
		// User does NOT have 2FA enabled.

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);

		$status = AtomicEdge_2FA_Policy::get_user_enforcement_status( 1 );

		$this->assertTrue( $status['required'] );
		$this->assertFalse( $status['has_2fa'] );
		$this->assertFalse( $status['compliant'] );
		$this->assertTrue( $status['in_grace_period'] );
		$this->assertSame( 5, $status['grace_days_left'] );
	}

	public function test_get_user_enforcement_status_compliant_when_has_2fa() {
		$this->options[ AtomicEdge_2FA_Policy::OPTION_KEY ] = array(
			'enabled'        => true,
			'enforced_roles' => array( 'administrator' ),
		);

		Functions\when( 'get_userdata' )->justReturn(
			$this->create_mock_user( 1, array( 'administrator' ) )
		);

		// User has 2FA enabled.
		$this->user_meta[1][ AtomicEdge_2FA::META_ENABLED ] = '1';

		$status = AtomicEdge_2FA_Policy::get_user_enforcement_status( 1 );

		$this->assertTrue( $status['required'] );
		$this->assertTrue( $status['has_2fa'] );
		$this->assertTrue( $status['compliant'] );
	}

	// ==================== Reminder Tests ====================

	public function test_dismiss_reminder_sets_timestamp() {
		AtomicEdge_2FA_Policy::dismiss_reminder( 1 );

		$this->assertArrayHasKey( AtomicEdge_2FA_Policy::META_NOTICE_DISMISSED, $this->user_meta[1] );
		$this->assertGreaterThan( 0, $this->user_meta[1][ AtomicEdge_2FA_Policy::META_NOTICE_DISMISSED ] );
	}

	public function test_is_reminder_dismissed_returns_true_when_recently_dismissed() {
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_NOTICE_DISMISSED ] = time() - 3600; // 1 hour ago.

		$this->assertTrue( AtomicEdge_2FA_Policy::is_reminder_dismissed( 1 ) );
	}

	public function test_is_reminder_dismissed_returns_false_after_24_hours() {
		$this->user_meta[1][ AtomicEdge_2FA_Policy::META_NOTICE_DISMISSED ] = time() - ( 25 * 3600 ); // 25 hours ago.

		$this->assertFalse( AtomicEdge_2FA_Policy::is_reminder_dismissed( 1 ) );
	}

	public function test_is_reminder_dismissed_returns_false_when_never_dismissed() {
		$this->assertFalse( AtomicEdge_2FA_Policy::is_reminder_dismissed( 1 ) );
	}
}
