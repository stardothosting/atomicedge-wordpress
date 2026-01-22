<?php
/**
 * AtomicEdge 2FA Audit Tests
 *
 * @package AtomicEdge\Tests
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;
use Mockery;

/**
 * Test case for AtomicEdge_2FA_Audit class.
 */
class TwoFactorAuditTest extends TestCase {

	/**
	 * Audit log storage for mocking.
	 *
	 * @var array
	 */
	private $audit_log = array();

	/**
	 * Set up test environment.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->audit_log = array();

		// Mock get_option for audit log.
		Functions\when( 'get_option' )->alias( function ( $key, $default = false ) {
			if ( $key === \AtomicEdge_2FA_Audit::OPTION_KEY ) {
				return $this->audit_log;
			}
			return $default;
		} );

		// Mock update_option for audit log.
		Functions\when( 'update_option' )->alias( function ( $key, $value, $autoload = null ) {
			if ( $key === \AtomicEdge_2FA_Audit::OPTION_KEY ) {
				$this->audit_log = $value;
				return true;
			}
			return true;
		} );

		// Mock delete_option.
		Functions\when( 'delete_option' )->alias( function ( $key ) {
			if ( $key === \AtomicEdge_2FA_Audit::OPTION_KEY ) {
				$this->audit_log = array();
				return true;
			}
			return true;
		} );

		// Mock get_userdata.
		Functions\when( 'get_userdata' )->alias( function ( $user_id ) {
			if ( $user_id > 0 ) {
				$user = new \stdClass();
				$user->ID = $user_id;
				$user->user_login = 'testuser' . $user_id;
				$user->user_email = 'testuser' . $user_id . '@example.com';
				return $user;
			}
			return false;
		} );

		// Mock get_current_user_id.
		Functions\when( 'get_current_user_id' )->justReturn( 0 );

		// Mock sanitize_text_field.
		Functions\when( 'sanitize_text_field' )->returnArg();

		// Mock wp_unslash.
		Functions\when( 'wp_unslash' )->returnArg();

		// Mock wp_date.
		Functions\when( 'wp_date' )->alias( function ( $format, $timestamp = null ) {
			return gmdate( $format, $timestamp ?? time() );
		} );

		// Mock wp_parse_args.
		Functions\when( 'wp_parse_args' )->alias( function ( $args, $defaults ) {
			return array_merge( $defaults, $args );
		} );

		// Mock wp_next_scheduled.
		Functions\when( 'wp_next_scheduled' )->justReturn( false );

		// Mock wp_schedule_event.
		Functions\when( 'wp_schedule_event' )->justReturn( true );

		// Mock add_action.
		Functions\when( 'add_action' )->justReturn( true );

		// Clear $_SERVER for IP tests.
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		unset( $_SERVER['HTTP_X_REAL_IP'] );
		unset( $_SERVER['REMOTE_ADDR'] );
		unset( $_SERVER['HTTP_USER_AGENT'] );
	}

	/**
	 * Tear down test environment.
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		parent::tearDown();
		$this->audit_log = array();
	}

	// =========================================================================
	// Log Event Tests
	// =========================================================================

	/**
	 * Test logging a basic event.
	 *
	 * @return void
	 */
	public function test_log_event_stores_entry() {
		\AtomicEdge_2FA_Audit::log_event( 1, 'enrollment_completed', array() );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertCount( 1, $log );
		$this->assertEquals( 1, $log[0]['user_id'] );
		$this->assertEquals( 'enrollment_completed', $log[0]['event'] );
		$this->assertEquals( 'testuser1', $log[0]['user_login'] );
		$this->assertEquals( 'testuser1@example.com', $log[0]['user_email'] );
	}

	/**
	 * Test log event includes timestamp.
	 *
	 * @return void
	 */
	public function test_log_event_includes_timestamp() {
		$before = time();
		\AtomicEdge_2FA_Audit::log_event( 1, 'login_success' );
		$after = time();

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertGreaterThanOrEqual( $before, $log[0]['timestamp'] );
		$this->assertLessThanOrEqual( $after, $log[0]['timestamp'] );
	}

	/**
	 * Test log event stores context.
	 *
	 * @return void
	 */
	public function test_log_event_stores_context() {
		$context = array( 'reason' => 'Test reason', 'codes_remaining' => 5 );
		\AtomicEdge_2FA_Audit::log_event( 1, 'backup_code_used', $context );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( $context, $log[0]['context'] );
	}

	/**
	 * Test log event captures IP address.
	 *
	 * @return void
	 */
	public function test_log_event_captures_ip_address() {
		$_SERVER['REMOTE_ADDR'] = '192.168.1.100';

		\AtomicEdge_2FA_Audit::log_event( 1, 'login_success' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( '192.168.1.100', $log[0]['ip_address'] );
	}

	/**
	 * Test log event captures Cloudflare IP.
	 *
	 * @return void
	 */
	public function test_log_event_prefers_cloudflare_ip() {
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.50';
		$_SERVER['REMOTE_ADDR'] = '192.168.1.1';

		\AtomicEdge_2FA_Audit::log_event( 1, 'login_success' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( '203.0.113.50', $log[0]['ip_address'] );
	}

	/**
	 * Test log event handles X-Forwarded-For with multiple IPs.
	 *
	 * @return void
	 */
	public function test_log_event_handles_forwarded_for_multiple() {
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.1, 10.0.0.2, 10.0.0.3';

		\AtomicEdge_2FA_Audit::log_event( 1, 'login_success' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		// Should take the first IP.
		$this->assertEquals( '10.0.0.1', $log[0]['ip_address'] );
	}

	/**
	 * Test log event captures user agent.
	 *
	 * @return void
	 */
	public function test_log_event_captures_user_agent() {
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 TestBrowser';
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';

		\AtomicEdge_2FA_Audit::log_event( 1, 'login_success' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( 'Mozilla/5.0 TestBrowser', $log[0]['user_agent'] );
	}

	/**
	 * Test log event truncates long user agent.
	 *
	 * @return void
	 */
	public function test_log_event_truncates_long_user_agent() {
		$_SERVER['HTTP_USER_AGENT'] = str_repeat( 'A', 500 );
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';

		\AtomicEdge_2FA_Audit::log_event( 1, 'login_success' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( 200, strlen( $log[0]['user_agent'] ) );
	}

	/**
	 * Test log event handles unknown user.
	 *
	 * @return void
	 */
	public function test_log_event_handles_unknown_user() {
		// Override get_userdata to return false.
		Functions\when( 'get_userdata' )->justReturn( false );

		\AtomicEdge_2FA_Audit::log_event( 999, '2fa_disabled' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( 'unknown', $log[0]['user_login'] );
		$this->assertEquals( '', $log[0]['user_email'] );
	}

	/**
	 * Test log event includes admin info when action by admin.
	 *
	 * @return void
	 */
	public function test_log_event_includes_admin_info() {
		// Admin user ID 99 performing action on user 1.
		Functions\when( 'get_current_user_id' )->justReturn( 99 );

		\AtomicEdge_2FA_Audit::log_event( 1, 'admin_reset' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( 99, $log[0]['admin_id'] );
		$this->assertEquals( 'testuser99', $log[0]['admin_login'] );
	}

	/**
	 * Test log event doesn't include admin info when self-action.
	 *
	 * @return void
	 */
	public function test_log_event_no_admin_for_self_action() {
		// User 1 performing action on themselves.
		Functions\when( 'get_current_user_id' )->justReturn( 1 );

		\AtomicEdge_2FA_Audit::log_event( 1, 'enrollment_completed' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertArrayNotHasKey( 'admin_id', $log[0] );
	}

	/**
	 * Test newest entries are first.
	 *
	 * @return void
	 */
	public function test_log_prepends_new_entries() {
		\AtomicEdge_2FA_Audit::log_event( 1, 'enrollment_started' );
		\AtomicEdge_2FA_Audit::log_event( 2, 'enrollment_completed' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertCount( 2, $log );
		$this->assertEquals( 2, $log[0]['user_id'] ); // Newest first.
		$this->assertEquals( 1, $log[1]['user_id'] );
	}

	/**
	 * Test log respects max entries limit.
	 *
	 * @return void
	 */
	public function test_log_respects_max_entries() {
		// Create 600 entries.
		for ( $i = 1; $i <= 600; $i++ ) {
			$this->audit_log[] = array(
				'timestamp'  => time() - ( 600 - $i ),
				'user_id'    => $i,
				'user_login' => 'user' . $i,
				'user_email' => 'user' . $i . '@example.com',
				'event'      => 'test_event',
				'ip_address' => '127.0.0.1',
				'user_agent' => '',
				'context'    => array(),
			);
		}

		// Log one more.
		\AtomicEdge_2FA_Audit::log_event( 999, 'new_event' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertCount( \AtomicEdge_2FA_Audit::MAX_ENTRIES, $log );
		$this->assertEquals( 999, $log[0]['user_id'] ); // Newest is first.
	}

	// =========================================================================
	// Get Entries Tests
	// =========================================================================

	/**
	 * Test get entries returns all entries by default.
	 *
	 * @return void
	 */
	public function test_get_entries_returns_all() {
		$this->seed_audit_log( 10 );

		$result = \AtomicEdge_2FA_Audit::get_entries( array( 'limit' => 100 ) );

		$this->assertEquals( 10, $result['total'] );
		$this->assertCount( 10, $result['entries'] );
	}

	/**
	 * Test get entries filters by user ID.
	 *
	 * @return void
	 */
	public function test_get_entries_filters_by_user_id() {
		$this->seed_audit_log( 10 );

		$result = \AtomicEdge_2FA_Audit::get_entries( array(
			'user_id' => 1,
			'limit'   => 100,
		) );

		// All seeded entries have user_id incrementing 1-10.
		$this->assertEquals( 1, $result['total'] );
		$this->assertEquals( 1, $result['entries'][0]['user_id'] );
	}

	/**
	 * Test get entries filters by event type.
	 *
	 * @return void
	 */
	public function test_get_entries_filters_by_event() {
		$this->audit_log = array(
			$this->make_entry( 1, 'login_success' ),
			$this->make_entry( 2, 'login_failed' ),
			$this->make_entry( 3, 'login_success' ),
		);

		$result = \AtomicEdge_2FA_Audit::get_entries( array(
			'event' => 'login_failed',
			'limit' => 100,
		) );

		$this->assertEquals( 1, $result['total'] );
		$this->assertEquals( 'login_failed', $result['entries'][0]['event'] );
	}

	/**
	 * Test get entries filters by timestamp.
	 *
	 * @return void
	 */
	public function test_get_entries_filters_by_since() {
		$now = time();
		$this->audit_log = array(
			$this->make_entry( 1, 'event1', $now ),
			$this->make_entry( 2, 'event2', $now - 3600 ), // 1 hour ago.
			$this->make_entry( 3, 'event3', $now - 86400 ), // 1 day ago.
		);

		$result = \AtomicEdge_2FA_Audit::get_entries( array(
			'since' => $now - 7200, // 2 hours ago.
			'limit' => 100,
		) );

		$this->assertEquals( 2, $result['total'] ); // Only events from last 2 hours.
	}

	/**
	 * Test get entries respects limit.
	 *
	 * @return void
	 */
	public function test_get_entries_respects_limit() {
		$this->seed_audit_log( 20 );

		$result = \AtomicEdge_2FA_Audit::get_entries( array( 'limit' => 5 ) );

		$this->assertEquals( 20, $result['total'] );
		$this->assertCount( 5, $result['entries'] );
	}

	/**
	 * Test get entries respects offset.
	 *
	 * @return void
	 */
	public function test_get_entries_respects_offset() {
		$this->seed_audit_log( 20 );

		$result = \AtomicEdge_2FA_Audit::get_entries( array(
			'limit'  => 5,
			'offset' => 10,
		) );

		$this->assertEquals( 20, $result['total'] );
		$this->assertCount( 5, $result['entries'] );
	}

	// =========================================================================
	// Get User Entries Tests
	// =========================================================================

	/**
	 * Test get user entries returns only user's entries.
	 *
	 * @return void
	 */
	public function test_get_user_entries() {
		$this->audit_log = array(
			$this->make_entry( 1, 'login_success' ),
			$this->make_entry( 2, 'login_success' ),
			$this->make_entry( 1, 'enrollment_completed' ),
		);

		$entries = \AtomicEdge_2FA_Audit::get_user_entries( 1 );

		$this->assertCount( 2, $entries );
		foreach ( $entries as $entry ) {
			$this->assertEquals( 1, $entry['user_id'] );
		}
	}

	/**
	 * Test get user entries respects limit.
	 *
	 * @return void
	 */
	public function test_get_user_entries_respects_limit() {
		// Add 30 entries for user 1.
		for ( $i = 0; $i < 30; $i++ ) {
			$this->audit_log[] = $this->make_entry( 1, 'login_success' );
		}

		$entries = \AtomicEdge_2FA_Audit::get_user_entries( 1, 10 );

		$this->assertCount( 10, $entries );
	}

	// =========================================================================
	// Get Security Events Tests
	// =========================================================================

	/**
	 * Test get security events returns only security-relevant events.
	 *
	 * @return void
	 */
	public function test_get_security_events() {
		$this->audit_log = array(
			$this->make_entry( 1, 'login_success' ),
			$this->make_entry( 2, 'login_failed' ),
			$this->make_entry( 3, 'rate_limited' ),
			$this->make_entry( 4, 'enrollment_completed' ),
			$this->make_entry( 5, 'admin_reset' ),
			$this->make_entry( 6, '2fa_disabled' ),
		);

		$events = \AtomicEdge_2FA_Audit::get_security_events();

		$this->assertCount( 4, $events );
		$event_types = array_column( $events, 'event' );
		$this->assertContains( 'login_failed', $event_types );
		$this->assertContains( 'rate_limited', $event_types );
		$this->assertContains( 'admin_reset', $event_types );
		$this->assertContains( '2fa_disabled', $event_types );
		$this->assertNotContains( 'login_success', $event_types );
		$this->assertNotContains( 'enrollment_completed', $event_types );
	}

	/**
	 * Test get security events respects limit.
	 *
	 * @return void
	 */
	public function test_get_security_events_respects_limit() {
		// Add 20 failed logins.
		for ( $i = 0; $i < 20; $i++ ) {
			$this->audit_log[] = $this->make_entry( $i, 'login_failed' );
		}

		$events = \AtomicEdge_2FA_Audit::get_security_events( 5 );

		$this->assertCount( 5, $events );
	}

	// =========================================================================
	// Cleanup Tests
	// =========================================================================

	/**
	 * Test cleanup removes old entries.
	 *
	 * @return void
	 */
	public function test_cleanup_removes_old_entries() {
		$now = time();
		$retention_days = \AtomicEdge_2FA_Audit::RETENTION_DAYS;

		$this->audit_log = array(
			$this->make_entry( 1, 'recent', $now - DAY_IN_SECONDS ), // 1 day ago.
			$this->make_entry( 2, 'old', $now - ( $retention_days + 1 ) * DAY_IN_SECONDS ), // 91+ days ago.
			$this->make_entry( 3, 'boundary', $now - $retention_days * DAY_IN_SECONDS ), // Exactly 90 days.
		);

		$removed = \AtomicEdge_2FA_Audit::cleanup_old_entries();

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( 1, $removed );
		$this->assertCount( 2, $log );
	}

	/**
	 * Test cleanup returns count of removed entries.
	 *
	 * @return void
	 */
	public function test_cleanup_returns_removed_count() {
		$now = time();
		$retention_days = \AtomicEdge_2FA_Audit::RETENTION_DAYS;

		// Add 5 old entries.
		for ( $i = 0; $i < 5; $i++ ) {
			$this->audit_log[] = $this->make_entry( $i, 'old', $now - ( $retention_days + 5 ) * DAY_IN_SECONDS );
		}

		$removed = \AtomicEdge_2FA_Audit::cleanup_old_entries();

		$this->assertEquals( 5, $removed );
	}

	// =========================================================================
	// Clear Log Tests
	// =========================================================================

	/**
	 * Test clear log removes all entries.
	 *
	 * @return void
	 */
	public function test_clear_log() {
		$this->seed_audit_log( 10 );

		$result = \AtomicEdge_2FA_Audit::clear_log();

		$this->assertTrue( $result );
		$this->assertEmpty( \AtomicEdge_2FA_Audit::get_log() );
	}

	// =========================================================================
	// Label and Severity Tests
	// =========================================================================

	/**
	 * Test get event label returns correct label.
	 *
	 * @return void
	 */
	public function test_get_event_label() {
		$this->assertEquals( 'Completed 2FA setup', \AtomicEdge_2FA_Audit::get_event_label( 'enrollment_completed' ) );
		$this->assertEquals( 'Failed 2FA verification', \AtomicEdge_2FA_Audit::get_event_label( 'login_failed' ) );
		$this->assertEquals( 'Admin reset 2FA', \AtomicEdge_2FA_Audit::get_event_label( 'admin_reset' ) );
	}

	/**
	 * Test get event label returns event name for unknown event.
	 *
	 * @return void
	 */
	public function test_get_event_label_unknown() {
		$this->assertEquals( 'unknown_event', \AtomicEdge_2FA_Audit::get_event_label( 'unknown_event' ) );
	}

	/**
	 * Test get event severity returns correct severity.
	 *
	 * @return void
	 */
	public function test_get_event_severity() {
		$this->assertEquals( 'success', \AtomicEdge_2FA_Audit::get_event_severity( 'enrollment_completed' ) );
		$this->assertEquals( 'danger', \AtomicEdge_2FA_Audit::get_event_severity( 'login_failed' ) );
		$this->assertEquals( 'warning', \AtomicEdge_2FA_Audit::get_event_severity( '2fa_disabled' ) );
	}

	/**
	 * Test get event severity returns info for unknown event.
	 *
	 * @return void
	 */
	public function test_get_event_severity_unknown() {
		$this->assertEquals( 'info', \AtomicEdge_2FA_Audit::get_event_severity( 'unknown_event' ) );
	}

	// =========================================================================
	// Statistics Tests
	// =========================================================================

	/**
	 * Test get statistics returns correct counts.
	 *
	 * @return void
	 */
	public function test_get_statistics() {
		$now = time();

		$this->audit_log = array(
			$this->make_entry( 1, 'login_success', $now ),
			$this->make_entry( 2, 'login_success', $now ),
			$this->make_entry( 3, 'login_failed', $now ),
			$this->make_entry( 4, 'enrollment_completed', $now ),
			$this->make_entry( 5, 'backup_code_used', $now ),
			$this->make_entry( 6, 'rate_limited', $now ),
			$this->make_entry( 7, '2fa_disabled', $now ),
			$this->make_entry( 8, 'admin_reset', $now ),
		);

		$stats = \AtomicEdge_2FA_Audit::get_statistics( 30 );

		$this->assertEquals( 8, $stats['total_events'] );
		$this->assertEquals( 2, $stats['login_success'] );
		$this->assertEquals( 1, $stats['login_failed'] );
		$this->assertEquals( 1, $stats['enrollments'] );
		$this->assertEquals( 1, $stats['backup_code_used'] );
		$this->assertEquals( 1, $stats['rate_limited'] );
		$this->assertEquals( 1, $stats['disabled'] );
		$this->assertEquals( 1, $stats['admin_resets'] );
	}

	/**
	 * Test get statistics respects date range.
	 *
	 * @return void
	 */
	public function test_get_statistics_date_range() {
		$now = time();

		$this->audit_log = array(
			$this->make_entry( 1, 'login_success', $now ), // Today.
			$this->make_entry( 2, 'login_success', $now - 40 * DAY_IN_SECONDS ), // 40 days ago.
		);

		$stats = \AtomicEdge_2FA_Audit::get_statistics( 30 );

		$this->assertEquals( 1, $stats['total_events'] );
		$this->assertEquals( 1, $stats['login_success'] );
	}

	// =========================================================================
	// Export Tests
	// =========================================================================

	/**
	 * Test export returns formatted array.
	 *
	 * @return void
	 */
	public function test_export() {
		$this->audit_log = array(
			$this->make_entry( 1, 'login_success', 1704067200 ), // 2024-01-01 00:00:00 UTC.
		);

		$export = \AtomicEdge_2FA_Audit::export();

		$this->assertCount( 1, $export );
		$this->assertEquals( 'testuser1', $export[0]['user'] );
		$this->assertEquals( 'testuser1@example.com', $export[0]['user_email'] );
		$this->assertEquals( 'Logged in with 2FA', $export[0]['event'] );
		$this->assertEquals( '127.0.0.1', $export[0]['ip_address'] );
	}

	/**
	 * Test export respects limit.
	 *
	 * @return void
	 */
	public function test_export_respects_limit() {
		$this->seed_audit_log( 50 );

		$export = \AtomicEdge_2FA_Audit::export( 10 );

		$this->assertCount( 10, $export );
	}

	/**
	 * Test export includes admin info.
	 *
	 * @return void
	 */
	public function test_export_includes_admin() {
		$entry = $this->make_entry( 1, 'admin_reset' );
		$entry['admin_id'] = 99;
		$entry['admin_login'] = 'adminuser';
		$this->audit_log = array( $entry );

		$export = \AtomicEdge_2FA_Audit::export();

		$this->assertEquals( 'adminuser', $export[0]['admin'] );
	}

	// =========================================================================
	// Init Tests
	// =========================================================================

	/**
	 * Test init adds action hook.
	 *
	 * @return void
	 */
	public function test_init_adds_hooks() {
		$add_action_calls = array();

		Functions\when( 'add_action' )->alias( function ( $hook, $callback, $priority = 10, $args = 1 ) use ( &$add_action_calls ) {
			$add_action_calls[] = array( 'hook' => $hook, 'callback' => $callback );
			return true;
		} );

		\AtomicEdge_2FA_Audit::init();

		$hooks = array_column( $add_action_calls, 'hook' );
		$this->assertContains( 'atomicedge_2fa_event', $hooks );
		$this->assertContains( 'atomicedge_2fa_audit_cleanup', $hooks );
	}

	// =========================================================================
	// IP Address Edge Cases
	// =========================================================================

	/**
	 * Test invalid IP is replaced with 0.0.0.0.
	 *
	 * @return void
	 */
	public function test_invalid_ip_replaced() {
		$_SERVER['REMOTE_ADDR'] = 'not-an-ip';

		\AtomicEdge_2FA_Audit::log_event( 1, 'login_success' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( '0.0.0.0', $log[0]['ip_address'] );
	}

	/**
	 * Test missing IP uses 0.0.0.0.
	 *
	 * @return void
	 */
	public function test_missing_ip() {
		\AtomicEdge_2FA_Audit::log_event( 1, 'login_success' );

		$log = \AtomicEdge_2FA_Audit::get_log();

		$this->assertEquals( '0.0.0.0', $log[0]['ip_address'] );
	}

	// =========================================================================
	// Helper Methods
	// =========================================================================

	/**
	 * Seed audit log with test entries.
	 *
	 * @param int $count Number of entries.
	 * @return void
	 */
	private function seed_audit_log( $count ) {
		for ( $i = 1; $i <= $count; $i++ ) {
			$this->audit_log[] = $this->make_entry( $i, 'test_event', time() - $i );
		}
	}

	/**
	 * Create a test audit log entry.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $event     Event type.
	 * @param int    $timestamp Optional timestamp.
	 * @return array Entry array.
	 */
	private function make_entry( $user_id, $event, $timestamp = null ) {
		return array(
			'timestamp'  => $timestamp ?? time(),
			'user_id'    => $user_id,
			'user_login' => 'testuser' . $user_id,
			'user_email' => 'testuser' . $user_id . '@example.com',
			'event'      => $event,
			'ip_address' => '127.0.0.1',
			'user_agent' => 'TestAgent',
			'context'    => array(),
		);
	}
}
