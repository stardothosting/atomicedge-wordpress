<?php
/**
 * AtomicEdge Cron Tests
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

class CronTest extends TestCase {

	public function test_add_cron_schedules_adds_weekly_schedule() {
		$cron = new \AtomicEdge_Cron(
			$this->createMock( \AtomicEdge_API::class ),
			$this->createMock( \AtomicEdge_Scanner::class )
		);

		$schedules = $cron->add_cron_schedules( array() );

		$this->assertArrayHasKey( 'atomicedge_weekly', $schedules );
		$this->assertSame( WEEK_IN_SECONDS, $schedules['atomicedge_weekly']['interval'] );
	}

	public function test_sync_settings_updates_site_data_when_connected() {
		$api = $this->createMock( \AtomicEdge_API::class );
		$scanner = $this->createMock( \AtomicEdge_Scanner::class );

		$api->method( 'is_connected' )->willReturn( true );
		$api->method( 'get_site_info' )->willReturn(
			array(
				'success' => true,
				'data'    => array( 'site' => 'demo' ),
			)
		);

		$cron = new \AtomicEdge_Cron( $api, $scanner );
		$cron->sync_settings();

		$this->assertSame( array( 'site' => 'demo' ), get_option( 'atomicedge_site_data' ) );
	}

	public function test_run_daily_scan_triggers_action_when_issues_found() {
		$api = $this->createMock( \AtomicEdge_API::class );
		$scanner = $this->createMock( \AtomicEdge_Scanner::class );

		$results = array(
			'summary' => array( 'total_issues' => 2 ),
		);

		$scanner->method( 'run_full_scan' )->willReturn( $results );

		$called = false;
		Functions\when( 'do_action' )->alias(
			function ( $hook, $payload = null ) use ( &$called, $results ) {
				if ( 'atomicedge_scan_issues_found' === $hook && $payload === $results ) {
					$called = true;
				}
			}
		);

		$cron = new \AtomicEdge_Cron( $api, $scanner );
		$cron->run_daily_scan();

		$this->assertTrue( $called );
	}
}
