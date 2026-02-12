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

	/**
	 * Test CDN cache cleanup removes old files.
	 */
	public function test_cleanup_cdn_cache_removes_old_files() {
		// Ensure the constant is defined.
		if ( ! defined( 'ATOMICEDGE_CDN_CACHE_DIR' ) ) {
			define( 'ATOMICEDGE_CDN_CACHE_DIR', 'atomicedge-cdn-cache' );
		}

		// Create a temporary cache directory structure.
		$temp_dir  = sys_get_temp_dir() . '/atomicedge-cron-test-' . uniqid();
		$cache_dir = $temp_dir . '/' . ATOMICEDGE_CDN_CACHE_DIR;
		$css_dir   = $cache_dir . '/css';
		$js_dir    = $cache_dir . '/js';

		mkdir( $css_dir, 0755, true );
		mkdir( $js_dir, 0755, true );

		// Create test files.
		$old_file = $css_dir . '/old-file.css';
		$new_file = $css_dir . '/new-file.css';
		file_put_contents( $old_file, 'body{}' );
		file_put_contents( $new_file, 'div{}' );

		// Make the old file appear 8 days old.
		touch( $old_file, time() - ( 8 * DAY_IN_SECONDS ) );
		// New file is current.
		touch( $new_file, time() );

		// Mock wp_upload_dir to our temp directory.
		Functions\when( 'wp_upload_dir' )->justReturn( array(
			'basedir' => $temp_dir,
		) );

		$api     = $this->createMock( \AtomicEdge_API::class );
		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$cron    = new \AtomicEdge_Cron( $api, $scanner );

		$cron->cleanup_cdn_cache();

		// Old file should be deleted, new file should remain.
		$this->assertFileDoesNotExist( $old_file );
		$this->assertFileExists( $new_file );

		// Cleanup.
		@unlink( $new_file );
		@rmdir( $css_dir );
		@rmdir( $js_dir );
		@rmdir( $cache_dir );
		@rmdir( $temp_dir );
	}

	/**
	 * Test CDN cache cleanup does nothing when no cache directory exists.
	 */
	public function test_cleanup_cdn_cache_handles_missing_directory() {
		// Ensure the constant is defined.
		if ( ! defined( 'ATOMICEDGE_CDN_CACHE_DIR' ) ) {
			define( 'ATOMICEDGE_CDN_CACHE_DIR', 'atomicedge-cdn-cache' );
		}

		// Mock wp_upload_dir to non-existent path.
		Functions\when( 'wp_upload_dir' )->justReturn( array(
			'basedir' => sys_get_temp_dir() . '/non-existent-' . uniqid(),
		) );

		$api     = $this->createMock( \AtomicEdge_API::class );
		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$cron    = new \AtomicEdge_Cron( $api, $scanner );

		// Should not throw any errors.
		$cron->cleanup_cdn_cache();
		$this->addToAssertionCount( 1 );
	}
}
