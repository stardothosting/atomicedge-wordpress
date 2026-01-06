<?php
/**
 * AtomicEdge Cron Handler
 *
 * Manages scheduled tasks and background processes.
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_Cron
 *
 * Handles scheduled tasks.
 */
class AtomicEdge_Cron {

	/**
	 * API client instance.
	 *
	 * @var AtomicEdge_API
	 */
	private $api;

	/**
	 * Scanner instance.
	 *
	 * @var AtomicEdge_Scanner
	 */
	private $scanner;

	/**
	 * Constructor.
	 *
	 * @param AtomicEdge_API     $api     API client instance.
	 * @param AtomicEdge_Scanner $scanner Scanner instance.
	 */
	public function __construct( AtomicEdge_API $api, AtomicEdge_Scanner $scanner ) {
		$this->api     = $api;
		$this->scanner = $scanner;
		$this->init_hooks();
	}

	/**
	 * Initialize cron hooks.
	 *
	 * @return void
	 */
	private function init_hooks() {
		// Daily scan.
		add_action( 'atomicedge_daily_scan', array( $this, 'run_daily_scan' ) );

		// Settings sync (hourly).
		add_action( 'atomicedge_sync_settings', array( $this, 'sync_settings' ) );

		// Add custom cron schedule.
		add_filter( 'cron_schedules', array( $this, 'add_cron_schedules' ) );
	}

	/**
	 * Add custom cron schedules.
	 *
	 * @param array $schedules Existing schedules.
	 * @return array Modified schedules.
	 */
	public function add_cron_schedules( $schedules ) {
		$schedules['atomicedge_weekly'] = array(
			'interval' => WEEK_IN_SECONDS,
			'display'  => __( 'Once Weekly', 'atomicedge' ),
		);

		return $schedules;
	}

	/**
	 * Run daily malware scan.
	 *
	 * @return void
	 */
	public function run_daily_scan() {
		AtomicEdge::log( 'Starting daily scan' );

		$results = $this->scanner->run_full_scan();

		if ( false === $results ) {
			AtomicEdge::log( 'Daily scan failed' );
			return;
		}

		// Check if there are issues.
		$total_issues = $results['summary']['total_issues'] ?? 0;

		if ( $total_issues > 0 ) {
			// Log warning.
			AtomicEdge::log( 'Daily scan found issues', array( 'count' => $total_issues ) );

			// Optionally send notification.
			// This could be expanded to send email notifications.
			do_action( 'atomicedge_scan_issues_found', $results );
		}

		AtomicEdge::log( 'Daily scan completed', $results['summary'] );
	}

	/**
	 * Sync settings with AtomicEdge API.
	 *
	 * @return void
	 */
	public function sync_settings() {
		if ( ! $this->api->is_connected() ) {
			return;
		}

		AtomicEdge::log( 'Syncing settings with AtomicEdge' );

		// Refresh site info.
		$site_info = $this->api->get_site_info();

		if ( $site_info['success'] && isset( $site_info['data'] ) ) {
			update_option( 'atomicedge_site_data', $site_info['data'] );
			AtomicEdge::log( 'Settings sync completed' );
		} else {
			AtomicEdge::log( 'Settings sync failed', $site_info );
		}
	}

	/**
	 * Schedule the settings sync.
	 *
	 * @return void
	 */
	public static function schedule_sync() {
		if ( ! wp_next_scheduled( 'atomicedge_sync_settings' ) ) {
			wp_schedule_event( time(), 'hourly', 'atomicedge_sync_settings' );
		}
	}

	/**
	 * Unschedule all cron events.
	 *
	 * @return void
	 */
	public static function unschedule_all() {
		wp_clear_scheduled_hook( 'atomicedge_daily_scan' );
		wp_clear_scheduled_hook( 'atomicedge_sync_settings' );
	}
}
