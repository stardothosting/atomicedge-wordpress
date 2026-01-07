<?php
/**
 * Uninstall Atomic Edge Security
 *
 * Removes all plugin data when the plugin is deleted.
 *
 * @package AtomicEdge
 */

// If uninstall not called from WordPress, exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Delete all plugin options.
$options_to_delete = array(
	'atomicedge_api_key',
	'atomicedge_api_url',
	'atomicedge_connected',
	'atomicedge_site_data',
	'atomicedge_last_scan',
	'atomicedge_scan_results',
);

foreach ( $options_to_delete as $option ) {
	delete_option( $option );
}

// Delete all transients.
global $wpdb;

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		'_transient_atomicedge_%',
		'_transient_timeout_atomicedge_%'
	)
);

// Clear any scheduled cron events.
wp_clear_scheduled_hook( 'atomicedge_daily_scan' );
wp_clear_scheduled_hook( 'atomicedge_sync_settings' );
