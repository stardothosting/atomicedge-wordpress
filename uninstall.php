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
$atomicedge_options_to_delete = array(
	'atomicedge_api_key',
	'atomicedge_api_url',
	'atomicedge_connected',
	'atomicedge_site_data',
	'atomicedge_last_scan',
	'atomicedge_scan_results',
);

foreach ( $atomicedge_options_to_delete as $atomicedge_option ) {
	delete_option( $atomicedge_option );
}

// Delete all transients.
global $wpdb;

// Drop scanner queue table.
$atomicedge_table_name = $wpdb->prefix . 'atomicedge_scan_queue';
if ( preg_match( '/^[A-Za-z0-9_]+$/', $atomicedge_table_name ) ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
	$wpdb->query( 'DROP TABLE IF EXISTS `' . $atomicedge_table_name . '`' );
}

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
if ( preg_match( '/^[A-Za-z0-9_]+$/', $wpdb->options ) ) {
	$wpdb->query(
		$wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			'DELETE FROM `' . $wpdb->options . '` WHERE option_name LIKE %s OR option_name LIKE %s',
			'_transient_atomicedge_%',
			'_transient_timeout_atomicedge_%'
		)
	);
}

// Clear any scheduled cron events.
wp_clear_scheduled_hook( 'atomicedge_daily_scan' );
wp_clear_scheduled_hook( 'atomicedge_sync_settings' );
