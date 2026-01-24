<?php
/**
 * AtomicEdge CDN Rule Definitions
 *
 * Constants and rules used throughout CDN operations.
 * Maintains compatibility with Shift8 CDN during migration.
 *
 * @package AtomicEdge
 * @since   2.0.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// AtomicEdge Dashboard API URL.
if ( ! defined( 'ATOMICEDGE_API_URL' ) ) {
	define( 'ATOMICEDGE_API_URL', 'https://dashboard.atomicedge.io' );
}

// CDN Suffixes - Must match Shift8 CDN for backward compatibility during migration.
// These are the legacy suffixes that existed in the Shift8 CDN system.
if ( ! defined( 'ATOMICEDGE_CDN_SUFFIX_PAID' ) ) {
	define( 'ATOMICEDGE_CDN_SUFFIX_PAID', '.wpcdn.shift8cdn.com' );
}

if ( ! defined( 'ATOMICEDGE_CDN_SUFFIX_FREE' ) ) {
	define( 'ATOMICEDGE_CDN_SUFFIX_FREE', '.cdn.shift8web.ca' );
}

if ( ! defined( 'ATOMICEDGE_CDN_SUFFIX_FREE_ALT' ) ) {
	define( 'ATOMICEDGE_CDN_SUFFIX_FREE_ALT', '.cdn.shift8web.com' );
}

// Transient key for plan/suffix checking.
if ( ! defined( 'ATOMICEDGE_CDN_PLAN_CHECK' ) ) {
	define( 'ATOMICEDGE_CDN_PLAN_CHECK', 'atomicedge_cdn_plan_check' );
}

// CDN cache directory name (for minified files).
if ( ! defined( 'ATOMICEDGE_CDN_CACHE_DIR' ) ) {
	define( 'ATOMICEDGE_CDN_CACHE_DIR', 'atomicedge-cdn-cache' );
}

// Cooldown period for cache purge (in minutes).
if ( ! defined( 'ATOMICEDGE_CDN_PURGE_COOLDOWN' ) ) {
	define( 'ATOMICEDGE_CDN_PURGE_COOLDOWN', 5 );
}
