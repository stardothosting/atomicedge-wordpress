<?php
/**
 * AtomicEdge CDN Rule Definitions
 *
 * Constants and rules used throughout CDN operations.
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

// Unified CDN Suffix - All users use the same suffix now.
// The paid/free tier distinction has been removed.
if ( ! defined( 'ATOMICEDGE_CDN_SUFFIX' ) ) {
	define( 'ATOMICEDGE_CDN_SUFFIX', '.wpcdn.shift8cdn.com' );
}

// Legacy constants kept for backward compatibility (all point to the unified suffix).
if ( ! defined( 'ATOMICEDGE_CDN_SUFFIX_PAID' ) ) {
	define( 'ATOMICEDGE_CDN_SUFFIX_PAID', ATOMICEDGE_CDN_SUFFIX );
}

if ( ! defined( 'ATOMICEDGE_CDN_SUFFIX_FREE' ) ) {
	define( 'ATOMICEDGE_CDN_SUFFIX_FREE', ATOMICEDGE_CDN_SUFFIX );
}

if ( ! defined( 'ATOMICEDGE_CDN_SUFFIX_FREE_ALT' ) ) {
	define( 'ATOMICEDGE_CDN_SUFFIX_FREE_ALT', ATOMICEDGE_CDN_SUFFIX );
}

// Transient key for plan/suffix checking (kept for backward compatibility, no longer needed).
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
