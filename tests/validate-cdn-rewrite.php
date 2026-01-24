#!/usr/bin/env php
<?php
/**
 * CDN Rewrite Validation Script
 *
 * Run this to validate CDN rewriting is working:
 *   cd /path/to/wordpress && wp eval-file wp-content/plugins/atomicedge/tests/validate-cdn-rewrite.php
 *
 * @package AtomicEdge
 */

if ( ! defined( 'ABSPATH' ) ) {
$wp_load = dirname( __DIR__, 4 ) . '/wp-load.php';
if ( file_exists( $wp_load ) ) {
require_once $wp_load;
} else {
echo "ERROR: Cannot find wp-load.php. Run this via: wp eval-file <this-file>\n";
exit( 1 );
}
}

echo "\n=== AtomicEdge CDN Rewrite Validation ===\n\n";

// 1. Check options.
echo "1. OPTIONS:\n";
$options = array(
'atomicedge_cdn_local_enabled' => get_option( 'atomicedge_cdn_local_enabled' ),
'atomicedge_cdn_css'           => get_option( 'atomicedge_cdn_css' ),
'atomicedge_cdn_js'            => get_option( 'atomicedge_cdn_js' ),
'atomicedge_cdn_media'         => get_option( 'atomicedge_cdn_media' ),
);
$site_data = get_option( 'atomicedge_site_data', array() );
$cdn_url   = $site_data['cdn_url'] ?? '(not set)';

echo "   site_url() = " . get_site_url() . "\n";
echo "   cdn_url (from dashboard) = " . $cdn_url . "\n";

foreach ( $options as $key => $value ) {
$status = '';
if ( in_array( $key, array( 'atomicedge_cdn_css', 'atomicedge_cdn_js', 'atomicedge_cdn_media' ), true ) ) {
$status = ( 'on' === $value ) ? ' ✓' : ' ✗ (OFF)';
}
printf( "   %-30s = %s%s\n", $key, $value ?: '(empty)', $status );
}

// 2. Check if CDN is enabled.
echo "\n2. CDN ENABLED CHECK:\n";
$cdn_enabled = AtomicEdge_CDN::is_cdn_enabled();
echo '   is_cdn_enabled() = ' . ( $cdn_enabled ? 'YES ✓' : 'NO ✗' ) . "\n";

if ( ! $cdn_enabled ) {
echo "\n   WARNING: CDN is not enabled. Check settings above.\n";
echo "   - atomicedge_cdn_local_enabled must be 'on'\n";
echo "   - Must be connected to dashboard with CDN enabled\n";
echo "   - Dashboard must provide cdn_url in site_data\n";
}

// 3. Test rewriting.
echo "\n3. REWRITE TESTS:\n";

if ( ! class_exists( 'AtomicEdge_CDN_Rewrite' ) ) {
require_once dirname( __DIR__ ) . '/includes/class-atomicedge-cdn-rewrite.php';
}

$rewriter = new AtomicEdge_CDN_Rewrite();
$site_url = get_site_url();

$tests = array(
'CSS'   => "<link href=\"{$site_url}/wp-content/themes/test/style.css\">",
'JS'    => "<script src=\"{$site_url}/wp-includes/js/test.js\"></script>",
'Image' => "<img src=\"{$site_url}/wp-content/uploads/2026/01/test.jpg\">",
);

$all_passed = true;
foreach ( $tests as $type => $input ) {
$output     = $rewriter->rewrite( $input );
$rewritten  = ( $input !== $output );
$type_lower = strtolower( $type );
$toggle     = get_option( "atomicedge_cdn_{$type_lower}", 'on' );

if ( 'on' === $toggle ) {
if ( $rewritten ) {
echo "   {$type}: PASS ✓ (rewritten)\n";
} else {
echo "   {$type}: FAIL ✗ (NOT rewritten but toggle is ON)\n";
$all_passed = false;
}
} else {
if ( ! $rewritten ) {
echo "   {$type}: PASS ✓ (NOT rewritten - toggle OFF as expected)\n";
} else {
echo "   {$type}: FAIL ✗ (rewritten but toggle is OFF)\n";
$all_passed = false;
}
}

if ( $rewritten ) {
echo "      Before: " . substr( $input, 0, 80 ) . "\n";
echo "      After:  " . substr( $output, 0, 80 ) . "\n";
}
}

echo "\n=== Summary: " . ( $all_passed ? "ALL PASSED ✓" : "SOME FAILED ✗" ) . " ===\n\n";
exit( $all_passed ? 0 : 1 );
