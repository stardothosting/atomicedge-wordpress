<?php
/**
 * AtomicEdge CDN URL Rewriter
 *
 * Handles URL rewriting to serve static assets through the CDN.
 * Ported from Shift8 CDN for 1:1 compatibility.
 *
 * @package AtomicEdge
 * @since   2.0.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicEdge_CDN_Rewrite
 *
 * Rewrites static asset URLs to serve through CDN.
 */
class AtomicEdge_CDN_Rewrite {

	/**
	 * CDN options from settings.
	 *
	 * @var array
	 */
	private $options;

	/**
	 * CDN URL to substitute.
	 *
	 * @var string
	 */
	private $cdn_url;

	/**
	 * Constructor - sets up rewrite hooks.
	 */
	public function __construct() {
		// Set up options and CDN URL.
		$this->options = AtomicEdge_CDN::get_cdn_options();
		$this->cdn_url = $this->get_cdn_url();

		// Only proceed if CDN URL is available.
		if ( empty( $this->cdn_url ) ) {
			return;
		}

		// Template redirect to start output buffering.
		add_action( 'template_redirect', array( $this, 'template_redirect' ) );

		// Filter for URL rewriting.
		add_filter( 'atomicedge_cdn_rewrite_urls', array( $this, 'filter' ) );

		// Rewrite responsive image srcsets.
		add_filter( 'wp_calculate_image_srcset', array( $this, 'rewrite_srcset' ), PHP_INT_MAX );

		// Rewrite emoji script URL.
		add_filter( 'script_loader_src', array( $this, 'cdn_script_loader_src' ), 10, 2 );
	}

	/**
	 * Get the CDN URL to use for rewriting.
	 *
	 * Supports two modes:
	 * 1. Dev mode: Uses ATOMICEDGE_CDN_DEV_URL constant from wp-config.php.
	 * 2. Production mode: Uses CDN URL from dashboard API response.
	 *
	 * @return string CDN URL.
	 */
	private function get_cdn_url() {
		// DEV MODE: If ATOMICEDGE_CDN_DEV_URL constant is defined, use it.
		// Usage: define('ATOMICEDGE_CDN_DEV_URL', 'https://cdn.atomicedge.io'); in wp-config.php
		if ( defined( 'ATOMICEDGE_CDN_DEV_URL' ) && ATOMICEDGE_CDN_DEV_URL ) {
			$cdn_url = rtrim( ATOMICEDGE_CDN_DEV_URL, '/' );
			// Ensure URL has a scheme.
			if ( ! preg_match( '#^https?://#i', $cdn_url ) ) {
				$cdn_url = 'https://' . $cdn_url;
			}
			return $cdn_url;
		}

		// Production mode: Get from API response.
		$site_data = get_option( 'atomicedge_site_data', array() );

		// Use cdn_url from API response if available.
		if ( ! empty( $site_data['cdn_url'] ) ) {
			$cdn_url = rtrim( $site_data['cdn_url'], '/' );
			// Ensure URL has a scheme (API may return just hostname).
			if ( ! preg_match( '#^https?://#i', $cdn_url ) ) {
				$cdn_url = 'https://' . $cdn_url;
			}
			return $cdn_url;
		}

		// Fall back to building URL from prefix + suffix.
		$cdn_prefix = $site_data['cdn_prefix'] ?? '';
		if ( empty( $cdn_prefix ) ) {
			return '';
		}

		// All users use the unified CDN suffix now.
		return 'https://' . $cdn_prefix . ATOMICEDGE_CDN_SUFFIX;
	}

	/**
	 * Start output buffering on template redirect.
	 *
	 * @return void
	 */
	public function template_redirect() {
		ob_start( array( $this, 'ob_callback' ) );
	}

	/**
	 * Output buffer callback - applies URL rewriting filter.
	 *
	 * @param string $contents Page content.
	 * @return string Modified content.
	 */
	public function ob_callback( $contents ) {
		return apply_filters( 'atomicedge_cdn_rewrite_urls', $contents, $this );
	}

	/**
	 * Filter callback for URL rewriting.
	 *
	 * @param string $content HTML content.
	 * @return string Modified content with rewritten URLs.
	 */
	public function filter( $content ) {
		return $this->rewrite( $content );
	}

	/**
	 * Search and replace URLs with CDN URLs.
	 *
	 * @param string $html HTML content.
	 * @return string Modified HTML.
	 */
	public function rewrite( $html ) {
		// Always use WordPress's site_url() - no user override needed.
		$site_url  = get_site_url();
		$base_url  = wp_parse_url( $site_url );
		$origin    = $base_url['scheme'] . '://' . $base_url['host'];

		$pattern = '#[("\']\s*(?<url>(?:(?:https?:|)' . preg_quote( $origin, '#' ) . ')\/(?:(?:(?:' . $this->get_allowed_paths() . ')[^"\',)]+))|\/[^/](?:[^"\')\s>]+\.[[:alnum:]]+))\s*["\')]#i';

		return preg_replace_callback(
			$pattern,
			array( $this, 'rewrite_callback' ),
			$html
		);
	}

	/**
	 * Callback for URL rewrite regex.
	 *
	 * @param array $matches Regex matches.
	 * @return string Replacement string.
	 */
	public function rewrite_callback( $matches ) {
		$url = $matches['url'];

		// Check if excluded (includes file type toggles like Shift8 CDN).
		if ( $this->is_excluded( $url ) ) {
			return $matches[0];
		}

		// Check if this is a CSS/JS file and minification is enabled.
		$extension = strtolower( pathinfo( wp_parse_url( $url, PHP_URL_PATH ), PATHINFO_EXTENSION ) );
		if ( in_array( $extension, array( 'css', 'js' ), true ) ) {
			$minified_url = $this->get_minified_url( $url, $extension );
			if ( $minified_url !== $url ) {
				$url = $minified_url;
			}
		}

		// Apply CDN rewriting.
		$uri          = wp_parse_url( $url );
		$query_string = wp_parse_url( $url, PHP_URL_QUERY ) ? '?' . wp_parse_url( $url, PHP_URL_QUERY ) : '';

		return str_replace( $matches['url'], $this->cdn_url . $uri['path'] . $query_string, $matches[0] );
	}

	/**
	 * Rewrite responsive image srcsets.
	 *
	 * @param array $sources Image srcset sources.
	 * @return array Modified sources.
	 */
	public function rewrite_srcset( $sources ) {
		if ( ! is_array( $sources ) || empty( $sources ) ) {
			return $sources;
		}

		// Always use WordPress's site_url() - no user override needed.
		$site_url  = get_site_url();
		$base_url  = wp_parse_url( $site_url );
		$origin    = $base_url['scheme'] . '://' . $base_url['host'];

		foreach ( $sources as $i => $source ) {
			if ( ! $this->is_excluded( $source['url'] ) ) {
				$sources[ $i ]['url'] = str_replace( $origin, $this->cdn_url, $source['url'] );
			}
		}

		return $sources;
	}

	/**
	 * Rewrite emoji script URL.
	 *
	 * @param string $source    Script source URL.
	 * @param string $scriptname Script handle.
	 * @return string Modified URL.
	 */
	public function cdn_script_loader_src( $source, $scriptname ) {
		if ( 'concatemoji' === $scriptname ) {
			// Always use WordPress's site_url() - no user override needed.
			$site_url  = get_site_url();
			$base_url  = wp_parse_url( $site_url );
			$origin    = $base_url['scheme'] . '://' . $base_url['host'];

			$source = str_replace( $origin, $this->cdn_url, $source );
		}

		return $source;
	}

	/**
	 * Check if a URL should be excluded from CDN rewriting.
	 * Matches Shift8 CDN approach: handles both file exclusions AND file type toggles.
	 *
	 * @param string $url URL to check.
	 * @return bool True if excluded.
	 */
	public function is_excluded( $url ) {
		$path = wp_parse_url( $url, PHP_URL_PATH );

		// No path = excluded.
		if ( ! $path ) {
			return true;
		}

		// Root path = excluded.
		if ( '/' === $path ) {
			return true;
		}

		// Check against user-defined exclusion patterns.
		$excluded_files = $this->get_excluded_files();
		if ( ! empty( $excluded_files ) && $this->match_url_pattern( $excluded_files, $path ) ) {
			return true;
		}

		// Build excluded extensions based on file type toggles (Shift8 CDN approach).
		$excluded_extensions = array();

		// If CSS is NOT enabled, exclude CSS files.
		if ( 'on' !== $this->options['cdn_css'] ) {
			$excluded_extensions[] = 'css';
		}

		// If JS is NOT enabled, exclude JS files.
		if ( 'on' !== $this->options['cdn_js'] ) {
			$excluded_extensions[] = 'js';
		}

		// If Media is NOT enabled, exclude media files.
		if ( 'on' !== $this->options['cdn_media'] ) {
			$media_extensions      = array( 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'pdf', 'mp3', 'm4a', 'ogg', 'wav', 'mp4', 'm4v', 'mov', 'wmv', 'avi', 'mpg', 'ogv', '3gp', '3g2', 'webp', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot' );
			$excluded_extensions   = array_merge( $excluded_extensions, $media_extensions );
		}

		// Check if file extension is in excluded list.
		if ( ! empty( $excluded_extensions ) ) {
			$extension = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
			if ( in_array( $extension, $excluded_extensions, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get allowed paths for CDN rewriting.
	 *
	 * @return string Regex pattern for allowed paths.
	 */
	private function get_allowed_paths() {
		$wp_content_dirname  = ltrim( trailingslashit( wp_parse_url( content_url(), PHP_URL_PATH ) ), '/' );
		$wp_includes_dirname = ltrim( trailingslashit( wp_parse_url( includes_url(), PHP_URL_PATH ) ), '/' );

		$upload_dirname = '';
		$uploads_info   = wp_upload_dir();

		if ( ! empty( $uploads_info['baseurl'] ) ) {
			$upload_dirname = '|' . ltrim( trailingslashit( wp_parse_url( $uploads_info['baseurl'], PHP_URL_PATH ) ), '/' );
		}

		return $wp_content_dirname . $upload_dirname . '|' . $wp_includes_dirname;
	}

	/**
	 * Get excluded file patterns.
	 *
	 * @return array Excluded patterns.
	 */
	private function get_excluded_files() {
		$files = get_option( 'atomicedge_cdn_reject_files', '' );
		if ( empty( $files ) ) {
			return array();
		}

		$files = explode( "\n", $files );
		$files = array_filter( array_map( 'trim', $files ) );

		return $files;
	}

	/**
	 * Match URL against exclusion patterns with wildcard support.
	 *
	 * @param array  $patterns   Patterns to match against.
	 * @param string $url_path   URL path to check.
	 * @return bool True if matches.
	 */
	private function match_url_pattern( $patterns, $url_path ) {
		$escaped = array_map(
			function ( $pattern ) {
				return str_replace( '\*', '.*', preg_quote( $pattern, '#' ) );
			},
			$patterns
		);

		$regex = '#' . implode( '|', $escaped ) . '#';

		return (bool) preg_match( $regex, $url_path );
	}

	/**
	 * Get minified URL for a file if minification is enabled.
	 *
	 * @param string $url       Original URL.
	 * @param string $extension File extension (css or js).
	 * @return string Minified URL or original.
	 */
	private function get_minified_url( $url, $extension ) {
		// Check if minification is enabled for this type.
		// Must check for 'on' explicitly - 'off' and empty string are both disabled.
		$minify_option = 'css' === $extension ? 'cdn_minify_css' : 'cdn_minify_js';
		if ( 'on' !== ( $this->options[ $minify_option ] ?? '' ) ) {
			return $url;
		}

		// Skip if already minified.
		if ( $this->is_already_minified( $url ) ) {
			return $url;
		}

		// Get or create minified version.
		return AtomicEdge_CDN::get_minified_url( $url, $extension );
	}

	/**
	 * Check if a file is already minified based on filename.
	 *
	 * @param string $url URL to check.
	 * @return bool True if already minified.
	 */
	private function is_already_minified( $url ) {
		// Check for .min.css or .min.js.
		if ( preg_match( '/\.min\.(css|js)$/i', $url ) ) {
			return true;
		}

		// Check for common minified file patterns.
		if ( preg_match( '/[-_\.]min[-_\.]/i', $url ) ) {
			return true;
		}

		return false;
	}
}
