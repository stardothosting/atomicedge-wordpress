<?php
/**
 * PHPUnit Bootstrap for AtomicEdge WordPress Plugin
 *
 * Sets up Brain/Monkey for mocking WordPress functions and loads test dependencies.
 *
 * @package AtomicEdge\Tests
 */

namespace AtomicEdge\Tests;

// Composer autoloader.
require_once dirname( __DIR__ ) . '/vendor/autoload.php';

use Brain\Monkey;
use Brain\Monkey\Functions;

// Initialize Brain/Monkey.
Monkey\setUp();

// Define testing flag.
if ( ! defined( 'ATOMICEDGE_TESTING' ) ) {
	define( 'ATOMICEDGE_TESTING', true );
}

// Define WordPress constants for testing.
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', '/tmp/wordpress/' );
}

if ( ! defined( 'WP_DEBUG' ) ) {
	define( 'WP_DEBUG', true );
}

if ( ! defined( 'WP_DEBUG_LOG' ) ) {
	define( 'WP_DEBUG_LOG', false );
}

// Plugin constants.
if ( ! defined( 'ATOMICEDGE_VERSION' ) ) {
	define( 'ATOMICEDGE_VERSION', '1.0.0' );
}

if ( ! defined( 'ATOMICEDGE_PLUGIN_FILE' ) ) {
	define( 'ATOMICEDGE_PLUGIN_FILE', dirname( __DIR__ ) . '/atomicedge.php' );
}

if ( ! defined( 'ATOMICEDGE_PLUGIN_DIR' ) ) {
	define( 'ATOMICEDGE_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'ATOMICEDGE_PLUGIN_URL' ) ) {
	define( 'ATOMICEDGE_PLUGIN_URL', 'http://example.com/wp-content/plugins/atomicedge/' );
}

if ( ! defined( 'ATOMICEDGE_PLUGIN_BASENAME' ) ) {
	define( 'ATOMICEDGE_PLUGIN_BASENAME', 'atomicedge/atomicedge.php' );
}

// Minimal WP_CLI stub for tests that include CLI commands.
if ( ! class_exists( __NAMESPACE__ . '\\WP_CLI' ) ) {
	class WP_CLI {
		public static $logs = array();
		public static $successes = array();
		public static $errors = array();
		public static $commands = array();

		public static function log( $message ) {
			self::$logs[] = $message;
		}

		public static function success( $message ) {
			self::$successes[] = $message;
		}

		public static function error( $message, $exit = true ) {
			self::$errors[] = array( 'message' => $message, 'exit' => $exit );
		}

		public static function add_command( $name, $class ) {
			self::$commands[] = array( 'name' => $name, 'class' => $class );
		}

		public static function reset() {
			self::$logs = array();
			self::$successes = array();
			self::$errors = array();
			self::$commands = array();
		}
	}
}

if ( ! class_exists( 'WP_CLI' ) ) {
	class_alias( __NAMESPACE__ . '\\WP_CLI', 'WP_CLI' );
}

// WordPress core constants.
if ( ! defined( 'WPINC' ) ) {
	define( 'WPINC', 'wp-includes' );
}

if ( ! defined( 'WP_CONTENT_DIR' ) ) {
	define( 'WP_CONTENT_DIR', '/tmp/wordpress/wp-content' );
}

if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', '/tmp/wordpress/wp-content/plugins' );
}


// WordPress time constants.
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
	define( 'MINUTE_IN_SECONDS', 60 );
}

if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 60 * MINUTE_IN_SECONDS );
}

if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 24 * HOUR_IN_SECONDS );
}

if ( ! defined( 'WEEK_IN_SECONDS' ) ) {
	define( 'WEEK_IN_SECONDS', 7 * DAY_IN_SECONDS );
}

if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 24 * HOUR_IN_SECONDS );
}

if ( ! defined( 'WEEK_IN_SECONDS' ) ) {
	define( 'WEEK_IN_SECONDS', 7 * DAY_IN_SECONDS );
}

if ( ! defined( 'MONTH_IN_SECONDS' ) ) {
	define( 'MONTH_IN_SECONDS', 30 * DAY_IN_SECONDS );
}

if ( ! defined( 'YEAR_IN_SECONDS' ) ) {
	define( 'YEAR_IN_SECONDS', 365 * DAY_IN_SECONDS );
}

// WordPress encryption constants for API key tests.
if ( ! defined( 'AUTH_KEY' ) ) {
	define( 'AUTH_KEY', 'test_auth_key_1234567890abcdefghijklmnopqrstuvwxyz' );
}

if ( ! defined( 'SECURE_AUTH_KEY' ) ) {
	define( 'SECURE_AUTH_KEY', 'test_secure_auth_key_1234567890abcdefghijklmnopqrstuvwxyz' );
}

if ( ! defined( 'NONCE_KEY' ) ) {
	define( 'NONCE_KEY', 'test_nonce_key_1234567890abcdefghijklmnopqrstuvwxyz' );
}

// Global test options storage (simulates WordPress options table).
global $_test_options;
$_test_options = array();

// Global test transients storage.
global $_test_transients;
$_test_transients = array();

/**
 * Setup default WordPress function mocks.
 *
 * These are mocked globally but can be overridden in individual tests using Brain\Monkey\Functions\expect().
 */
function setup_default_mocks() {
	global $_test_options, $_test_transients;

	// Option functions.
	Functions\when( 'get_option' )->alias(
		function ( $option, $default = false ) {
			global $_test_options;
			return isset( $_test_options[ $option ] ) ? $_test_options[ $option ] : $default;
		}
	);

	Functions\when( 'update_option' )->alias(
		function ( $option, $value ) {
			global $_test_options;
			$_test_options[ $option ] = $value;
			return true;
		}
	);

	Functions\when( 'add_option' )->alias(
		function ( $option, $value ) {
			global $_test_options;
			if ( ! isset( $_test_options[ $option ] ) ) {
				$_test_options[ $option ] = $value;
				return true;
			}
			return false;
		}
	);

	Functions\when( 'delete_option' )->alias(
		function ( $option ) {
			global $_test_options;
			unset( $_test_options[ $option ] );
			return true;
		}
	);

	// Transient functions.
	Functions\when( 'get_transient' )->alias(
		function ( $transient ) {
			global $_test_transients;
			return isset( $_test_transients[ $transient ] ) ? $_test_transients[ $transient ] : false;
		}
	);

	Functions\when( 'set_transient' )->alias(
		function ( $transient, $value, $expiration = 0 ) {
			global $_test_transients;
			$_test_transients[ $transient ] = $value;
			return true;
		}
	);

	Functions\when( 'delete_transient' )->alias(
		function ( $transient ) {
			global $_test_transients;
			unset( $_test_transients[ $transient ] );
			return true;
		}
	);

	// Sanitization functions.
	Functions\when( 'wp_strip_all_tags' )->alias(
		function ( $text ) {
			// Minimal tag stripper for tests (avoid strip_tags() per WP standards).
			$sanitized = preg_replace( '/<[^>]*>/', '', (string) $text );
			return is_string( $sanitized ) ? $sanitized : '';
		}
	);

	Functions\when( 'wp_normalize_path' )->alias(
		function ( $path ) {
			$path = str_replace( '\\', '/', $path );
			return preg_replace( '|/+|', '/', $path );
		}
	);

	Functions\when( 'get_theme_root' )->justReturn( WP_CONTENT_DIR . '/themes' );

	// get_home_path() returns WordPress root directory with trailing slash.
	Functions\when( 'get_home_path' )->justReturn( ABSPATH );

	// trailingslashit() adds trailing slash if not present.
	Functions\when( 'trailingslashit' )->alias(
		function ( $path ) {
			return rtrim( $path, '/\\' ) . '/';
		}
	);

	// sanitize_key() makes string lowercase with only alphanumeric, dashes, and underscores.
	Functions\when( 'sanitize_key' )->alias(
		function ( $key ) {
			return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $key ) );
		}
	);

	Functions\when( 'sanitize_text_field' )->alias(
		function ( $str ) {
			return trim( wp_strip_all_tags( (string) $str ) );
		}
	);

	Functions\when( 'wp_unslash' )->alias(
		function ( $value ) {
			return is_string( $value ) ? stripslashes( $value ) : $value;
		}
	);

	Functions\when( 'absint' )->alias(
		function ( $value ) {
			return abs( (int) $value );
		}
	);

	Functions\when( 'esc_html' )->alias(
		function ( $text ) {
			return (string) filter_var( (string) $text, FILTER_SANITIZE_FULL_SPECIAL_CHARS );
		}
	);

	Functions\when( 'esc_attr' )->alias(
		function ( $text ) {
			return (string) filter_var( (string) $text, FILTER_SANITIZE_FULL_SPECIAL_CHARS );
		}
	);

	Functions\when( 'esc_url' )->alias(
		function ( $url ) {
			return filter_var( $url, FILTER_SANITIZE_URL );
		}
	);

	Functions\when( 'esc_url_raw' )->alias(
		function ( $url ) {
			return filter_var( $url, FILTER_SANITIZE_URL );
		}
	);

	// Translation functions (passthrough).
	Functions\when( '__' )->alias(
		function ( $text, $domain = 'default' ) {
			return $text;
		}
	);

	Functions\when( 'esc_html__' )->alias(
		function ( $text, $domain = 'default' ) {
			return esc_html( $text );
		}
	);

	Functions\when( 'esc_html_e' )->alias(
		function ( $text, $domain = 'default' ) {
			echo esc_html( $text );
		}
	);

	// JSON functions.
	Functions\when( 'wp_json_encode' )->alias( 'json_encode' );

	// Upload directory functions.
	Functions\when( 'wp_upload_dir' )->alias(
		function () {
			return array(
				'basedir' => WP_CONTENT_DIR . '/uploads',
				'baseurl' => 'http://example.com/wp-content/uploads',
				'path'    => WP_CONTENT_DIR . '/uploads/' . gmdate( 'Y/m' ),
				'url'     => 'http://example.com/wp-content/uploads/' . gmdate( 'Y/m' ),
				'error'   => false,
			);
		}
	);

	Functions\when( 'wp_get_upload_dir' )->alias(
		function () {
			return array(
				'basedir' => WP_CONTENT_DIR . '/uploads',
				'baseurl' => 'http://example.com/wp-content/uploads',
				'path'    => WP_CONTENT_DIR . '/uploads/' . gmdate( 'Y/m' ),
				'url'     => 'http://example.com/wp-content/uploads/' . gmdate( 'Y/m' ),
				'error'   => false,
			);
		}
	);

	// Time functions.
	Functions\when( 'current_time' )->alias(
		function ( $type ) {
			return 'mysql' === $type ? gmdate( 'Y-m-d H:i:s' ) : time();
		}
	);

	// Hook functions (no-op in tests unless specifically mocked).
	Functions\when( 'add_action' )->justReturn( true );
	Functions\when( 'add_filter' )->justReturn( true );
	Functions\when( 'do_action' )->justReturn( null );
	Functions\when( 'apply_filters' )->alias(
		function ( $hook, $value ) {
			return $value;
		}
	);
	Functions\when( 'remove_action' )->justReturn( true );
	Functions\when( 'remove_filter' )->justReturn( true );

	// Plugin functions.
	Functions\when( 'plugin_dir_path' )->justReturn( ATOMICEDGE_PLUGIN_DIR );
	Functions\when( 'plugin_dir_url' )->justReturn( ATOMICEDGE_PLUGIN_URL );
	Functions\when( 'plugin_basename' )->justReturn( ATOMICEDGE_PLUGIN_BASENAME );
	Functions\when( 'register_activation_hook' )->justReturn( true );
	Functions\when( 'register_deactivation_hook' )->justReturn( true );

	// Admin functions.
	Functions\when( 'is_admin' )->justReturn( true );
	Functions\when( 'current_user_can' )->justReturn( true );

	// AJAX functions.
	Functions\when( 'check_ajax_referer' )->justReturn( true );
	Functions\when( 'wp_verify_nonce' )->justReturn( true );

	// Error function.
	Functions\when( 'is_wp_error' )->alias(
		function ( $thing ) {
			return $thing instanceof \WP_Error;
		}
	);
}

// Run default setup.
setup_default_mocks();

// Add additional global mocks.
Functions\when( 'get_locale' )->justReturn( 'en_US' );

// Mock WP_Error class.
if ( ! class_exists( 'WP_Error' ) ) {
	/**
	 * Mock WP_Error class for testing.
	 */
	class WP_Error {
		/**
		 * Error codes and messages.
		 *
		 * @var array
		 */
		public $errors = array();

		/**
		 * Error data.
		 *
		 * @var array
		 */
		public $error_data = array();

		/**
		 * Constructor.
		 *
		 * @param string $code    Error code.
		 * @param string $message Error message.
		 * @param mixed  $data    Error data.
		 */
		public function __construct( $code = '', $message = '', $data = '' ) {
			if ( ! empty( $code ) ) {
				$this->errors[ $code ] = array( $message );
				if ( ! empty( $data ) ) {
					$this->error_data[ $code ] = $data;
				}
			}
		}

		/**
		 * Get error codes.
		 *
		 * @return array
		 */
		public function get_error_codes() {
			return array_keys( $this->errors );
		}

		/**
		 * Get first error code.
		 *
		 * @return string
		 */
		public function get_error_code() {
			$codes = $this->get_error_codes();
			return ! empty( $codes ) ? $codes[0] : '';
		}

		/**
		 * Get error message.
		 *
		 * @param string $code Error code.
		 * @return string
		 */
		public function get_error_message( $code = '' ) {
			if ( empty( $code ) ) {
				$code = $this->get_error_code();
			}
			return isset( $this->errors[ $code ][0] ) ? $this->errors[ $code ][0] : '';
		}

		/**
		 * Get error messages.
		 *
		 * @param string $code Error code.
		 * @return array
		 */
		public function get_error_messages( $code = '' ) {
			if ( empty( $code ) ) {
				return array_reduce( $this->errors, 'array_merge', array() );
			}
			return isset( $this->errors[ $code ] ) ? $this->errors[ $code ] : array();
		}

		/**
		 * Add error.
		 *
		 * @param string $code    Error code.
		 * @param string $message Error message.
		 * @param mixed  $data    Error data.
		 */
		public function add( $code, $message, $data = '' ) {
			$this->errors[ $code ][] = $message;
			if ( ! empty( $data ) ) {
				$this->error_data[ $code ] = $data;
			}
		}

		/**
		 * Check if errors exist.
		 *
		 * @return bool
		 */
		public function has_errors() {
			return ! empty( $this->errors );
		}
	}
}

// Include plugin classes for testing.
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-api.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-scanner.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-vulnerability-scanner.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-ajax.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-admin.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cron.php';
// 2FA classes (dependencies first).
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-2fa-crypto.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-2fa-totp.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-2fa-backup.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-2fa.php';
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-2fa-login.php';
// Main plugin class (depends on all components).
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge.php';
