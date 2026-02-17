<?php
/**
 * Tests for AtomicEdge_Dev_Mode class.
 *
 * This class has 0% coverage currently. These tests verify the core functionality
 * for detecting local/development environments.
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

/**
 * Test case for development mode.
 */
class DevModeTest extends TestCase {

	/**
	 * Test that is_local_environment returns true for .local domains.
	 *
	 * @return void
	 */
	public function test_is_local_environment_detects_local_domain() {
		Functions\when( 'get_site_url' )->justReturn( 'http://mysite.local' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertTrue(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'.local domains should be detected as local environment'
		);
	}

	/**
	 * Test that is_local_environment returns true for .test domains.
	 *
	 * @return void
	 */
	public function test_is_local_environment_detects_test_domain() {
		Functions\when( 'get_site_url' )->justReturn( 'http://mysite.test' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertTrue(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'.test domains should be detected as local environment'
		);
	}

	/**
	 * Test that is_local_environment returns true for .dev domains.
	 *
	 * @return void
	 */
	public function test_is_local_environment_detects_dev_domain() {
		Functions\when( 'get_site_url' )->justReturn( 'http://mysite.dev' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertTrue(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'.dev domains should be detected as local environment'
		);
	}

	/**
	 * Test that is_local_environment returns true for localhost.
	 *
	 * @return void
	 */
	public function test_is_local_environment_detects_localhost() {
		Functions\when( 'get_site_url' )->justReturn( 'http://localhost' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertTrue(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'localhost should be detected as local environment'
		);
	}

	/**
	 * Test that is_local_environment returns true for 127.0.0.1.
	 *
	 * @return void
	 */
	public function test_is_local_environment_detects_loopback_ip() {
		Functions\when( 'get_site_url' )->justReturn( 'http://127.0.0.1' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertTrue(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'127.0.0.1 should be detected as local environment'
		);
	}

	/**
	 * Test that is_local_environment returns true for DDEV sites.
	 *
	 * @return void
	 */
	public function test_is_local_environment_detects_ddev_domain() {
		Functions\when( 'get_site_url' )->justReturn( 'http://mysite.ddev.site' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertTrue(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'.ddev.site domains should be detected as local environment'
		);
	}

	/**
	 * Test that is_local_environment returns false for production domains.
	 *
	 * @return void
	 */
	public function test_is_local_environment_returns_false_for_production() {
		Functions\when( 'get_site_url' )->justReturn( 'https://example.com' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertFalse(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'Production domains should not be detected as local environment'
		);
	}

	/**
	 * Test that is_local_environment returns false for .com domains.
	 *
	 * @return void
	 */
	public function test_is_local_environment_returns_false_for_com_domains() {
		Functions\when( 'get_site_url' )->justReturn( 'https://mysite.com' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertFalse(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'.com domains should not be detected as local environment'
		);
	}

	/**
	 * Test that is_local_environment returns false for empty URL.
	 *
	 * @return void
	 */
	public function test_is_local_environment_returns_false_for_empty_url() {
		Functions\when( 'get_site_url' )->justReturn( '' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertFalse(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'Empty URL should return false'
		);
	}

	/**
	 * Test that is_local_environment returns true for private IP ranges.
	 *
	 * @return void
	 */
	public function test_is_local_environment_detects_private_ip() {
		Functions\when( 'get_site_url' )->justReturn( 'http://192.168.1.100' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertTrue(
			\AtomicEdge_Dev_Mode::is_local_environment(),
			'Private IP ranges should be detected as local environment'
		);
	}

	/**
	 * Test that is_enabled returns false when not in local environment.
	 *
	 * @return void
	 */
	public function test_is_enabled_returns_false_for_production() {
		Functions\when( 'get_site_url' )->justReturn( 'https://example.com' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );

		$this->assertFalse(
			\AtomicEdge_Dev_Mode::is_enabled(),
			'Dev mode should be disabled for production environments'
		);
	}

	/**
	 * Test that the class file exists.
	 *
	 * @return void
	 */
	public function test_dev_mode_class_exists() {
		$this->assertTrue(
			class_exists( 'AtomicEdge_Dev_Mode' ),
			'AtomicEdge_Dev_Mode class should exist'
		);
	}

	/**
	 * Test that all expected methods exist.
	 *
	 * @return void
	 */
	public function test_dev_mode_has_expected_methods() {
		$expected_methods = array(
			'is_local_environment',
			'is_enabled',
		);

		foreach ( $expected_methods as $method ) {
			$this->assertTrue(
				method_exists( 'AtomicEdge_Dev_Mode', $method ),
				sprintf( 'AtomicEdge_Dev_Mode::%s() should exist', $method )
			);
		}
	}
}
