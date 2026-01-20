<?php
/**
 * AtomicEdge CLI Tests
 *
 * @package AtomicEdge\Tests\Unit
 */

namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;

class CliTest extends TestCase {

	protected function set_up() {
		parent::set_up();

		if ( ! defined( 'WP_CLI' ) ) {
			define( 'WP_CLI', true );
		}

		\AtomicEdge\Tests\WP_CLI::reset();

		if ( ! class_exists( '\\AtomicEdge_CLI' ) ) {
			require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-cli.php';
		}
	}

	public function test_scan_full_reports_success_when_no_results() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'run_full_scan' )->willReturn(
			array(
				'core_files' => array(),
				'suspicious' => array(),
			)
		);

		$reflection = new \ReflectionClass( $cli );
		$property = $reflection->getProperty( 'scanner' );
		$property->setAccessible( true );
		$property->setValue( $cli, $scanner );

		$cli->scan( array(), array( 'type' => 'full' ) );

		$this->assertSame( array( 'No issues found!' ), \AtomicEdge\Tests\WP_CLI::$successes );
		$this->assertSame( array(), \AtomicEdge\Tests\WP_CLI::$errors );
	}

	public function test_scan_core_invokes_core_scan() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->expects( $this->once() )->method( 'scan_core_files' )->willReturn( array() );

		$reflection = new \ReflectionClass( $cli );
		$property = $reflection->getProperty( 'scanner' );
		$property->setAccessible( true );
		$property->setValue( $cli, $scanner );

		$cli->scan( array(), array( 'type' => 'core' ) );

		$this->assertSame( array( 'No issues found!' ), \AtomicEdge\Tests\WP_CLI::$successes );
	}

	public function test_stats_logs_summary() {
		$cli = new \AtomicEdge_CLI();

		$scanner = $this->createMock( \AtomicEdge_Scanner::class );
		$scanner->method( 'get_scan_statistics' )->willReturn(
			array(
				'total_patterns'   => 3,
				'categories'       => array( 'core' => 1, 'plugins' => 2 ),
				'scan_areas'       => array( 'core', 'plugins' ),
				'whitelisted_paths' => 0,
			)
		);

		$reflection = new \ReflectionClass( $cli );
		$property = $reflection->getProperty( 'scanner' );
		$property->setAccessible( true );
		$property->setValue( $cli, $scanner );

		$cli->stats( array(), array() );

		$this->assertNotEmpty( \AtomicEdge\Tests\WP_CLI::$logs );
		$this->assertStringContainsString( 'Total Patterns', implode( "\n", \AtomicEdge\Tests\WP_CLI::$logs ) );
	}
}
