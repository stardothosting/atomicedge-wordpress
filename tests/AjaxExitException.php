<?php
/**
 * Exception to simulate wp_send_json exit behavior in AJAX tests.
 *
 * @package AtomicEdge\Tests
 */

namespace AtomicEdge\Tests;

/**
 * Exception to simulate wp_send_json exit behavior.
 *
 * Used by AJAX handler tests to halt execution after wp_send_json_success
 * or wp_send_json_error is called, simulating the exit() call that
 * WordPress normally performs.
 */
class AjaxExitException extends \Exception {
}
