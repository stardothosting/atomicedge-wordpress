# AtomicEdge WordPress Plugin - Test Suite

This directory contains the automated test suite for the AtomicEdge WordPress plugin.

## Requirements

- PHP 7.4+
- Composer

## Installation

```bash
# Install dependencies
composer install
```

## Running Tests

```bash
# Run all tests
composer test

# Run only unit tests
composer test:unit

# Run only integration tests
composer test:integration

# Run tests with code coverage
composer test:coverage

# Generate HTML coverage report
composer test:coverage-html
```

## Test Structure

```
tests/
├── bootstrap.php           # Test bootstrap and setup
├── TestCase.php            # Base test case class
├── unit/                   # Unit tests (isolated)
│   ├── ApiTest.php         # API class tests
│   ├── AjaxTest.php        # AJAX handler tests
│   ├── ScannerTest.php     # Scanner class tests
│   └── MainPluginTest.php  # Main plugin class tests
└── integration/            # Integration tests
    └── ConnectionFlowTest.php  # End-to-end flow tests
```

## Test Categories

### Unit Tests (`tests/unit/`)

Unit tests verify individual components in isolation using Brain/Monkey to mock WordPress functions.

- **ApiTest.php**: Tests for `AtomicEdge_API` class
  - API key encryption/decryption
  - IP validation (IPv4, IPv6, CIDR)
  - Connection/disconnection flow
  - Analytics, WAF logs, IP rules API methods
  - Error handling

- **AjaxTest.php**: Tests for `AtomicEdge_Ajax` class
  - Security validation (nonce, capabilities)
  - Input sanitization
  - All AJAX endpoints

- **ScannerTest.php**: Tests for `AtomicEdge_Scanner` class
  - Pattern detection for malicious code
  - Baseline creation and comparison
  - Scan result persistence

- **MainPluginTest.php**: Tests for `AtomicEdge` class
  - Singleton pattern
  - Component initialization
  - Logging

### Integration Tests (`tests/integration/`)

Integration tests verify that components work together correctly.

- **ConnectionFlowTest.php**: End-to-end connection flows
  - Full connection lifecycle
  - Cache behavior
  - State persistence

## Writing Tests

### Base Test Case

All tests should extend `AtomicEdge\Tests\TestCase` which provides:

- Brain/Monkey setup/teardown
- Global option/transient storage mocking
- Helper methods for common operations

### Example Test

```php
<?php
namespace AtomicEdge\Tests\Unit;

use AtomicEdge\Tests\TestCase;
use Brain\Monkey\Functions;

class MyClassTest extends TestCase {

    protected function set_up() {
        parent::set_up();
        // Your setup code
    }

    public function test_something() {
        // Mock WordPress functions
        Functions\when('some_wp_function')->justReturn('value');
        
        // Test your code
        $result = my_function();
        
        $this->assertEquals('expected', $result);
    }
}
```

### Mocking WordPress Functions

Use Brain/Monkey to mock WordPress functions:

```php
// Simple return value
Functions\when('get_option')->justReturn('value');

// Custom callback
Functions\when('sanitize_text_field')->alias(function($str) {
    return htmlspecialchars(strip_tags($str));
});

// Expect specific calls
Functions\expect('update_option')
    ->once()
    ->with('my_option', 'my_value')
    ->andReturn(true);
```

### Test Options/Transients

Use the base class helpers:

```php
// Set option for test
$this->set_option('my_option', 'value');

// Get option in test
$value = $this->get_option('my_option');

// Set transient for test
$this->set_transient('my_transient', 'value');
```

## Code Coverage

After running `composer test:coverage-html`, open `tests/coverage/html/index.html` in a browser to view the coverage report.

### Coverage Goals

- Aim for 80%+ code coverage on core classes
- 100% coverage on security-critical code (API key handling, validation)
- Focus on testing edge cases and error paths

## Continuous Integration

Tests should be run on:
- Every pull request
- Before merging to main branch
- On release tags

## Troubleshooting

### Tests fail with "Class not found"

Run `composer dump-autoload` to regenerate the autoloader.

### Brain/Monkey errors

Ensure you're calling `parent::set_up()` and `parent::tear_down()` in your test methods.

### Mock not working

Brain/Monkey mocks are reset between tests. Set up mocks in `set_up()` or within each test method.
