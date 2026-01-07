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
├── bootstrap.php              # Test bootstrap and setup
├── TestCase.php               # Base test case class
├── unit/                      # Unit tests (isolated)
│   ├── ApiTest.php            # API class tests
│   ├── AjaxTest.php           # AJAX handler tests
│   ├── ScannerTest.php        # Scanner class tests
│   ├── VulnerabilityScannerTest.php  # Vulnerability scanner tests
│   └── MainPluginTest.php     # Main plugin class tests
└── integration/               # Integration tests
    ├── ConnectionFlowTest.php      # End-to-end flow tests
    └── ApiResponseContractTest.php # API response format validation (CRITICAL)
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

- **ApiResponseContractTest.php**: API response format validation (**CRITICAL**)
  - Validates plugin correctly unwraps Laravel API response format
  - Prevents double-nested data bugs
  - Tests AJAX response structure matches JavaScript expectations
  - See "API Response Contract Testing" in Best Practices section

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

### Current Coverage (as of 2026-01-07)

| Class | Methods | Lines |
|-------|---------|-------|
| AtomicEdge_API | 76.19% | 96.83% |
| AtomicEdge_Ajax | 25.00% | 66.42% |
| AtomicEdge_Vulnerability_Scanner | 57.14% | 64.37% |
| AtomicEdge_Scanner | 34.62% | 44.32% |
| AtomicEdge | 55.56% | 23.08% |
| **Overall** | **40.00%** | **46.04%** |

### Coverage Goals

- Aim for 80%+ code coverage on core classes
- 100% coverage on security-critical code (API key handling, validation)
- Focus on testing edge cases and error paths

## Best Practices for WordPress Plugin Testing

### 1. Use Brain/Monkey for Mocking
Brain/Monkey is the standard library for mocking WordPress functions in isolated unit tests. It's already configured in this project.

### 2. Define All Required WordPress Constants
The test bootstrap (`bootstrap.php`) must define all WordPress constants your code uses:
- `ABSPATH`, `WPINC`, `WP_CONTENT_DIR`, `WP_PLUGIN_DIR`
- Time constants: `MINUTE_IN_SECONDS`, `HOUR_IN_SECONDS`, `DAY_IN_SECONDS`, etc.
- Encryption constants: `AUTH_KEY`, `SECURE_AUTH_KEY`, `NONCE_KEY`
- Plugin-specific constants: `ATOMICEDGE_VERSION`, `ATOMICEDGE_PLUGIN_DIR`, etc.

### 3. Separate Unit and Integration Tests
- **Unit tests** (`tests/unit/`): Test individual classes in isolation with mocked dependencies
- **Integration tests** (`tests/integration/`): Test how components work together

### 4. Include All Plugin Files in Bootstrap
Every class file must be included in `bootstrap.php`:
```php
require_once ATOMICEDGE_PLUGIN_DIR . 'includes/class-atomicedge-api.php';
// ... add any new class files here
```

### 5. Reset State Between Tests
The `TestCase` base class automatically resets options and transients between tests. Use the helper methods:
```php
$this->set_option('key', 'value');
$this->get_option('key');
$this->set_transient('key', 'value');
$this->get_transient('key');
$this->clear_transients();
```

### 6. Mock HTTP Requests
Use the provided helpers for testing API calls:
```php
$this->mock_http_success(['data' => 'value'], 200);
$this->mock_http_error('Connection failed');
```

### 7. API Response Contract Testing (CRITICAL)

**Lesson Learned (2026-01-06):** A bug shipped where the API class double-wrapped response data because tests mocked HTTP responses with **incorrect formats** that didn't match the real API.

#### The Problem

The Laravel API returns:
```json
{"success": true, "data": {"total_requests": 1000, ...}}
```

But tests were mocking with:
```json
{"total_requests": 1000, ...}
```

This meant the bug (where `$result['data']` contained `{"success": true, "data": {...}}` instead of just the inner data) was never caught.

#### Best Practices

1. **Always mock with the REAL API response format:**
```php
// WRONG - doesn't match real API
$api_response = ['total_requests' => 1000];
Functions\when('wp_remote_retrieve_body')->justReturn(wp_json_encode($api_response));

// RIGHT - matches real Laravel API format
$api_response = [
    'success' => true,
    'data' => ['total_requests' => 1000],
];
Functions\when('wp_remote_retrieve_body')->justReturn(wp_json_encode($api_response));
```

2. **Test that data is NOT double-nested:**
```php
$result = $api->get_analytics('24h');
$this->assertArrayNotHasKey('success', $result['data'], 'Data should not be double-nested');
```

3. **Simulate AJAX response structure:**
```php
// This is what wp_send_json_success($result['data']) sends
$ajax_response = ['success' => true, 'data' => $result['data']];
$this->assertArrayHasKey('total_requests', $ajax_response['data']);
```

4. **Don't over-mock internal methods:**
```php
// WRONG - bypasses the request() transformation logic
$this->api->method('check_vulnerabilities')->willReturn($mock_result);

// RIGHT - test through the HTTP layer to catch transformation bugs
Functions\when('wp_remote_request')->justReturn([...]);
$result = $api->check_vulnerabilities($data);
```

#### Contract Tests Location

See `tests/integration/ApiResponseContractTest.php` for examples of response format validation.

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
